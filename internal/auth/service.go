package auth

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"

	usersdb "github.com/Steve-s-Circle-on-System-Design/golang-rbac-system/internal/users/sqlc"
)

var (
	ErrUserWithEmailAlreadyExists  = errors.New("user with that email already exists")
	ErrNonExistentUser             = errors.New("user doesn't exist with that email")
	ErrPasswordMismatchDuringLogin = errors.New("invalid password")
	ErrRefreshTokenInvalid         = errors.New("refresh token is invalid")
	ErrRefreshTokenExpired         = errors.New("refresh token has expired")
	ErrRefreshTokenReuse           = errors.New("refresh token reuse detected — all sessions have been terminated")
	ErrLockedOut                   = errors.New("too many failed attempts while trying to sign in. Try again later")
)

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64 // Life span of access token
}

type Service interface {
	RegisterWithPassword(ctx context.Context, email, password string) error
	LoginWithPassword(ctx context.Context, email, password string) (*TokenPair, error)
	Logout(ctx context.Context, rawRefreshToken string) error
	RefreshTokens(ctx context.Context, rawRefreshToken string) (*TokenPair, error)
}

type authService struct {
	Repository *Repository
	jwtUtil    *JWTUtil
}

func NewService(repository *Repository, jwtUtil *JWTUtil) Service {
	return &authService{
		Repository: repository,
		jwtUtil:    jwtUtil,
	}
}

func (s *authService) RegisterWithPassword(ctx context.Context, email, password string) error {
	_, err := s.Repository.GetByEmail(ctx, email)
	if err == nil {
		return ErrUserWithEmailAlreadyExists
	} else if !errors.Is(err, pgx.ErrNoRows) {
		log.Println("failed to check existing user:", err)
		return err
	}

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Something went wrong while hashing the password", err.Error())
		return err
	}

	_, err = s.Repository.Create(ctx, usersdb.CreateUserParams{
		Email:        email,
		PasswordHash: string(passwordHash),
	})
	if err != nil {
		log.Println("Something went wrong while trying to save the new user in the db", err.Error())
		return err
	}
	return nil
}

func (s *authService) LoginWithPassword(ctx context.Context, email, password string) (*TokenPair, error) {
	existingUser, err := s.Repository.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNonExistentUser
		}
		log.Println("failed to check existing user:", err)
		return nil, err
	}

	// Check if user is locked
	if existingUser.LockedUntil.Valid &&
		time.Now().Before(existingUser.LockedUntil.Time) {
		return nil, ErrLockedOut
	}

	err = bcrypt.CompareHashAndPassword([]byte(existingUser.PasswordHash), []byte(password))
	if err != nil {
		newAttempts, err := s.Repository.queries.IncrementFailedAttempts(ctx, existingUser.ID)
		if err != nil {
			log.Println("failed to increment failed attempts:", err)
			return nil, err
		}

		if newAttempts >= 5 {
			lockOutWindowEnd := time.Now().Add(15 * time.Minute)
			err := s.Repository.queries.LockUser(ctx, usersdb.LockUserParams{
				ID: existingUser.ID,
				LockedUntil: pgtype.Timestamptz{
					Time:  lockOutWindowEnd,
					Valid: true,
				},
			})
			if err != nil {
				log.Println("Failed to lock user after 5 attempts", err)
				return nil, err
			}
		}

		return nil, ErrPasswordMismatchDuringLogin
	}

	err = s.Repository.queries.ResetLockout(ctx, existingUser.ID)
	if err != nil {
		log.Println("failed to reset lockout:", err)
	}

	accessToken, refreshToken, refreshHash, err := s.jwtUtil.IssueTokenPair(
		existingUser.ID,
		existingUser.Role,
	)
	if err != nil {
		log.Println("failed to issue token pair:", err)
		return nil, err
	}

	expiresAt := time.Now().UTC().Add(s.jwtUtil.RefreshTokenTTL())

	_, err = s.Repository.CreateRefreshToken(
		ctx,
		usersdb.CreateRefreshTokenParams{
			UserID:    existingUser.ID,
			TokenHash: refreshHash,
			ExpiresAt: expiresAt,
		},
	)
	if err != nil {
		log.Println("failed to save refresh token:", err)
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.jwtUtil.AccessTokenTTL().Seconds()),
	}, nil
}

func (s *authService) Logout(ctx context.Context, rawRefreshToken string) error {
	hash := s.jwtUtil.HashRefreshToken(rawRefreshToken)

	token, err := s.Repository.GetRefreshTokenByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}

	if token.IsRevoked {
		return nil
	}

	return s.Repository.RevokeRefreshToken(ctx, token.ID)
}

func (s *authService) RefreshTokens(ctx context.Context, rawRefreshToken string) (*TokenPair, error) {
	hash := s.jwtUtil.HashRefreshToken(rawRefreshToken)

	token, err := s.Repository.GetRefreshTokenByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRefreshTokenInvalid
		}
		return nil, err
	}

	// If there's a breach revoke all tokens for the user
	if token.IsRevoked {
		_ = s.Repository.RevokeAllRefreshTokensForUser(ctx, token.UserID)
		return nil, ErrRefreshTokenReuse
	}

	if time.Now().UTC().After(token.ExpiresAt) {
		return nil, ErrRefreshTokenExpired
	}

	user, err := s.Repository.GetByID(ctx, token.UserID)
	if err != nil {
		return nil, err
	}

	// revoke the used token immediately before issuing a new one
	err = s.Repository.RevokeRefreshToken(ctx, token.ID)
	if err != nil {
		return nil, err
	}

	accessToken, refreshToken, refreshHash, err := s.jwtUtil.IssueTokenPair(user.ID, user.Role)
	if err != nil {
		return nil, err
	}

	newExpiry := time.Now().UTC().Add(s.jwtUtil.RefreshTokenTTL())

	_, err = s.Repository.CreateRefreshToken(ctx, usersdb.CreateRefreshTokenParams{
		UserID:    user.ID,
		TokenHash: refreshHash,
		ExpiresAt: newExpiry,
	})
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.jwtUtil.AccessTokenTTL().Seconds()),
	}, nil
}
