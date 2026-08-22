package auth

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	usersdb "github.com/Steve-s-Circle-on-System-Design/golang-rbac-system/internal/users/sqlc"
)

type Repository struct {
	pool    *pgxpool.Pool
	queries *usersdb.Queries
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{
		pool:    pool,
		queries: usersdb.New(pool),
	}
}

// --- USER WRAPPER METHODS ---

func (r *Repository) Create(ctx context.Context, arg usersdb.CreateUserParams) (usersdb.User, error) {
	return r.queries.CreateUser(ctx, arg)
}

func (r *Repository) GetByEmail(ctx context.Context, email string) (usersdb.User, error) {
	return r.queries.GetUserByEmail(ctx, email)
}

func (r *Repository) GetByID(ctx context.Context, id uuid.UUID) (usersdb.User, error) {
	return r.queries.GetUserByID(ctx, id)
}

func (r *Repository) Verify(ctx context.Context, id uuid.UUID) error {
	return r.queries.VerifyUser(ctx, id)
}

func (r *Repository) UpdateRole(ctx context.Context, arg usersdb.UpdateUserRoleParams) error {
	return r.queries.UpdateUserRole(ctx, arg)
}

// --- REFRESH TOKEN WRAPPER METHODS ---

func (r *Repository) CreateRefreshToken(ctx context.Context, arg usersdb.CreateRefreshTokenParams) (usersdb.RefreshToken, error) {
	return r.queries.CreateRefreshToken(ctx, arg)
}

func (r *Repository) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (usersdb.RefreshToken, error) {
	return r.queries.GetRefreshTokenByHash(ctx, tokenHash)
}

func (r *Repository) RevokeRefreshToken(ctx context.Context, id uuid.UUID) error {
	return r.queries.RevokeRefreshToken(ctx, id)
}

func (r *Repository) RevokeAllRefreshTokensForUser(ctx context.Context, userID uuid.UUID) error {
	return r.queries.RevokeAllRefreshTokensForUser(ctx, userID)
}

func (r *Repository) IncrementFailedAttempts(ctx context.Context, id uuid.UUID) (int32, error) {
	return r.queries.IncrementFailedAttempts(ctx, id)
}

func (r *Repository) LockUser(ctx context.Context, arg usersdb.LockUserParams) error {
	return r.queries.LockUser(ctx, arg)
}

func (r *Repository) ResetLockout(ctx context.Context, id uuid.UUID) error {
	return r.queries.ResetLockout(ctx, id)
}
