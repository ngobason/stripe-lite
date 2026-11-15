package webhooks

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Runtime owns the PostgreSQL connection pool used by Webhooks.
type Runtime struct {
	Service *Service
	pool    *pgxpool.Pool
}

// LoadRuntime initializes the Webhooks service.
// Without DATABASE_URL, the service remains unavailable.
func LoadRuntime(ctx context.Context) (*Runtime, error) {
	runtime := &Runtime{}

	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if databaseURL == "" {
		return runtime, nil
	}

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse webhook database config: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create webhook database pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect webhook database: %w", err)
	}

	runtime.pool = pool
	runtime.Service = NewService(NewStore(pool))

	return runtime, nil
}

// Close releases the Webhooks database connection pool.
func (r *Runtime) Close() {
	if r != nil && r.pool != nil {
		r.pool.Close()
	}
}
