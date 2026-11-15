package webhooks

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrUnavailable = errors.New("webhook database unavailable")

// Endpoint represents a persisted webhook endpoint.
// Signing secrets are intentionally excluded from read results.
type Endpoint struct {
	ID         string
	MerchantID string
	URL        string
	Events     []string
	Status     string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type Store struct {
	DB *pgxpool.Pool
}

func NewStore(db *pgxpool.Pool) *Store {
	return &Store{DB: db}
}

const endpointColumns = `
	id, merchant_id, url, events, status, created_at, updated_at
`

// Get retrieves an endpoint belonging to the specified merchant.
func (s *Store) Get(ctx context.Context, merchantID, id string) (Endpoint, error) {
	if s == nil || s.DB == nil {
		return Endpoint{}, ErrUnavailable
	}

	var e Endpoint

	err := s.DB.QueryRow(ctx, `
		SELECT `+endpointColumns+`
		FROM public.webhook_endpoints
		WHERE merchant_id = $1 AND id = $2
	`, merchantID, id).Scan(
		&e.ID,
		&e.MerchantID,
		&e.URL,
		&e.Events,
		&e.Status,
		&e.CreatedAt,
		&e.UpdatedAt,
	)

	if err != nil {
		return Endpoint{}, err
	}

	return e, nil
}

// List retrieves all endpoints belonging to the specified merchant.
func (s *Store) List(ctx context.Context, merchantID string) ([]Endpoint, error) {
	if s == nil || s.DB == nil {
		return nil, ErrUnavailable
	}

	rows, err := s.DB.Query(ctx, `
		SELECT `+endpointColumns+`
		FROM public.webhook_endpoints
		WHERE merchant_id = $1
		ORDER BY created_at DESC, id DESC
	`, merchantID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	endpoints := make([]Endpoint, 0)

	for rows.Next() {
		var e Endpoint

		err := rows.Scan(
			&e.ID,
			&e.MerchantID,
			&e.URL,
			&e.Events,
			&e.Status,
			&e.CreatedAt,
			&e.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		endpoints = append(endpoints, e)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return endpoints, nil
}

// Create persists a new webhook endpoint.
// The signing secret is stored but excluded from the returned Endpoint.
func (s *Store) Create(
	ctx context.Context,
	id, merchantID, url, secret string,
	events []string,
) (Endpoint, error) {
	if s == nil || s.DB == nil {
		return Endpoint{}, ErrUnavailable
	}

	var e Endpoint

	err := s.DB.QueryRow(ctx, `
			INSERT INTO public.webhook_endpoints (
				id, merchant_id, url, secret, events
			)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING `+endpointColumns,
		id, merchantID, url, secret, events,
	).Scan(
		&e.ID,
		&e.MerchantID,
		&e.URL,
		&e.Events,
		&e.Status,
		&e.CreatedAt,
		&e.UpdatedAt,
	)

	if err != nil {
		return Endpoint{}, err
	}

	return e, nil
}

type UpdateParams struct {
	URL    *string
	Events *[]string
	Status *string
}

// Update modifies an endpoint belonging to the specified merchant.
// Only fields explicitly provided in UpdateParams are changed.
func (s *Store) Update(
	ctx context.Context,
	merchantID, id string,
	params UpdateParams,
) (Endpoint, error) {
	if s == nil || s.DB == nil {
		return Endpoint{}, ErrUnavailable
	}

	var eventsArg any
	if params.Events != nil {
		eventsArg = *params.Events
	}

	var e Endpoint

	err := s.DB.QueryRow(ctx, `
		UPDATE public.webhook_endpoints
		SET
			url = COALESCE($3::text, url),
			events = COALESCE($4::text[], events),
			status = COALESCE($5::text, status),
			updated_at = CURRENT_TIMESTAMP
		WHERE merchant_id = $1 AND id = $2
		RETURNING `+endpointColumns,
		merchantID,
		id,
		params.URL,
		eventsArg,
		params.Status,
	).Scan(
		&e.ID,
		&e.MerchantID,
		&e.URL,
		&e.Events,
		&e.Status,
		&e.CreatedAt,
		&e.UpdatedAt,
	)

	if err != nil {
		return Endpoint{}, err
	}

	return e, nil
}

// Delete removes an endpoint belonging to the specified merchant.
// Returns pgx.ErrNoRows if the endpoint does not exist
// or belongs to another merchant.
func (s *Store) Delete(
	ctx context.Context,
	merchantID, id string,
) error {
	if s == nil || s.DB == nil {
		return ErrUnavailable
	}

	result, err := s.DB.Exec(ctx, `
         DELETE FROM public.webhook_endpoints
         WHERE merchant_id = $1 AND id = $2
     `, merchantID, id)

	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}

	return nil
}

// RotateSecret replaces the signing secret of a merchant-owned endpoint.
// The old secret becomes invalid immediately after the update commits.
func (s *Store) RotateSecret(
	ctx context.Context,
	merchantID, id, newSecret string,
) error {
	if s == nil || s.DB == nil {
		return ErrUnavailable
	}

	result, err := s.DB.Exec(ctx, `
         UPDATE public.webhook_endpoints
         SET secret = $3,
             updated_at = CURRENT_TIMESTAMP
         WHERE merchant_id = $1 AND id = $2
     `, merchantID, id, newSecret)

	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}

	return nil
}
