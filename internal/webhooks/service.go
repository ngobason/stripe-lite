package webhooks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

var ErrInvalidEndpoint = errors.New("invalid webhook endpoint")

type Service struct {
	Store *Store
}

func NewService(store *Store) *Service {
	return &Service{Store: store}
}

func generateToken(prefix string, size int) (string, error) {
	b := make([]byte, size)

	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate webhook token: %w", err)
	}

	return prefix + hex.EncodeToString(b), nil
}

func generateEndpointID() (string, error) {
	return generateToken("we_", 16)
}

func generateSigningSecret() (string, error) {
	return generateToken("whsec_", 32)
}

// Create validates and persists a webhook endpoint.
// The signing secret is returned separately from Endpoint.
func (s *Service) Create(
	ctx context.Context,
	merchantID, destination string,
	events []string,
) (Endpoint, string, error) {
	if s == nil || s.Store == nil ||
		s.Store.DB == nil {
		return Endpoint{}, "", ErrUnavailable
	}

	if strings.TrimSpace(merchantID) == "" ||
		len(merchantID) > 255 {
		return Endpoint{}, "", ErrInvalidEndpoint
	}

	u, err := url.Parse(destination)
	if err != nil ||
		!strings.HasPrefix(destination, "https://") ||
		u.Scheme != "https" ||
		u.Hostname() == "" ||
		u.User != nil ||
		u.Fragment != "" {
		return Endpoint{}, "", ErrInvalidEndpoint
	}

	allowed := map[string]bool{
		"payment_intent.succeeded":      true,
		"payment_intent.payment_failed": true,
		"refund.created":                true,
	}

	if len(events) == 0 {
		return Endpoint{}, "", ErrInvalidEndpoint
	}

	seen := make(map[string]bool)
	for _, event := range events {
		if !allowed[event] || seen[event] {
			return Endpoint{}, "", ErrInvalidEndpoint
		}
		seen[event] = true
	}

	id, err := generateEndpointID()
	if err != nil {
		return Endpoint{}, "", err
	}

	secret, err := generateSigningSecret()
	if err != nil {
		return Endpoint{}, "", err
	}

	endpoint, err := s.Store.Create(
		ctx,
		id,
		merchantID,
		destination,
		secret,
		events,
	)
	if err != nil {
		return Endpoint{}, "", err
	}

	return endpoint, secret, nil
}

// RotateSecret generates a new signing secret for a merchant-owned endpoint.
// The previous secret is replaced in PostgreSQL.
func (s *Service) RotateSecret(
	ctx context.Context,
	merchantID, id string,
) (string, error) {
	if s == nil || s.Store == nil || s.Store.DB == nil {
		return "", ErrUnavailable
	}

	if strings.TrimSpace(merchantID) == "" ||
		len(merchantID) > 255 ||
		strings.TrimSpace(id) == "" {
		return "", ErrInvalidEndpoint
	}

	newSecret, err := generateSigningSecret()
	if err != nil {
		return "", err
	}

	if err := s.Store.RotateSecret(ctx, merchantID, id, newSecret); err != nil {
		return "", err
	}

	return newSecret, nil
}

// Update validates and updates a merchant-owned webhook endpoint.
func (s *Service) Update(
	ctx context.Context,
	merchantID, id string,
	params UpdateParams,
) (Endpoint, error) {
	if s == nil || s.Store == nil || s.Store.DB == nil {
		return Endpoint{}, ErrUnavailable
	}

	if strings.TrimSpace(merchantID) == "" ||
		len(merchantID) > 255 ||
		!strings.HasPrefix(id, "we_") {
		return Endpoint{}, ErrInvalidEndpoint
	}

	// Reject requests that do not update any field.
	if params.URL == nil && params.Events == nil && params.Status == nil {
		return Endpoint{}, ErrInvalidEndpoint
	}

	// Validate destination URL when provided.
	if params.URL != nil {
		u, err := url.Parse(*params.URL)
		if err != nil ||
			!strings.HasPrefix(*params.URL, "https://") ||
			u.Scheme != "https" ||
			u.Hostname() == "" ||
			u.User != nil ||
			u.Fragment != "" {
			return Endpoint{}, ErrInvalidEndpoint
		}
	}

	// Validate event subscriptions when provided.
	if params.Events != nil {
		allowed := map[string]bool{
			"payment_intent.succeeded":      true,
			"payment_intent.payment_failed": true,
			"refund.created":                true,
		}

		if len(*params.Events) == 0 {
			return Endpoint{}, ErrInvalidEndpoint
		}

		seen := make(map[string]bool)
		for _, event := range *params.Events {
			if !allowed[event] || seen[event] {
				return Endpoint{}, ErrInvalidEndpoint
			}
			seen[event] = true
		}
	}

	// Validate status when provided.
	if params.Status != nil &&
		*params.Status != "active" &&
		*params.Status != "disabled" {
		return Endpoint{}, ErrInvalidEndpoint
	}

	return s.Store.Update(ctx, merchantID, id, params)
}

// Delete removes a merchant-owned webhook endpoint.
func (s *Service) Delete(
	ctx context.Context,
	merchantID, id string,
) error {
	if s == nil || s.Store == nil || s.Store.DB == nil {
		return ErrUnavailable
	}

	if strings.TrimSpace(merchantID) == "" ||
		len(merchantID) > 255 ||
		!strings.HasPrefix(id, "we_") {
		return ErrInvalidEndpoint
	}

	return s.Store.Delete(ctx, merchantID, id)
}

// Get retrieves a webhook endpoint belonging to a merchant.
func (s *Service) Get(
	ctx context.Context,
	merchantID, id string,
) (Endpoint, error) {
	if s == nil || s.Store == nil || s.Store.DB == nil {
		return Endpoint{}, ErrUnavailable
	}

	if strings.TrimSpace(merchantID) == "" ||
		len(merchantID) > 255 ||
		!strings.HasPrefix(id, "we_") {
		return Endpoint{}, ErrInvalidEndpoint
	}

	return s.Store.Get(ctx, merchantID, id)
}

// List retrieves webhook endpoints belonging to a merchant.
func (s *Service) List(
	ctx context.Context,
	merchantID string,
) ([]Endpoint, error) {
	if s == nil || s.Store == nil || s.Store.DB == nil {
		return nil, ErrUnavailable
	}

	if strings.TrimSpace(merchantID) == "" ||
		len(merchantID) > 255 {
		return nil, ErrInvalidEndpoint
	}

	return s.Store.List(ctx, merchantID)
}
