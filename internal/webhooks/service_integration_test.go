package webhooks

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestServiceCreatePostgres(t *testing.T) {
	if os.Getenv("WEBHOOK_INTEGRATION_TEST") != "1" {
		t.Skip("Webhook integration test is disabled")
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("DATABASE_URL is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)

	if err := db.Ping(ctx); err != nil {
		t.Fatalf("cannot connect to PostgreSQL: %v", err)
	}

	store := NewStore(db)
	service := NewService(store)

	merchantID := "merchant_webhooks_integration"

	endpoint, secret, err := service.Create(
		ctx,
		merchantID,
		"https://example.com/webhooks",
		[]string{"payment_intent.succeeded"},
	)
	if err != nil {
		t.Fatalf("create webhook failed: %v", err)
	}

	// Remove the test record even if subsequent assertions fail.
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(
			context.Background(), 5*time.Second,
		)
		defer cleanupCancel()

		_, err := db.Exec(cleanupCtx,
			"DELETE FROM public.webhook_endpoints WHERE id = $1 AND merchant_id = $2",
			endpoint.ID, merchantID,
		)
		if err != nil {
			t.Errorf("cleanup failed: %v", err)
		}
	})

	if !strings.HasPrefix(endpoint.ID, "we_") {
		t.Fatalf("invalid endpoint ID: %q", endpoint.ID)
	}

	if !strings.HasPrefix(secret, "whsec_") || len(secret) != 70 {
		t.Fatal("invalid signing secret")
	}

	if endpoint.Status != "active" {
		t.Fatalf("expected active status, got %q", endpoint.Status)
	}

	// Verify the endpoint is persisted and merchant-scoped.
	saved, err := store.Get(ctx, merchantID, endpoint.ID)
	if err != nil {
		t.Fatalf("read webhook failed: %v", err)
	}

	if saved.ID != endpoint.ID || saved.URL != endpoint.URL {
		t.Fatal("persisted webhook data does not match")
	}

	// Verify that the signing secret was stored correctly.
	var storedSecret string
	err = db.QueryRow(ctx,
		`SELECT secret FROM public.webhook_endpoints
		 WHERE id = $1 AND merchant_id = $2`,
		endpoint.ID, merchantID,
	).Scan(&storedSecret)
	if err != nil {
		t.Fatal(err)
	}

	if storedSecret != secret {
		t.Fatal("stored signing secret does not match")
	}

	// Verify that List returns the created endpoint.
	endpoints, err := store.List(ctx, merchantID)
	if err != nil {
		t.Fatalf("list webhooks failed: %v", err)
	}

	found := false
	for _, e := range endpoints {
		if e.ID == endpoint.ID {
			found = true
			break
		}
	}

	if !found {
		t.Fatal("created endpoint not found in merchant list")
	}

	// Verify that another merchant cannot list this endpoint.
	otherEndpoints, err := store.List(ctx, "another_merchant")
	if err != nil {
		t.Fatalf("list for another merchant failed: %v", err)
	}

	for _, e := range otherEndpoints {
		if e.ID == endpoint.ID {
			t.Fatal("webhook leaked into another merchant's list")
		}
	}

	// Verify updating the endpoint.
	newURL := "https://example.com/updated-webhooks"
	newStatus := "disabled"
	newEvents := []string{"refund.created"}

	updated, err := store.Update(ctx, merchantID, endpoint.ID, UpdateParams{
		URL:    &newURL,
		Events: &newEvents,
		Status: &newStatus,
	})
	if err != nil {
		t.Fatalf("update webhook failed: %v", err)
	}

	if updated.URL != newURL || updated.Status != newStatus {
		t.Fatal("updated URL or status does not match")
	}

	if len(updated.Events) != 1 || updated.Events[0] != "refund.created" {
		t.Fatal("updated events do not match")
	}

	// Verify another merchant cannot update the endpoint.
	_, err = store.Update(ctx, "another_merchant", endpoint.ID, UpdateParams{
		Status: &newStatus,
	})
	if err == nil {
		t.Fatal("another merchant must not update this endpoint")
	}

	// Verify merchant isolation.
	_, err = store.Get(ctx, "another_merchant", endpoint.ID)
	if err == nil {
		t.Fatal("another merchant must not access this endpoint")
	}

	// Verify that another merchant cannot rotate the signing secret.
	unauthorizedSecret, err := generateSigningSecret()
	if err != nil {
		t.Fatal(err)
	}

	err = store.RotateSecret(ctx, "another_merchant", endpoint.ID, unauthorizedSecret)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected not found for another merchant, got %v", err)
	}

	// Rotate the signing secret as the endpoint owner.
	newSecret, err := generateSigningSecret()
	if err != nil {
		t.Fatal(err)
	}

	if newSecret == secret {
		t.Fatal("new signing secret must differ from the old secret")
	}

	err = store.RotateSecret(ctx, merchantID, endpoint.ID, newSecret)
	if err != nil {
		t.Fatalf("rotate signing secret failed: %v", err)
	}

	// Verify the new secret is persisted.
	var rotatedSecret string
	err = db.QueryRow(ctx,
		`SELECT secret FROM public.webhook_endpoints
		WHERE id = $1 AND merchant_id = $2`,
		endpoint.ID, merchantID,
	).Scan(&rotatedSecret)
	if err != nil {
		t.Fatalf("read rotated secret failed: %v", err)
	}

	if rotatedSecret != newSecret {
		t.Fatal("rotated signing secret does not match")
	}

	if rotatedSecret == secret {
		t.Fatal("old signing secret is still stored")
	}

	// Verify that Service.RotateSecret generates and persists a new secret.
	serviceSecret, err := service.RotateSecret(ctx, merchantID, endpoint.ID)
	if err != nil {
		t.Fatalf("service rotate secret failed: %v", err)
	}

	if !strings.HasPrefix(serviceSecret, "whsec_") || len(serviceSecret) != 70 {
		t.Fatal("invalid service-generated signing secret")
	}

	if serviceSecret == newSecret {
		t.Fatal("service must generate a different signing secret")
	}

	var persistedSecret string
	err = db.QueryRow(ctx, `
		SELECT secret FROM public.webhook_endpoints
		WHERE id = $1 AND merchant_id = $2
	`, endpoint.ID, merchantID).Scan(&persistedSecret)
	if err != nil {
		t.Fatalf("read service-rotated secret failed: %v", err)
	}

	if persistedSecret != serviceSecret {
		t.Fatal("service-generated secret was not persisted")
	}

	// Another merchant must not rotate this endpoint.
	_, err = service.RotateSecret(ctx, "another_merchant", endpoint.ID)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected not found for another merchant, got %v", err)
	}

	// Unauthorized rotation must not modify the existing secret.
	err = db.QueryRow(ctx, `
		SELECT secret FROM public.webhook_endpoints
		WHERE id = $1 AND merchant_id = $2
	`, endpoint.ID, merchantID).Scan(&persistedSecret)
	if err != nil || persistedSecret != serviceSecret {
		t.Fatal("unauthorized rotation changed the signing secret")
	}

	// Verify another merchant cannot delete the endpoint.
	err = store.Delete(ctx, "another_merchant", endpoint.ID)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected not found for another merchant, got %v", err)
	}

	// Verify the owner can delete the endpoint.
	err = store.Delete(ctx, merchantID, endpoint.ID)
	if err != nil {
		t.Fatalf("delete webhook failed: %v", err)
	}

	// Verify the deleted endpoint cannot be retrieved.
	_, err = store.Get(ctx, merchantID, endpoint.ID)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected not found after deletion, got %v", err)
	}

	// Create a separate endpoint for Service Update/Delete tests.
	serviceEndpoint, _, err := service.Create(
		ctx,
		merchantID,
		"https://example.com/service-test",
		[]string{"payment_intent.succeeded"},
	)
	if err != nil {
		t.Fatalf("create service test endpoint failed: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if _, err := db.Exec(cleanupCtx,
			"DELETE FROM public.webhook_endpoints WHERE id = $1 AND merchant_id = $2",
			serviceEndpoint.ID, merchantID,
		); err != nil {
			t.Errorf("service test cleanup failed: %v", err)
		}
	})

	// Verify Service.Get returns the merchant-owned endpoint.
	got, err := service.Get(ctx, merchantID, serviceEndpoint.ID)
	if err != nil {
		t.Fatalf("service get failed: %v", err)
	}

	if got.ID != serviceEndpoint.ID ||
		got.MerchantID != merchantID ||
		got.URL != serviceEndpoint.URL {
		t.Fatal("service get returned incorrect endpoint")
	}

	// Verify Service.List includes the created endpoint.
	listed, err := service.List(ctx, merchantID)
	if err != nil {
		t.Fatalf("service list failed: %v", err)
	}

	serviceFound := false
	for _, e := range listed {
		if e.ID == serviceEndpoint.ID {
			serviceFound = true
			break
		}
	}

	if !serviceFound {
		t.Fatal("service list did not include the created endpoint")
	}

	// Another merchant must not retrieve the endpoint.
	_, err = service.Get(ctx, "another_merchant", serviceEndpoint.ID)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected not found for another merchant, got %v", err)
	}

	// Another merchant must not see the endpoint in its list.
	otherList, err := service.List(ctx, "another_merchant")
	if err != nil {
		t.Fatalf("service list for another merchant failed: %v", err)
	}

	for _, e := range otherList {
		if e.ID == serviceEndpoint.ID {
			t.Fatal("endpoint leaked into another merchant's list")
		}
	}

	// Reject an invalid endpoint ID.
	_, err = service.Get(ctx, merchantID, "invalid_id")
	if !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("expected invalid endpoint ID error, got %v", err)
	}

	// Reject an invalid destination URL.
	invalidURL := "http://example.com/insecure"
	_, err = service.Update(ctx, merchantID, serviceEndpoint.ID, UpdateParams{
		URL: &invalidURL,
	})
	if !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("expected invalid endpoint error, got %v", err)
	}

	// Reject an empty update request.
	_, err = service.Update(ctx, merchantID, serviceEndpoint.ID, UpdateParams{})
	if !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("expected invalid empty update, got %v", err)
	}

	// Update URL, event subscriptions and status.
	serviceURL := "https://example.com/service-updated"
	serviceEvents := []string{"refund.created"}
	serviceStatus := "disabled"

	serviceUpdated, err := service.Update(ctx, merchantID, serviceEndpoint.ID, UpdateParams{
		URL:    &serviceURL,
		Events: &serviceEvents,
		Status: &serviceStatus,
	})
	if err != nil {
		t.Fatalf("service update failed: %v", err)
	}

	if serviceUpdated.URL != serviceURL ||
		serviceUpdated.Status != serviceStatus ||
		len(serviceUpdated.Events) != 1 ||
		serviceUpdated.Events[0] != "refund.created" {
		t.Fatal("service update returned incorrect data")
	}

	// Confirm changes were persisted.
	persisted, err := store.Get(ctx, merchantID, serviceEndpoint.ID)
	if err != nil {
		t.Fatalf("read updated endpoint failed: %v", err)
	}
	if persisted.URL != serviceURL || persisted.Status != serviceStatus {
		t.Fatal("service changes were not persisted")
	}

	// Another merchant must not update the endpoint.
	_, err = service.Update(ctx, "another_merchant", serviceEndpoint.ID, UpdateParams{
		Status: &serviceStatus,
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected not found for unauthorized update, got %v", err)
	}

	// Another merchant must not delete the endpoint.
	err = service.Delete(ctx, "another_merchant", serviceEndpoint.ID)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected not found for unauthorized delete, got %v", err)
	}

	// The owner can delete the endpoint.
	err = service.Delete(ctx, merchantID, serviceEndpoint.ID)
	if err != nil {
		t.Fatalf("service delete failed: %v", err)
	}

	// Verify the endpoint no longer exists.
	_, err = store.Get(ctx, merchantID, serviceEndpoint.ID)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected not found after service delete, got %v", err)
	}

}
