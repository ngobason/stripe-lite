package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thep1ckaxe91/stripe-lite/internal/payments"
	"github.com/thep1ckaxe91/stripe-lite/internal/webhooks"
)

func TestCreateWebhookEndpointHTTPPostgres(t *testing.T) {
	if os.Getenv("WEBHOOK_INTEGRATION_TEST") != "1" {
		t.Skip("Webhook integration test is disabled")
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("DATABASE_URL is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)

	if err := db.Ping(ctx); err != nil {
		t.Fatalf("PostgreSQL connection failed: %v", err)
	}

	const (
		merchantID      = "merchant_webhooks_http_test"
		apiKey          = "webhook_http_integration_api_key_123456789"
		otherMerchantID = "merchant_webhooks_http_other"
		otherAPIKey     = "webhook_other_merchant_api_key_123456789"
	)

	keyConfig, err := json.Marshal([]payments.KeyConfig{
		{
			Key:        apiKey,
			MerchantID: merchantID,
			Scopes:     []string{"webhooks:read", "webhooks:write"},
		},
		{
			Key:        otherAPIKey,
			MerchantID: otherMerchantID,
			Scopes:     []string{"webhooks:read", "webhooks:write"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	credentials, err := payments.NewCredentials(
		string(keyConfig), "", "", "",
	)
	if err != nil {
		t.Fatal(err)
	}

	webhookService := webhooks.NewService(webhooks.NewStore(db))

	server := NewServer(
		"1.0.0",
		WithPayments(nil, credentials, 120),
		WithWebhooks(webhookService),
	)

	middleware, err := server.PaymentMiddleware("/v1")
	if err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.ContextWithFallback = true
	router.Use(middleware)

	strictHandler := NewStrictHandler(server, nil)
	RegisterHandlersWithOptions(router, strictHandler, GinServerOptions{
		BaseURL:      "/v1",
		ErrorHandler: PaymentBindingError,
	})

	body := `{
		"url": "https://example.com/webhook-http-test",
		"events": ["payment_intent.succeeded"]
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/v1/webhook-endpoints",
		strings.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusCreated {
		t.Fatalf(
			"expected HTTP 201, got %d: %s",
			recorder.Code,
			recorder.Body.String(),
		)
	}

	var response CreateWebhookEndpointResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}

	if !strings.HasPrefix(response.Id, "we_") {
		t.Fatal("invalid endpoint ID")
	}
	if !strings.HasPrefix(response.Secret, "whsec_") {
		t.Fatal("signing secret missing")
	}
	if response.Status != CreateWebhookEndpointResponseStatusActive {
		t.Fatal("expected active status")
	}

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(
			context.Background(), 5*time.Second,
		)
		defer cleanupCancel()

		_, err := db.Exec(cleanupCtx,
			`DELETE FROM public.webhook_endpoints
			 WHERE id = $1 AND merchant_id = $2`,
			response.Id, merchantID,
		)
		if err != nil {
			t.Errorf("cleanup failed: %v", err)
		}
	})

	var storedMerchant, storedSecret string
	err = db.QueryRow(ctx,
		`SELECT merchant_id, secret
		 FROM public.webhook_endpoints
		 WHERE id = $1`,
		response.Id,
	).Scan(&storedMerchant, &storedSecret)

	if err != nil {
		t.Fatalf("read persisted webhook failed: %v", err)
	}

	if storedMerchant != merchantID {
		t.Fatal("incorrect persisted merchant")
	}
	if storedSecret != response.Secret {
		t.Fatal("persisted signing secret does not match")
	}

	// Create another webhook with the same URL and merchant.
	duplicateReq := httptest.NewRequest(
		http.MethodPost,
		"/v1/webhook-endpoints",
		strings.NewReader(body),
	)
	duplicateReq.Header.Set("Content-Type", "application/json")
	duplicateReq.Header.Set("X-API-Key", apiKey)

	duplicateRecorder := httptest.NewRecorder()
	router.ServeHTTP(duplicateRecorder, duplicateReq)

	// Duplicate URL must return HTTP 409.
	if duplicateRecorder.Code != http.StatusConflict {
		t.Fatalf(
			"expected HTTP 409, got %d: %s",
			duplicateRecorder.Code,
			duplicateRecorder.Body.String(),
		)
	}

	// Error response must follow RFC 7807.
	if contentType := duplicateRecorder.Header().Get("Content-Type"); contentType != "application/problem+json" {
		t.Fatalf("expected application/problem+json, got %q", contentType)
	}

	var duplicateProblem ProblemDocument
	if err := json.Unmarshal(duplicateRecorder.Body.Bytes(), &duplicateProblem); err != nil {
		t.Fatalf("decode conflict response failed: %v", err)
	}

	if duplicateProblem.Status != int32(http.StatusConflict) {
		t.Fatal("incorrect conflict problem status")
	}

	// Verify PostgreSQL contains only one matching endpoint.
	var count int
	err = db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM public.webhook_endpoints
		WHERE merchant_id = $1 AND url = $2
	`, merchantID, "https://example.com/webhook-http-test").Scan(&count)

	if err != nil {
		t.Fatalf("count webhook endpoints failed: %v", err)
	}

	if count != 1 {
		t.Fatalf("expected exactly 1 endpoint, got %d", count)
	}

	// Helper to send authenticated List requests.
	sendListRequest := func(key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(
			http.MethodGet,
			"/v1/webhook-endpoints",
			nil,
		)
		req.Header.Set("X-API-Key", key)

		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	// The owner can list their webhook endpoints.
	listRecorder := sendListRequest(apiKey)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf(
			"expected List HTTP 200, got %d: %s",
			listRecorder.Code,
			listRecorder.Body.String(),
		)
	}

	var listResponse ListWebhookEndpointsResponse
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &listResponse); err != nil {
		t.Fatalf("decode List response failed: %v", err)
	}

	// Verify the created endpoint appears in the owner's list.
	listFound := false
	for _, item := range listResponse.Data {
		if item.Id == response.Id {
			listFound = true

			if item.Url != response.Url {
				t.Fatal("List returned incorrect webhook URL")
			}
		}
	}

	if !listFound {
		t.Fatal("created endpoint missing from owner's list")
	}

	// List responses must never expose signing secrets.
	if strings.Contains(listRecorder.Body.String(), `"secret"`) ||
		strings.Contains(listRecorder.Body.String(), response.Secret) {
		t.Fatal("List response exposed a signing secret")
	}

	// Another merchant must not see this endpoint.
	otherRecorder := sendListRequest(otherAPIKey)
	if otherRecorder.Code != http.StatusOK {
		t.Fatalf(
			"expected other merchant List HTTP 200, got %d: %s",
			otherRecorder.Code,
			otherRecorder.Body.String(),
		)
	}

	var otherList ListWebhookEndpointsResponse
	if err := json.Unmarshal(otherRecorder.Body.Bytes(), &otherList); err != nil {
		t.Fatalf("decode other merchant List failed: %v", err)
	}

	for _, item := range otherList.Data {
		if item.Id == response.Id {
			t.Fatal("webhook leaked into another merchant's list")
		}
	}

	// Helper to send authenticated Get requests.
	sendGetRequest := func(key, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-API-Key", key)

		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	getPath := "/v1/webhook-endpoints/" + response.Id

	// Owner can retrieve the endpoint.
	getRecorder := sendGetRequest(apiKey, getPath)
	if getRecorder.Code != http.StatusOK {
		t.Fatalf(
			"expected Get HTTP 200, got %d: %s",
			getRecorder.Code,
			getRecorder.Body.String(),
		)
	}

	var getResponse WebhookEndpointResponse
	if err := json.Unmarshal(getRecorder.Body.Bytes(), &getResponse); err != nil {
		t.Fatalf("decode Get response failed: %v", err)
	}

	if getResponse.Id != response.Id ||
		getResponse.Url != response.Url ||
		getResponse.Status != Active {
		t.Fatal("Get returned incorrect webhook data")
	}

	// Get must never expose the signing secret.
	if strings.Contains(getRecorder.Body.String(), `"secret"`) ||
		strings.Contains(getRecorder.Body.String(), response.Secret) {
		t.Fatal("Get response exposed a signing secret")
	}

	// Another merchant cannot retrieve this endpoint.
	otherGetRecorder := sendGetRequest(otherAPIKey, getPath)
	if otherGetRecorder.Code != http.StatusNotFound {
		t.Fatalf(
			"expected HTTP 404 for another merchant, got %d: %s",
			otherGetRecorder.Code,
			otherGetRecorder.Body.String(),
		)
	}

	// A nonexistent endpoint must return HTTP 404.
	missingPath := "/v1/webhook-endpoints/we_00000000000000000000000000000000"
	missingGetRecorder := sendGetRequest(apiKey, missingPath)

	if missingGetRecorder.Code != http.StatusNotFound {
		t.Fatalf(
			"expected HTTP 404 for missing endpoint, got %d: %s",
			missingGetRecorder.Code,
			missingGetRecorder.Body.String(),
		)
	}

	// Verify the error response follows RFC 7807.
	if missingGetRecorder.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatal("Get 404 response must use application/problem+json")
	}

	// Helper to send authenticated PATCH requests.
	sendPatchRequest := func(key, path, payload string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(
			http.MethodPatch,
			path,
			strings.NewReader(payload),
		)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", key)

		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	patchPath := "/v1/webhook-endpoints/" + response.Id

	// Owner updates URL, events and status.
	patchBody := `{
		"url": "https://example.com/webhook-patch-updated",
		"events": ["refund.created"],
		"status": "disabled"
	}`

	patchRecorder := sendPatchRequest(apiKey, patchPath, patchBody)

	if patchRecorder.Code != http.StatusOK {
		t.Fatalf(
			"expected PATCH HTTP 200, got %d: %s",
			patchRecorder.Code,
			patchRecorder.Body.String(),
		)
	}

	var patchResponse WebhookEndpointResponse
	if err := json.Unmarshal(patchRecorder.Body.Bytes(), &patchResponse); err != nil {
		t.Fatalf("decode PATCH response failed: %v", err)
	}

	if patchResponse.Id != response.Id ||
		patchResponse.Url != "https://example.com/webhook-patch-updated" ||
		string(patchResponse.Status) != "disabled" ||
		len(patchResponse.Events) != 1 ||
		string(patchResponse.Events[0]) != "refund.created" {
		t.Fatal("PATCH returned incorrect updated data")
	}

	// PATCH must never expose the signing secret.
	if strings.Contains(patchRecorder.Body.String(), `"secret"`) ||
		strings.Contains(patchRecorder.Body.String(), response.Secret) {
		t.Fatal("PATCH response exposed the signing secret")
	}

	// Verify the updated fields were persisted.
	var patchStoredURL, patchStoredStatus, patchStoredSecret string
	var patchStoredEvents []string

	err = db.QueryRow(ctx, `
		SELECT url, events, status, secret
		FROM public.webhook_endpoints
		WHERE id = $1 AND merchant_id = $2
	`, response.Id, merchantID).Scan(
		&patchStoredURL,
		&patchStoredEvents,
		&patchStoredStatus,
		&patchStoredSecret,
	)
	if err != nil {
		t.Fatalf("read PATCH data from PostgreSQL failed: %v", err)
	}

	if patchStoredURL != patchResponse.Url ||
		patchStoredStatus != "disabled" ||
		len(patchStoredEvents) != 1 ||
		patchStoredEvents[0] != "refund.created" {
		t.Fatal("PATCH changes were not persisted correctly")
	}

	if patchStoredSecret != response.Secret {
		t.Fatal("PATCH must not change the signing secret")
	}

	// Empty update payload must be rejected.
	emptyPatch := sendPatchRequest(apiKey, patchPath, `{}`)
	if emptyPatch.Code != http.StatusBadRequest {
		t.Fatalf(
			"expected PATCH HTTP 400, got %d: %s",
			emptyPatch.Code,
			emptyPatch.Body.String(),
		)
	}

	// Another merchant must not update the endpoint.
	otherPatch := sendPatchRequest(
		otherAPIKey,
		patchPath,
		`{"status":"active"}`,
	)
	if otherPatch.Code != http.StatusNotFound {
		t.Fatalf(
			"expected another merchant PATCH HTTP 404, got %d: %s",
			otherPatch.Code,
			otherPatch.Body.String(),
		)
	}

	// Nonexistent endpoint must return HTTP 404.
	missingPatch := sendPatchRequest(
		apiKey,
		"/v1/webhook-endpoints/we_00000000000000000000000000000000",
		`{"status":"active"}`,
	)
	if missingPatch.Code != http.StatusNotFound {
		t.Fatalf(
			"expected missing endpoint PATCH HTTP 404, got %d: %s",
			missingPatch.Code,
			missingPatch.Body.String(),
		)
	}

	// Helper to send authenticated RotateSecret requests.
	sendRotateRequest := func(key, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("X-API-Key", key)

		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	rotatePath := "/v1/webhook-endpoints/" + response.Id + "/rotate-secret"

	// Another merchant must not rotate the signing secret.
	otherRotate := sendRotateRequest(otherAPIKey, rotatePath)
	if otherRotate.Code != http.StatusNotFound {
		t.Fatalf(
			"expected another merchant Rotate HTTP 404, got %d: %s",
			otherRotate.Code,
			otherRotate.Body.String(),
		)
	}

	// Verify unauthorized rotation did not change the secret.
	var secretBeforeRotate string
	err = db.QueryRow(ctx, `
		SELECT secret FROM public.webhook_endpoints
		WHERE id = $1 AND merchant_id = $2
	`, response.Id, merchantID).Scan(&secretBeforeRotate)

	if err != nil {
		t.Fatalf("read secret before rotation failed: %v", err)
	}

	if secretBeforeRotate != response.Secret {
		t.Fatal("unauthorized rotation modified the signing secret")
	}

	// Owner rotates the signing secret.
	ownerRotate := sendRotateRequest(apiKey, rotatePath)
	if ownerRotate.Code != http.StatusOK {
		t.Fatalf(
			"expected Rotate HTTP 200, got %d: %s",
			ownerRotate.Code,
			ownerRotate.Body.String(),
		)
	}

	var rotateResponse RotateWebhookSecretResponse
	if err := json.Unmarshal(ownerRotate.Body.Bytes(), &rotateResponse); err != nil {
		t.Fatalf("decode Rotate response failed: %v", err)
	}

	if rotateResponse.Id != response.Id {
		t.Fatal("Rotate returned incorrect endpoint ID")
	}

	if !strings.HasPrefix(rotateResponse.Secret, "whsec_") ||
		len(rotateResponse.Secret) != 70 {
		t.Fatal("Rotate returned an invalid signing secret")
	}

	if rotateResponse.Secret == response.Secret {
		t.Fatal("rotated secret must differ from the original secret")
	}

	// Verify the new secret was persisted in PostgreSQL.
	var persistedRotatedSecret string
	err = db.QueryRow(ctx, `
		SELECT secret FROM public.webhook_endpoints
		WHERE id = $1 AND merchant_id = $2
	`, response.Id, merchantID).Scan(&persistedRotatedSecret)

	if err != nil {
		t.Fatalf("read rotated secret from PostgreSQL failed: %v", err)
	}

	if persistedRotatedSecret != rotateResponse.Secret {
		t.Fatal("rotated signing secret was not persisted")
	}

	// Another merchant still cannot rotate the endpoint.
	secondOtherRotate := sendRotateRequest(otherAPIKey, rotatePath)
	if secondOtherRotate.Code != http.StatusNotFound {
		t.Fatalf(
			"expected unauthorized Rotate HTTP 404, got %d",
			secondOtherRotate.Code,
		)
	}

	// Verify the second unauthorized attempt did not modify the secret.
	var secretAfterUnauthorizedRotate string
	err = db.QueryRow(ctx, `
		SELECT secret FROM public.webhook_endpoints
		WHERE id = $1 AND merchant_id = $2
	`, response.Id, merchantID).Scan(&secretAfterUnauthorizedRotate)

	if err != nil || secretAfterUnauthorizedRotate != rotateResponse.Secret {
		t.Fatal("unauthorized rotation changed the persisted secret")
	}

	// Helper to send authenticated DELETE requests.
	sendDeleteRequest := func(key, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, path, nil)
		req.Header.Set("X-API-Key", key)

		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	deletePath := "/v1/webhook-endpoints/" + response.Id

	// Another merchant must not delete the endpoint.
	otherDelete := sendDeleteRequest(otherAPIKey, deletePath)
	if otherDelete.Code != http.StatusNotFound {
		t.Fatalf(
			"expected another merchant DELETE HTTP 404, got %d: %s",
			otherDelete.Code,
			otherDelete.Body.String(),
		)
	}

	// Confirm the endpoint still exists after unauthorized deletion.
	var beforeDeleteCount int
	err = db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM public.webhook_endpoints
		WHERE id = $1 AND merchant_id = $2
	`, response.Id, merchantID).Scan(&beforeDeleteCount)

	if err != nil || beforeDeleteCount != 1 {
		t.Fatal("unauthorized deletion affected the endpoint")
	}

	// The owner can delete the endpoint.
	ownerDelete := sendDeleteRequest(apiKey, deletePath)
	if ownerDelete.Code != http.StatusNoContent {
		t.Fatalf(
			"expected DELETE HTTP 204, got %d: %s",
			ownerDelete.Code,
			ownerDelete.Body.String(),
		)
	}

	// HTTP 204 must not contain a response body.
	if ownerDelete.Body.Len() != 0 {
		t.Fatal("DELETE 204 response must have an empty body")
	}

	// Verify the endpoint was removed from PostgreSQL.
	var afterDeleteCount int
	err = db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM public.webhook_endpoints
		WHERE id = $1 AND merchant_id = $2
	`, response.Id, merchantID).Scan(&afterDeleteCount)

	if err != nil {
		t.Fatalf("verify deletion failed: %v", err)
	}

	if afterDeleteCount != 0 {
		t.Fatal("deleted endpoint still exists in PostgreSQL")
	}

	// Deleting the same endpoint again must return HTTP 404.
	repeatedDelete := sendDeleteRequest(apiKey, deletePath)
	if repeatedDelete.Code != http.StatusNotFound {
		t.Fatalf(
			"expected repeated DELETE HTTP 404, got %d: %s",
			repeatedDelete.Code,
			repeatedDelete.Body.String(),
		)
	}

	// GET after DELETE must return HTTP 404.
	getAfterDelete := sendGetRequest(apiKey, deletePath)
	if getAfterDelete.Code != http.StatusNotFound {
		t.Fatalf(
			"expected GET after DELETE HTTP 404, got %d: %s",
			getAfterDelete.Code,
			getAfterDelete.Body.String(),
		)
	}

}
