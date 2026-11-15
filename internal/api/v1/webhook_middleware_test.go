package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/thep1ckaxe91/stripe-lite/internal/payments"
)

func TestWebhookAuthenticationMiddleware(t *testing.T) {
	const (
		merchantID = "merchant_webhooks_test"
		readKey    = "webhook_read_test_key_123456789012345"
		paymentKey = "payment_only_test_key_12345678901234"
	)

	config, err := json.Marshal([]payments.KeyConfig{
		{
			Key:        readKey,
			MerchantID: merchantID,
			Scopes:     []string{"webhooks:read"},
		},
		{
			Key:        paymentKey,
			MerchantID: merchantID,
			Scopes:     []string{"payment_intents:read"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	credentials, err := payments.NewCredentials(
		string(config), "", "", "",
	)
	if err != nil {
		t.Fatalf("create credentials: %v", err)
	}

	server := NewServer(
		"1.0.0",
		WithPayments(nil, credentials, 120),
	)

	middleware, err := server.PaymentMiddleware("/v1")
	if err != nil {
		t.Fatalf("create middleware: %v", err)
	}

	router := gin.New()
	router.Use(middleware)

	router.GET("/v1/webhook-endpoints", func(c *gin.Context) {
		principal, ok := payments.PrincipalFrom(c.Request.Context())
		if !ok || principal.MerchantID != merchantID {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusOK)
	})

	tests := []struct {
		name       string
		apiKey     string
		wantStatus int
	}{
		{
			name:       "Missing credentials",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "Missing webhook scope",
			apiKey:     paymentKey,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "Valid webhook read scope",
			apiKey:     readKey,
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(
				http.MethodGet,
				"/v1/webhook-endpoints",
				nil,
			)

			if tt.apiKey != "" {
				req.Header.Set("X-API-Key", tt.apiKey)
			}

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)

			if recorder.Code != tt.wantStatus {
				t.Fatalf(
					"expected HTTP %d, got %d: %s",
					tt.wantStatus,
					recorder.Code,
					recorder.Body.String(),
				)
			}
		})
	}
}

func TestWebhookWriteScopeMiddleware(t *testing.T) {
	const (
		merchantID = "merchant_webhooks_test"
		readKey    = "webhook_read_key_12345678901234567890"
		writeKey   = "webhook_write_key_12345678901234567890"
	)

	config, err := json.Marshal([]payments.KeyConfig{
		{
			Key:        readKey,
			MerchantID: merchantID,
			Scopes:     []string{"webhooks:read"},
		},
		{
			Key:        writeKey,
			MerchantID: merchantID,
			Scopes:     []string{"webhooks:write"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	credentials, err := payments.NewCredentials(
		string(config), "", "", "",
	)
	if err != nil {
		t.Fatal(err)
	}

	server := NewServer(
		"1.0.0",
		WithPayments(nil, credentials, 120),
	)

	middleware, err := server.PaymentMiddleware("/v1")
	if err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.Use(middleware)

	handler := func(c *gin.Context) {
		principal, ok := payments.PrincipalFrom(c.Request.Context())
		if !ok || principal.MerchantID != merchantID {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusOK)
	}

	router.DELETE("/v1/webhook-endpoints/:id", handler)
	router.POST("/v1/webhook-endpoints/:id/rotate-secret", handler)

	tests := []struct {
		name       string
		method     string
		path       string
		key        string
		wantStatus int
	}{
		{
			"Delete without credentials",
			http.MethodDelete, "/v1/webhook-endpoints/we_test",
			"", http.StatusUnauthorized,
		},
		{
			"Delete with read scope",
			http.MethodDelete, "/v1/webhook-endpoints/we_test",
			readKey, http.StatusForbidden,
		},
		{
			"Delete with write scope",
			http.MethodDelete, "/v1/webhook-endpoints/we_test",
			writeKey, http.StatusOK,
		},
		{
			"Rotate secret without credentials",
			http.MethodPost, "/v1/webhook-endpoints/we_test/rotate-secret",
			"", http.StatusUnauthorized,
		},
		{
			"Rotate secret with read scope",
			http.MethodPost, "/v1/webhook-endpoints/we_test/rotate-secret",
			readKey, http.StatusForbidden,
		},
		{
			"Rotate secret with write scope",
			http.MethodPost, "/v1/webhook-endpoints/we_test/rotate-secret",
			writeKey, http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)

			if tt.key != "" {
				req.Header.Set("X-API-Key", tt.key)
			}

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)

			if recorder.Code != tt.wantStatus {
				t.Fatalf(
					"expected HTTP %d, got %d: %s",
					tt.wantStatus,
					recorder.Code,
					recorder.Body.String(),
				)
			}
		})
	}
}
