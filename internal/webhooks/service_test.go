package webhooks

import (
	"strings"
	"testing"
)

func TestGenerateEndpointID(t *testing.T) {
	id1, err := generateEndpointID()
	if err != nil {
		t.Fatal(err)
	}

	id2, err := generateEndpointID()
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(id1, "we_") || len(id1) != 35 {
		t.Fatalf("invalid endpoint ID format: %q", id1)
	}

	if id1 == id2 {
		t.Fatal("generated endpoint IDs must be unique")
	}
}

func TestGenerateSigningSecret(t *testing.T) {
	secret, err := generateSigningSecret()
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(secret, "whsec_") || len(secret) != 70 {
		t.Fatal("invalid signing secret format")
	}
}
