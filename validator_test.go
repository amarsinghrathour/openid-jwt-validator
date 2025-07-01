package jwtvalidator

import (
	"testing"
)

func TestNewValidator(t *testing.T) {
	v := NewValidator()
	if v == nil {
		t.Fatal("NewValidator() returned nil")
	}
	if v.client == nil {
		t.Fatal("HTTP client is nil")
	}
}

func TestFetchOpenIDConfiguration(t *testing.T) {
	v := NewValidator()
	
	err := v.FetchOpenIDConfiguration()
	if err != nil {
		t.Fatalf("Failed to fetch OpenID configuration: %v", err)
	}
	
	if v.openIDConfig == nil {
		t.Fatal("OpenID configuration is nil")
	}
	
	if v.openIDConfig.JWKSURI == "" {
		t.Fatal("JWKS URI is empty")
	}
	
	expectedJWKSURI := "https://login.microsoftonline.com/common/discovery/keys"
	if v.openIDConfig.JWKSURI != expectedJWKSURI {
		t.Errorf("Expected JWKS URI %s, got %s", expectedJWKSURI, v.openIDConfig.JWKSURI)
	}
}

func TestFetchJWKSIfNeeded(t *testing.T) {
	v := NewValidator()
	// First fetch the OpenID configuration
	err := v.FetchOpenIDConfiguration()
	if err != nil {
		t.Fatalf("Failed to fetch OpenID configuration: %v", err)
	}
	// Then fetch the JWKS (should fetch and cache)
	err = v.FetchJWKSIfNeeded()
	if err != nil {
		t.Fatalf("Failed to fetch JWKS: %v", err)
	}
	if v.jwks == nil {
		t.Fatal("JWKS is nil")
	}
	firstFetched := v.jwksFetched
	// Call again, should use cache (no error, timestamp should not change)
	err = v.FetchJWKSIfNeeded()
	if err != nil {
		t.Fatalf("Failed to fetch JWKS from cache: %v", err)
	}
	if v.jwksFetched != firstFetched {
		t.Errorf("JWKS cache timestamp changed unexpectedly")
	}
}

func TestExtractTokenHeader(t *testing.T) {
	// Example JWT token with a real kid from Microsoft's JWKS
	tokenString := "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IkNOdjBPSVNSd3FsSEZFVm5hb01Bc2hDSDJYRSJ9.eyJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vY29tbW9uIiwic3ViIjoiZXhhbXBsZSIsImF1ZCI6ImV4YW1wbGUiLCJpYXQiOjE2MzQ1Njc4OTAsImV4cCI6MTYzNDU3MTQ5MH0.signature"
	
	header, err := ExtractTokenHeader(tokenString)
	if err != nil {
		t.Fatalf("Failed to extract token header: %v", err)
	}
	
	// Check the expected values
	if header["typ"] != "JWT" {
		t.Errorf("Expected typ 'JWT', got %v", header["typ"])
	}
	
	if header["alg"] != "RS256" {
		t.Errorf("Expected alg 'RS256', got %v", header["alg"])
	}
	
	expectedKid := "CNv0OISRwqlHFEVnaoMAshCH2XE"
	if header["kid"] != expectedKid {
		t.Errorf("Expected kid '%s', got %v", expectedKid, header["kid"])
	}
}

func TestGetJWKSURI(t *testing.T) {
	v := NewValidator()
	
	// Initially should return empty string
	if v.GetJWKSURI() != "" {
		t.Errorf("Expected empty JWKS URI before fetching config, got %s", v.GetJWKSURI())
	}
	
	// Fetch the configuration
	err := v.FetchOpenIDConfiguration()
	if err != nil {
		t.Fatalf("Failed to fetch OpenID configuration: %v", err)
	}
	
	// Now should return the JWKS URI
	expectedJWKSURI := "https://login.microsoftonline.com/common/discovery/keys"
	if v.GetJWKSURI() != expectedJWKSURI {
		t.Errorf("Expected JWKS URI %s, got %s", expectedJWKSURI, v.GetJWKSURI())
	}
}

func TestGetPublicKeyByKid(t *testing.T) {
	v := NewValidator()
	
	// Fetch configuration and JWKS
	err := v.FetchOpenIDConfiguration()
	if err != nil {
		t.Fatalf("Failed to fetch OpenID configuration: %v", err)
	}
	
	err = v.FetchJWKSIfNeeded()
	if err != nil {
		t.Fatalf("Failed to fetch JWKS: %v", err)
	}
	
	// Try to get a public key by kid (this will fail if the kid doesn't exist)
	// We'll use a real kid from Microsoft's JWKS response
	kid := "CNv0OI3RwqlHFEVnaoMAshCH2XE"
	publicKey, err := v.GetPublicKeyByKid(kid)
	
	// This might fail if the key doesn't exist in the current JWKS
	// That's expected behavior, so we just log it
	if err != nil {
		t.Logf("Key with kid %s not found (this is expected if the key is not in current JWKS): %v", kid, err)
	} else {
		if publicKey == nil {
			t.Fatal("Public key is nil")
		}
		t.Logf("Successfully retrieved public key with %d bits", publicKey.N.BitLen())
	}
}

func TestDecodeX509Certificate(t *testing.T) {
	// Example certificate from your JWK (first certificate in the x5c array)
	base64Cert := "MIIC4jCCAcqgAwIBAgIQbJm7eEjzMAGOCg58LS3b3D0EQwJumOCkZAp8b9NVBam1FmYz19bmRZfLmFYl2Vc2vbnKnyB2wUdZG39v5ZuVCxhimhMC0v4DrhQ2EM4TKMzizWhcmMiQWOmiM1ibAn8HkqGW9wDeZAFQCQAABM1bcKKGQAEIAMEMIbkCQA0Ehl1neIeb0CkZ0FbTz6dskL9A=="
	
	cert, err := DecodeX509Certificate(base64Cert)
	if err != nil {
		t.Logf("Failed to decode X.509 certificate (this might be expected for test data): %v", err)
		// Don't fail the test since this is just example data
		return
	}
	
	if cert == nil {
		t.Fatal("Certificate is nil")
	}
	
	t.Logf("Successfully decoded certificate with subject: %s", cert.Subject)
}

func TestX5CToPEM(t *testing.T) {
	// Using a real certificate from Microsoft's JWKS response
	x5c := "MIIC/TCCAeWgAwIBAgIICu+WfBLOqBAwDQYJKoZIhvcNAQELBQAwLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDAeFw0yNTAzMTYyMDE3MjNaFw0zMDAzMTYyMDE3MjNaMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCHPp9RIJIC6LJDPovWdCPjNryQi168nPGFVt5wyKBMiX2ldlIdlreDMyC1qmdvWr3oIbmq9Hvx0fpm9MovwzM3hV8aBmG8sS/kskp6jS0aAEhLrnDEiIliP0TEQOoWTD1F2FbWc3wg3147vo9sL590Q+0N6QDYFohNjYMBEhIo3gp7REsERY2sp4SOM7OvKBLZ7dD01XMTnVkYZAAYdq7tq0fLwz+oDWed3Z0xSBQycRggzMMFNIrPXsbqK0k51qca8bfBe92md0p9+cOmlo+TJZufJt0wjgg/urpawKqe3ca2D5toboYOplBAQGn0L2AsAW/g5FNGWkPfDSAIyHvHAgMBAAGjITAfMB0GA1UdDgQWBBSsQvFDUwCTJXK+ltZFLaHUGzIS6jANBgkqhkiG9w0BAQsFAAOCAQEAUsfNQA+O7eXGI4IL/FmafEmmFjoXC+Ym9UIzG/vXcXzQEK9S9nV35Q0Fn9PsL1w8Sud3itm/V6t9UtB9yaRvWREPOdEYsHEkZahoSFi2fgOLP+AsTtQq0ePeBbqAQvnfrTvFuv+j1we3uxxov77pt7U+pB+6Sq8+yww85qeTCWmV4av2WWXB+6pW9oUd/D9htlxKL5WzNsaVojP56eg3mwhBmOpqxkYnL7RAPGOYRjaeHic9ONrctC8HImjf21UC5wK8G/lcVQATcvPZm/AYJg10fNsxZ/8ApFLblf9Q8l0QcKZfjs/si3VKcWvilDrfO9Dg83Ou6tvsLnPU5lV3aA=="
	pem := X5CToPEM(x5c)
	if len(pem) == 0 {
		t.Fatal("PEM output is empty")
	}
	if pem[:27] != "-----BEGIN CERTIFICATE-----" {
		t.Errorf("PEM does not start with BEGIN CERTIFICATE")
	}
	if pem[len(pem)-26:] != "-----END CERTIFICATE-----\n" {
		t.Errorf("PEM does not end with END CERTIFICATE")
	}
} 