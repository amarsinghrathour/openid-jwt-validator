// Example demonstrates how to use the JWT validator package for Microsoft OIDC tokens.
// This example shows the complete workflow including:
// - Fetching OpenID configuration
// - JWKS caching and key retrieval
// - Token header extraction
// - Public key validation
// - PEM certificate conversion
package main

import (
	"encoding/json"
	"fmt"
	"log"

	jwtvalidator "jwt-validator"
)

func main() {
	// Create a new validator instance with automatic JWKS caching
	// The validator will handle Microsoft's key rotation automatically
	v := jwtvalidator.NewValidator()

	// Step 1: Fetch the OpenID configuration from Microsoft's discovery endpoint
	// This provides the JWKS URI and other OIDC configuration details
	fmt.Println("Fetching OpenID configuration...")
	if err := v.FetchOpenIDConfiguration(); err != nil {
		log.Fatalf("Failed to fetch OpenID configuration: %v", err)
	}
	fmt.Printf("OpenID Configuration fetched successfully\n")
	fmt.Printf("JWKS URI: %s\n", v.GetJWKSURI())

	// Step 2: Fetch the JWKS (JSON Web Key Set) using cache-aware method
	// The JWKS is cached for 24 hours to handle Microsoft's key rotation efficiently
	fmt.Println("\nFetching JWKS (with caching)...")
	if err := v.FetchJWKSIfNeeded(); err != nil {
		log.Fatalf("Failed to fetch JWKS: %v", err)
	}
	fmt.Println("JWKS fetched and cached successfully")

	// Example JWT token header using a real kid from Microsoft's JWKS
	// This uses the first key from the JWKS response: "CNv0OI3RwqlHFEVnaoMAshCH2XE"
	// Note: This is an example token with a valid kid but not a real signature
	exampleToken := "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IkNOdjBPSTNSd3FsSEZFVm5hb01Bc2hDSDJYRSJ9.eyJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vY29tbW9uIiwic3ViIjoiZXhhbXBsZSIsImF1ZCI6ImV4YW1wbGUiLCJpYXQiOjE2MzQ1Njc4OTAsImV4cCI6MTYzNDU3MTQ5MH0.signature"

	// Step 3: Extract the token header to get the kid
	// This demonstrates how to inspect a JWT token's header without validation
	fmt.Println("\nExtracting token header...")
	header, err := jwtvalidator.ExtractTokenHeader(exampleToken)
	if err != nil {
		log.Fatalf("Failed to extract token header: %v", err)
	}

	headerJSON, _ := json.MarshalIndent(header, "", "  ")
	fmt.Printf("Token Header:\n%s\n", string(headerJSON))

	// Get the kid from the header - this identifies which public key to use
	kid, ok := header["kid"].(string)
	if !ok {
		log.Fatal("kid not found in token header")
	}
	fmt.Printf("Key ID (kid): %s\n", kid)

	// Step 4: Get the public key by kid (uses JWKS cache)
	// This demonstrates how to retrieve a specific public key from the cached JWKS
	fmt.Printf("\nRetrieving public key for kid: %s\n", kid)
	publicKey, err := v.GetPublicKeyByKid(kid)
	if err != nil {
		log.Fatalf("Failed to get public key: %v", err)
	}
	fmt.Printf("Public key retrieved successfully\n")
	fmt.Printf("Public key modulus length: %d bits\n", publicKey.N.BitLen())

	// Step 5: Validate the token (this would fail with the example token since it's not real)
	// This demonstrates the complete validation process including automatic JWKS fetching
	fmt.Println("\nAttempting to validate token (first call, will fetch JWKS if needed)...")
	token, err := v.ValidateToken(exampleToken)
	if err != nil {
		fmt.Printf("Token validation failed (expected for example token): %v\n", err)
	} else {
		fmt.Printf("Token is valid!\n")
		fmt.Printf("Claims: %+v\n", token.Claims)
	}

	// Step 6: Validate the token again (should use cached JWKS, not refetch)
	// This demonstrates the caching behavior - the second call uses the cached JWKS
	fmt.Println("\nAttempting to validate token again (should use cached JWKS)...")
	token, err = v.ValidateToken(exampleToken)
	if err != nil {
		fmt.Printf("Token validation failed (expected for example token): %v\n", err)
	} else {
		fmt.Printf("Token is valid!\n")
		fmt.Printf("Claims: %+v\n", token.Claims)
	}

	// Example of how to decode an X.509 certificate from the JWK and convert to PEM
	// This demonstrates working with Microsoft's certificate format
	fmt.Println("\nExample: Decoding and converting x5c to PEM format...")
	// Using the first certificate from the real Microsoft JWKS response
	x5c := "MIIC/TCCAeWgAwIBAgIICu+WfBLOqBAwDQYJKoZIhvcNAQELBQAwLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDAeFw0yNTAzMTYyMDE3MjNaFw0zMDAzMTYyMDE3MjNaMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCHPp9RIJIC6LJDPovWdCPjNryQi168nPGFVt5wyKBMiX2ldlIdlreDMyC1qmdvWr3oIbmq9Hvx0fpm9MovwzM3hV8aBmG8sS/kskp6jS0aAEhLrnDEiIliP0TEQOoWTD1F2FbWc3wg3147vo9sL590Q+0N6QDYFohNjYMBEhIo3gp7REsERY2sp4SOM7OvKBLZ7dD01XMTnVkYZAAYdq7tq0fLwz+oDWed3Z0xSBQycRggzMMFNIrPXsbqK0k51qca8bfBe92md0p9+cOmlo+TJZufJt0wjgg/urpawKqe3ca2D5toboYOplBAQGn0L2AsAW/g5FNGWkPfDSAIyHvHAgMBAAGjITAfMB0GA1UdDgQWBBSsQvFDUwCTJXK+ltZFLaHUGzIS6jANBgkqhkiG9w0BAQsFAAOCAQEAUsfNQA+O7eXGI4IL/FmafEmmFjoXC+Ym9UIzG/vXcXzQEK9S9nV35Q0Fn9PsL1w8Sud3itm/V6t9UtB9yaRvWREPOdEYsHEkZahoSFi2fgOLP+AsTtQq0ePeBbqAQvnfrTvFuv+j1we3uxxov77pt7U+pB+6Sq8+yww85qeTCWmV4av2WWXB+6pW9oUd/D9htlxKL5WzNsaVojP56eg3mwhBmOpqxkYnL7RAPGOYRjaeHic9ONrctC8HImjf21UC5wK8G/lcVQATcvPZm/AYJg10fNsxZ/8ApFLblf9Q8l0QcKZfjs/si3VKcWvilDrfO9Dg83Ou6tvsLnPU5lV3aA=="
	pem := jwtvalidator.X5CToPEM(x5c)
	fmt.Println("PEM-formatted certificate:")
	fmt.Println(pem)

	// Step 7: Demonstrate that we can work with multiple keys from the JWKS
	// This shows how the validator can access any key in the current JWKS
	fmt.Println("\nDemonstrating access to multiple keys from JWKS...")
	// Try to get a different key from the JWKS response
	otherKid := "PoVKeirIOvmTyLQ9G9BenBwos7k"
	fmt.Printf("Attempting to retrieve key with kid: %s\n", otherKid)
	otherPublicKey, err := v.GetPublicKeyByKid(otherKid)
	if err != nil {
		fmt.Printf("Failed to get public key for %s: %v\n", otherKid, err)
	} else {
		fmt.Printf("Successfully retrieved public key with %d bits\n", otherPublicKey.N.BitLen())
	}
} 