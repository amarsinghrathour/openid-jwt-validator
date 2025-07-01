package main

import (
	"encoding/json"
	"fmt"
	"log"

	jwtvalidator "jwt-validator"
)

func main() {
	v := jwtvalidator.NewValidator()
	
	// Fetch OpenID configuration
	if err := v.FetchOpenIDConfiguration(); err != nil {
		log.Fatalf("Failed to fetch OpenID configuration: %v", err)
	}
	
	// Fetch JWKS
	if err := v.FetchJWKSIfNeeded(); err != nil {
		log.Fatalf("Failed to fetch JWKS: %v", err)
	}
	
	// Get JWKS as JSON to see all available keys
	jwksJSON, err := json.MarshalIndent(v.GetJWKS(), "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JWKS: %v", err)
	}
	
	fmt.Println("Available keys in Microsoft JWKS:")
	fmt.Println(string(jwksJSON))
} 