// Package jwtvalidator provides a production-ready JWT validator for Microsoft OpenID Connect (OIDC).
// It handles fetching and caching of Microsoft's JWKS (JSON Web Key Set) with automatic key rotation support.
//
// Key Features:
// - 24-hour JWKS caching to handle Microsoft's frequent key rotation
// - Automatic OpenID configuration discovery
// - RSA256 token validation
// - X.509 certificate to PEM conversion
// - Comprehensive error handling
//
// Example usage:
//
//	v := jwtvalidator.NewValidator()
//	token, err := v.ValidateToken("your.jwt.token")
//	if err != nil {
//	    log.Fatal(err)
//	}
package jwtvalidator

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// OpenIDConfiguration represents the Microsoft OIDC configuration
// fetched from https://login.microsoftonline.com/common/.well-known/openid-configuration
type OpenIDConfiguration struct {
	Issuer                string   `json:"issuer"`                // The OIDC issuer identifier
	AuthorizationEndpoint string   `json:"authorization_endpoint"` // OAuth2 authorization endpoint
	TokenEndpoint         string   `json:"token_endpoint"`         // OAuth2 token endpoint
	JWKSURI               string   `json:"jwks_uri"`               // JSON Web Key Set endpoint
	ResponseTypes         []string `json:"response_types"`         // Supported response types
	SubjectTypes          []string `json:"subject_types"`          // Supported subject types
	IDTokenSigningAlg     []string `json:"id_token_signing_alg_values_supported"` // Supported signing algorithms
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Kid string   `json:"kid"`
	X5t string   `json:"x5t"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

// JWKSet represents a set of JSON Web Keys
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// Validator represents a JWT validator for Microsoft OIDC with built-in caching.
// It automatically handles Microsoft's key rotation by caching JWKS for 24 hours.
type Validator struct {
	openIDConfig *OpenIDConfiguration // Cached OpenID configuration
	jwks         jwk.Set              // Cached JSON Web Key Set
	jwksFetched  time.Time            // Timestamp when JWKS was last fetched
	client       *http.Client         // HTTP client for API calls
}

// NewValidator creates a new JWT validator instance with a 30-second HTTP timeout.
// The validator will automatically handle JWKS caching and key rotation.
func NewValidator() *Validator {
	return &Validator{
		client: &http.Client{
			Timeout: 30 * time.Second, // Reasonable timeout for Microsoft API calls
		},
	}
}

// FetchOpenIDConfiguration retrieves the OpenID configuration from Microsoft's discovery endpoint.
// This must be called before fetching JWKS or validating tokens.
// The configuration is cached in the validator instance.
func (v *Validator) FetchOpenIDConfiguration() error {
	resp, err := v.client.Get("https://login.microsoftonline.com/common/.well-known/openid-configuration")
	if err != nil {
		return fmt.Errorf("failed to fetch OpenID configuration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch OpenID configuration: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	var config OpenIDConfiguration
	if err := json.Unmarshal(body, &config); err != nil {
		return fmt.Errorf("failed to parse OpenID configuration: %w", err)
	}

	v.openIDConfig = &config
	return nil
}

// FetchJWKSIfNeeded retrieves the JWKS if not cached or cache is older than 24 hours.
// This implements Microsoft's recommendation to refresh keys every 24 hours.
// The method is automatically called by ValidateToken and GetPublicKeyByKid.
func (v *Validator) FetchJWKSIfNeeded() error {
	if v.jwks != nil && time.Since(v.jwksFetched) < 24*time.Hour {
		return nil // Use cached keys
	}
	if v.openIDConfig == nil {
		return fmt.Errorf("OpenID configuration not fetched. Call FetchOpenIDConfiguration first")
	}
	resp, err := v.client.Get(v.openIDConfig.JWKSURI)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch JWKS: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	jwks, err := jwk.Parse(body)
	if err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}
	v.jwks = jwks
	v.jwksFetched = time.Now()
	return nil
}

// ValidateToken validates a JWT token using the appropriate public key from Microsoft's JWKS.
// It automatically fetches JWKS if needed and handles key rotation.
// Returns the parsed JWT token if valid, or an error if validation fails.
func (v *Validator) ValidateToken(tokenString string) (*jwt.Token, error) {
	if err := v.FetchJWKSIfNeeded(); err != nil {
		return nil, err
	}

	// Parse the token without validation first to get the header
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Extract the kid from the header
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("kid not found in token header")
	}

	// Find the key with matching kid
	key, found := v.jwks.LookupKeyID(kid)
	if !found {
		return nil, fmt.Errorf("key with kid %s not found in JWKS", kid)
	}

	// Get the public key
	var rawKey interface{}
	if err := key.Raw(&rawKey); err != nil {
		return nil, fmt.Errorf("failed to get raw key: %w", err)
	}

	// Parse the token with validation
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return rawKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	if !parsedToken.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	return parsedToken, nil
}

// GetPublicKeyByKid retrieves a specific public key by its kid from the cached JWKS.
// It automatically fetches JWKS if needed and handles key rotation.
// Returns the RSA public key if found, or an error if the key is not in the JWKS.
func (v *Validator) GetPublicKeyByKid(kid string) (*rsa.PublicKey, error) {
	if err := v.FetchJWKSIfNeeded(); err != nil {
		return nil, err
	}

	key, found := v.jwks.LookupKeyID(kid)
	if !found {
		return nil, fmt.Errorf("key with kid %s not found in JWKS", kid)
	}

	var rawKey interface{}
	if err := key.Raw(&rawKey); err != nil {
		return nil, fmt.Errorf("failed to get raw key: %w", err)
	}

	publicKey, ok := rawKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA public key")
	}

	return publicKey, nil
}

// DecodeX509Certificate decodes an X.509 certificate from base64-encoded DER data.
// This is useful for working with certificates from the x5c field in JWK data.
// Returns the parsed X.509 certificate, or an error if decoding fails.
func DecodeX509Certificate(base64Cert string) (*x509.Certificate, error) {
	data, err := base64.StdEncoding.DecodeString(base64Cert)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}

	return cert, nil
}

// GetJWKSURI returns the JWKS URI from the cached OpenID configuration.
// Returns an empty string if the configuration hasn't been fetched yet.
func (v *Validator) GetJWKSURI() string {
	if v.openIDConfig == nil {
		return ""
	}
	return v.openIDConfig.JWKSURI
}

// GetJWKS returns the current JWKS (for testing and debugging purposes).
// This method is primarily intended for testing and should not be used in production code.
func (v *Validator) GetJWKS() jwk.Set {
	return v.jwks
}

// ExtractTokenHeader extracts the header from a JWT token without validation.
// This is useful for inspecting the token's kid and algorithm before validation.
// Returns the decoded header as a map, or an error if the token format is invalid.
func ExtractTokenHeader(tokenString string) (map[string]interface{}, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT token format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	return header, nil
}

// X5CToPEM converts a base64-encoded x5c certificate to PEM format.
// This is useful for converting Microsoft's certificate format to standard PEM format.
// The PEM output includes proper headers and line breaks every 64 characters.
func X5CToPEM(x5c string) string {
	var pem strings.Builder
	pem.WriteString("-----BEGIN CERTIFICATE-----\n")
	for i := 0; i < len(x5c); i += 64 {
		end := i + 64
		if end > len(x5c) {
			end = len(x5c)
		}
		pem.WriteString(x5c[i:end] + "\n")
	}
	pem.WriteString("-----END CERTIFICATE-----\n")
	return pem.String()
} 