# openid-jwt-validator

A production-ready Go package for validating JWT access tokens from Microsoft OpenID Connect (OIDC) by fetching and using the appropriate public keys from Microsoft's JWKS endpoint with intelligent caching.

## 🚀 Features

- **Microsoft OIDC Integration**: Fetches OpenID configuration from Microsoft's discovery endpoint
- **JWKS Management**: Retrieves JSON Web Key Set (JWKS) from Microsoft with 24-hour caching
- **Token Validation**: Validates JWT tokens using the correct public key based on the `kid` field
- **RSA256 Support**: Full support for RS256 signing algorithm
- **Key Rotation Handling**: Automatically handles Microsoft's frequent key rotation
- **PEM Conversion**: Converts X.509 certificates from JWK data to PEM format
- **Production Ready**: Includes comprehensive error handling and security measures

## 📦 Installation

```bash
go mod tidy
```

## 🔧 Usage

### Basic Example

```go
package main

import (
    "fmt"
    "log"
    jwtvalidator "jwt-validator"
)

func main() {
    // Create a new validator instance
    v := jwtvalidator.NewValidator()

    // Step 1: Fetch the OpenID configuration
    if err := v.FetchOpenIDConfiguration(); err != nil {
        log.Fatalf("Failed to fetch OpenID configuration: %v", err)
    }

    // Step 2: Validate a JWT token (automatically fetches JWKS if needed)
    tokenString := "your.jwt.token.here"
    token, err := v.ValidateToken(tokenString)
    if err != nil {
        log.Fatalf("Token validation failed: %v", err)
    }

    fmt.Printf("Token is valid! Claims: %+v\n", token.Claims)
}
```

### Complete Example with All Features

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"
    jwtvalidator "jwt-validator"
)

func main() {
    // Create a new validator instance
    v := jwtvalidator.NewValidator()

    // Step 1: Fetch the OpenID configuration
    fmt.Println("Fetching OpenID configuration...")
    if err := v.FetchOpenIDConfiguration(); err != nil {
        log.Fatalf("Failed to fetch OpenID configuration: %v", err)
    }
    fmt.Printf("JWKS URI: %s\n", v.GetJWKSURI())

    // Step 2: Fetch JWKS with caching (24-hour cache)
    fmt.Println("Fetching JWKS (with caching)...")
    if err := v.FetchJWKSIfNeeded(); err != nil {
        log.Fatalf("Failed to fetch JWKS: %v", err)
    }

    // Step 3: Extract token header to get the kid
    tokenString := "your.jwt.token.here"
    header, err := jwtvalidator.ExtractTokenHeader(tokenString)
    if err != nil {
        log.Fatalf("Failed to extract token header: %v", err)
    }

    kid, ok := header["kid"].(string)
    if !ok {
        log.Fatal("kid not found in token header")
    }
    fmt.Printf("Key ID (kid): %s\n", kid)

    // Step 4: Get the public key by kid
    publicKey, err := v.GetPublicKeyByKid(kid)
    if err != nil {
        log.Fatalf("Failed to get public key: %v", err)
    }
    fmt.Printf("Public key modulus length: %d bits\n", publicKey.N.BitLen())

    // Step 5: Validate the token
    token, err := v.ValidateToken(tokenString)
    if err != nil {
        log.Fatalf("Token validation failed: %v", err)
    }
    fmt.Printf("Token is valid! Claims: %+v\n", token.Claims)
}
```

## 🔄 Step-by-Step Process

The package follows the exact Microsoft OIDC validation process:

1. **Obtain the Public Key**:
   - Fetches the `jwks_uri` from `https://login.microsoftonline.com/common/.well-known/openid-configuration`
   - Navigates to the JWKS endpoint to retrieve the list of public keys
   - Finds the public key with the same thumbprint (`kid`) as specified in the JWT header

2. **JWT Header Processing**:
   - Extracts the `kid` field from the JWT header
   - Uses the `kid` to locate the correct public key in the JWKS

3. **Token Validation**:
   - Validates the JWT signature using the retrieved public key
   - Supports RS256 signing algorithm

## 🗄️ Caching Strategy

### 24-Hour JWKS Cache
- **Automatic Caching**: JWKS is cached in memory for 24 hours
- **Key Rotation Handling**: Automatically refreshes when cache expires
- **Performance**: Reduces API calls to Microsoft's JWKS endpoint
- **Reliability**: Handles Microsoft's frequent key rotation seamlessly

### Cache Behavior
```go
// First call: Fetches from Microsoft
err := v.FetchJWKSIfNeeded()

// Subsequent calls within 24 hours: Uses cache
err := v.ValidateToken(tokenString) // Automatically uses cached JWKS
```

## 🔧 Advanced Usage

### Extract Token Header

```go
// Extract header without validation
header, err := jwtvalidator.ExtractTokenHeader(tokenString)
if err != nil {
    log.Fatal(err)
}

// Get the kid from header
kid, ok := header["kid"].(string)
if !ok {
    log.Fatal("kid not found in token header")
}
fmt.Printf("Key ID: %s\n", kid)
```

### Get Public Key by KID

```go
// Get a specific public key by its kid
publicKey, err := v.GetPublicKeyByKid("CNv0OI3RwqlHFEVnaoMAshCH2XE")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Public key modulus length: %d bits\n", publicKey.N.BitLen())
```

### Convert X.509 Certificate to PEM

```go
// Convert an x5c certificate from base64 to PEM format
x5c := "MIIC/TCCAeWgAwIBAgIICu+WfBLOqBAwDQYJKoZIhvcNAQELBQAwLTErMCkGA1UE..."
pem := jwtvalidator.X5CToPEM(x5c)
fmt.Println("PEM-formatted certificate:")
fmt.Println(pem)
```

## 📋 API Reference

### Validator

```go
type Validator struct {
    // ... internal fields
}
```

#### Methods

- `NewValidator() *Validator` - Creates a new validator instance
- `FetchOpenIDConfiguration() error` - Fetches Microsoft's OpenID configuration
- `FetchJWKSIfNeeded() error` - Fetches JWKS with 24-hour caching
- `ValidateToken(tokenString string) (*jwt.Token, error)` - Validates a JWT token
- `GetPublicKeyByKid(kid string) (*rsa.PublicKey, error)` - Gets a public key by KID
- `GetJWKSURI() string` - Returns the JWKS URI from the configuration
- `GetJWKS() jwk.Set` - Returns the current JWKS (for testing)

### Utility Functions

- `ExtractTokenHeader(tokenString string) (map[string]interface{}, error)` - Extracts JWT header
- `DecodeX509Certificate(base64Cert string) (*x509.Certificate, error)` - Decodes X.509 certificate
- `X5CToPEM(x5c string) string` - Converts x5c base64 to PEM format

## 🔐 Security Considerations

### Best Practices
- **Always validate tokens** in a secure environment
- **Use HTTPS** for all network requests
- **Implement proper error handling** for production use
- **Validate token claims** beyond just signature validation
- **Monitor key rotation** and cache expiration

### Error Handling
The package provides detailed error messages for:
- Network connectivity problems
- Invalid JWT format
- Missing or invalid `kid` in token header
- Key not found in JWKS
- Invalid token signature
- Unsupported signing algorithms

## 🧪 Testing

### Run Tests
```bash
go test -v
```

### Run Example
```bash
cd example
go run main.go
```

### Test with Real Microsoft Data
```bash
cd test_keys
go run test_keys.go
```

## 📊 Example Output

### Successful Validation
```
Fetching OpenID configuration...
OpenID Configuration fetched successfully
JWKS URI: https://login.microsoftonline.com/common/discovery/keys

Fetching JWKS (with caching)...
JWKS fetched and cached successfully

Extracting token header...
Token Header:
{
  "alg": "RS256",
  "kid": "CNv0OI3RwqlHFEVnaoMAshCH2XE",
  "typ": "JWT"
}
Key ID (kid): CNv0OI3RwqlHFEVnaoMAshCH2XE

Retrieving public key for kid: CNv0OI3RwqlHFEVnaoMAshCH2XE
Public key retrieved successfully
Public key modulus length: 2048 bits

Token validation successful!
```

## 🔗 Dependencies

- `github.com/golang-jwt/jwt/v5` - JWT parsing and validation
- `github.com/lestrrat-go/jwx/v2` - JWK handling

## 📝 Example JWT Header

The package handles JWT headers like:

```json
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "CNv0OI3RwqlHFEVnaoMAshCH2XE"
}
```

## 📋 Example JWK

The package works with JWK data like:

```json
{
  "kty": "RSA",
  "use": "sig",
  "kid": "CNv0OI3RwqlHFEVnaoMAshCH2XE",
  "x5t": "CNv0OI3RwqlHFEVnaoMAshCH2XE",
  "n": "hz6fUSCSAuiyQz6L1nQj4za8kItevJzxhVbecMigTIl9pXZSHZa3gzMgtapnb1q96CG5qvR78dH6ZvTKL8MzN4VfGgZhvLEv5LJKeo0tGgBIS65wxIiJYj9ExEDqFkw9RdhW1nN8IN9eO76PbC-fdEPtDekA2BaITY2DARISKN4Ke0RLBEWNrKeEjjOzrygS2e3Q9NVzE51ZGGQAGHau7atHy8M_qA1nnd2dMUgUMnEYIMzDBTSKz17G6itJOdanGvG3wXvdpndKffnDppaPkyWbnybdMI4IP7q6WsCqnt3Gtg-baG6GDqZQQEBp9C9gLAFv4ORTRlpD3w0gCMh7xw",
  "e": "AQAB",
  "x5c": [
    "MIIC/TCCAeWgAwIBAgIICu+WfBLOqBAwDQYJKoZIhvcNAQELBQAwLTErMCkGA1UE..."
  ]
}
```

## 🚀 Production Deployment

### Environment Setup
1. Ensure HTTPS is enabled for all requests
2. Configure proper logging and monitoring
3. Set up error alerting for validation failures
4. Monitor JWKS cache performance

### Performance Optimization
- The 24-hour cache significantly reduces API calls
- Consider implementing additional caching layers if needed
- Monitor memory usage for long-running applications

### Monitoring
- Track validation success/failure rates
- Monitor JWKS fetch times
- Alert on cache misses or validation errors
- Log key rotation events

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Credits

This project was created and maintained by **Amar Singh Rathour** (https://github.com/amarsinghrathour).

Special thanks to Amar for the vision, guidance, and implementation of this open source Microsoft OIDC JWT validator for Go.
