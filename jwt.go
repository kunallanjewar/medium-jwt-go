// Package jwt is a simple and custom package written to sign, encode and decode
// custom jwt tokens with RSA256 algorithm.
package jwt

// Header defines the algorithm and type of Base64 encoded object.
// This is the first piece in the JWT.
// https://tools.ietf.org/html/rfc7519#page-6
type Header struct {
	// Algorithm that this package supports in RSA256
	Algorithm string `json:"alg"`
	// Type supports is JWT only
	Type string `json:"type"`
}

// Payload contains custom Public claims as defined in registered in IANA registry.
// https://www.iana.org/assignments/jwt/jwt.xhtml
//
// This is the second piece of the JWT.
// https://tools.ietf.org/html/rfc7519#page-8
type Payload struct {
	IssuedAt   string `json:"iat"`
	Expiration string `json:"exp"`
	Issuer     string `json:"iss"`
	Subject    string `json:"sub"`
	Audience   string `json:"aud"`
	User       *User  `json:"user"`
}

// Signature is the third piece of the JWT.
// A Base64 encoded string.
type Signature string

// User strut holds the information of a user
// who is trying to authenticate using the jwt.
// Complies with IANA registry.
type User struct {
	FirstName     string `json:"given_name"`
	LastName      string `json:"family_name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}
