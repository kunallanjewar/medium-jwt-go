package jwt

import "io"

const (
	HeaderRS256   = "RS256"
	HeaderTypeJWT = "jwt"
)

// Header defines the algorithm and type of Base64 encoded object.
// This is the first piece in the JWT.
// https://tools.ietf.org/html/rfc7519#page-6
type Header struct {
	// Algorithm that this package supports in RSA256
	Algorithm string `json:"alg"`
	// Type supported is JWT only
	Type string `json:"type"`
}

// Payload contains custom Public claims as defined in registered in IANA registry.
// https://www.iana.org/assignments/jwt/jwt.xhtml
//
// This is the second piece of the JWT.
// https://tools.ietf.org/html/rfc7519#page-8
type Payload struct {
	KeyIdentifier string `json:"kid"`
	IssuedAt      int64  `json:"iat"`
	Expiration    int64  `json:"exp"`
	Issuer        string `json:"iss"`
	Subject       string `json:"sub"`
	Audience      string `json:"aud"`
	User          *User  `json:"user"`
}

// User strut holds the information of a user
// who is trying to authenticate using the jwt.
// Complies with IANA registry.
type User struct {
	FirstName     string `json:"given_name"`
	LastName      string `json:"family_name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// Signature is the third piece of the JWT.
// A Base64 encoded string.
type Signature io.Reader

type ParseJwt struct {
	header    *Header
	payload   *Payload
	signature *Signature
}

type JWT struct {
	*ParseJwt
}

// NewWithPayload creates a *JWT and sets headers.
func NewWithPayload(p *Payload) *JWT {
	return &JWT{
		ParseJwt: &ParseJwt{
			payload: p,
			header: &Header{
				Algorithm: HeaderRS256,
				Type:      HeaderTypeJWT,
			},
		},
	}
}

// SignedJWT encodes, signs, and returns signed jwt string.
// Note: This method only supports RS256 algorithm for signing,
// a.k.a RSA PKCS#1 signature with SHA-256.
func (jwt *JWT) SignedJWT() (string, error) {
	return "TODO", nil
}

// Signer signs bytes with RSA256 algorithm.
type Signer interface {
	Sign(bytesToSign io.Reader) ([]byte, error)
}

// Verifier verifies the signature bytes are signed with.
// Returns error if verification is failed.
type Verifier interface {
	Verify(bytesToVerify io.Reader) error
}
