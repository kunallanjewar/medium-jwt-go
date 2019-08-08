package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const (
	// HeaderAlgoRS256 is the algorithm this package
	// uses for jwt signing and verification.
	HeaderAlgoRS256 = "RS256"

	// HeaderTypeJWT is the header attached to the jwt
	// to identify jwt's type.
	HeaderTypeJWT = "JWT"
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

// Signer signs bytes with RSA256 algorithm.
type Signer interface {
	Sign(bytesToSign io.Reader) ([]byte, error)
}

// Verifier verifies the signature bytes are signed with.
// Returns error if verification is failed.
type Verifier interface {
	Verify(bytesToVerify io.Reader) error
}

// JWT consists of header, payload, and signature.
type JWT struct {
	header    *Header
	payload   *Payload
	signature *Signature
}

// ParseJwt knows hows to parse a jwt and
// verify it's signature.
type ParseJwt struct {
	*JWT
	verifier Verifier
}

// NewParseJwt creates a *ParseJwt.
func NewParseJwt() (*ParseJwt, error) {
	return nil, errors.New("TODO")
}

// Verify verifies a jwt signature.
// Return error if signature doesn't match.
func (pjwt *ParseJwt) Verify(jwt io.Reader) error {
	return errors.New("TODO")
}

// SignedJWT knows how to create and sign a jwt.
type SignedJWT struct {
	*JWT
	signer Signer
}

// NewWithPayload creates a *SignedJWT and sets default headers.
func NewWithPayload(p *Payload, s Signer) (*SignedJWT, error) {
	return &SignedJWT{
		JWT: &JWT{
			header: &Header{
				Algorithm: HeaderAlgoRS256,
				Type:      HeaderTypeJWT,
			},
			payload: p,
		},
		signer: s,
	}, nil
}

// SignedJWT encodes, signs, and returns signed jwt string.
// Note: This method only supports RS256 algorithm for signing,
// a.k.a RSA PKCS#1 signature with SHA-256.
func (sjwt *SignedJWT) SignedJWT() (string, error) {
	return sjwt.encodeSign()
}

func (sjwt *SignedJWT) encodeSign() (string, error) {
	h, err := json.Marshal(sjwt.header)
	if err != nil {
		return "", err
	}

	p, err := json.Marshal(sjwt.payload)
	if err != nil {
		return "", err
	}

	header := strings.TrimRight(base64.StdEncoding.EncodeToString(h), "=")
	payload := strings.TrimRight(base64.StdEncoding.EncodeToString(p), "=")

	headerPayload := header + "." + payload
	sig, err := sjwt.signer.Sign(strings.NewReader(headerPayload))
	if err != nil {
		return "", err
	}

	signature := strings.TrimRight(base64.StdEncoding.EncodeToString(sig), "=")

	return headerPayload + "." + signature, nil
}
