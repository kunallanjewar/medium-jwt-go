package jwt

import (
	"strings"
	"testing"
)

var payload = &Payload{
	KeyIdentifier: "123",
	IssuedAt:      1565296295,
	Expiration:    1565296895,
	Issuer:        "issuer",
	Subject:       "subject",
	Audience:      "audience",
	User: &User{
		FirstName:     "John",
		LastName:      "Doe",
		Email:         "jd@fakemail.com",
		EmailVerified: true,
	},
}

func TestSignedJWT(t *testing.T) {
	// make a jwt on jwt.io signed with our fake keys.
	expectedJWT := "eyJhbGciOiJSUzI1NiIsInR5cGUiOiJKV1QifQ.eyJraWQiOiIxMjMiLCJpYXQiOjE1NjUyOTYyOTUsImV4cCI6MTU2NTI5Njg5NSwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCIsImF1ZCI6ImF1ZGllbmNlIiwidXNlciI6eyJnaXZlbl9uYW1lIjoiSm9obiIsImZhbWlseV9uYW1lIjoiRG9lIiwiZW1haWwiOiJqZEBmYWtlbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZX19.mn1rn1ethNRiUdtpq09oSKI3yQcrE9MkuzQ1ycMlq6q8WyhNBYmvBdRWSUaohqYACDPqWPdzQNHBNov5-0zK1DB0M70eXK4-UMb-3X25mIevKGRbZaF3qAWHgF9IkeSPhUbgxL1dhrkayne_2qH9npj3jXrmAYZBr7FN2AhmZ2luF6NUTp3rjT5KHo2AMgnRa6twnDSeDL-_7wr8qBN6iF8S-x1t0A9OzShmktul1PXOXEymZ0wFyaAPcV4aM1wzbGnIoJBGpAHXoSnUmKTvpn1i5eL0EmMqnZVZUhu-FSGD7sC6jQmfxnZNw44U8AjT0vRl5aKUeWGsd9-P-_NBZg"

	privateKey := strings.NewReader(fakePrivateRS256Key)
	publicKey := strings.NewReader(fakePublicRS256Key)
	s, err := NewMethodRSA(privateKey, publicKey)
	if err != nil {
		t.Error(err)
	}

	st, err := NewWithPayload(payload, s)
	if err != nil {
		t.Error(err)
	}

	actual, err := st.SignedJWT()
	if err != nil {
		t.Error(err)
	}
	if expectedJWT != actual {
		t.Errorf("jwt %s did not match expected %s", actual, expectedJWT)
	}
}
