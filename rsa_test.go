package jwt

import (
	"bytes"
	"strings"
	"testing"
)

const (
	// fakePrivateRS256Key is generated using following command,
	// $ openssl genrsa  -out private.pem 2048
	// Note that 2048 is just the key length.
	fakePrivateRS256Key = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtsenCilHdsl2HWmHKDPlMshO6YZDXFASvGOilvMa0hzsIAlL
OZPgz6GchuWUbSSTnt5aCsSw/VbkQwfN58dMN/ASn7XXbtoXsmdpQtL65veQSwsD
U+L/B1rmz7/UW+uwbB0VtW7EvSz1/st5DprD3KyVIoUUTKPft93NFPWHZdd+ZAQm
ZKk6VYJyQUA0+a6S1w1NT9CGAB1JrWCm6Zqr1wzOm6JIy3Wyelucv/cPELHV4yon
Vj1sxqvk2RDNiPCZaBikJM+UuO2nSjUjA6ogSbHwf1CcyOyepPZLpo3t0/0y/RjU
wC8NqJRBKeavjkOHZBkz4FtkUok5KfwCt0WsIQIDAQABAoIBAASSM6w+Ygoneau8
ouOvgJDnj4mpkO+zFPTfLQbHZ6lPjdwzP01eVGX87bQ186NTIdn8R5YzWxXK4YSH
om+kfVR8zYpu+sdL7wHIMkq4igvSryohSWEEsUoWzOTvMDloSI47n/pcndD5WeGY
ZxulZTaUnloxp9NO2d54TpOynENAuJNDrlxxpcJTvgHbZDGhPlQRytUZLuWzUVzw
yufAZoeJ6RCcJ+9LymjrHSE+2rjq1CYvl5JRdPPO1ChY/6c4LdtRlvXIy8QPbxI9
d2SsmnX433EPctL8nB2if9FSGW3fx9H6MSc6TUT9YN264d0lTS501AY2DVzTAwcT
1Rc7oF0CgYEA5NOtOi6uXR/KiR2rnoTZ5aA00NEcKtBnNsjnOkkcsTih4FmktWg+
J04hXqPXrWjxmHEL6rBXDE54MJ2HlimTqtWIv9AVMBOpjVoUlD0fiTsgIe/rhf43
eF4TFB0JCdTZCR6kg4b0Ttq7+jhipQ4tbMfpfi4ZIEBatUr+sxCMqQ8CgYEAzHwm
j7mmLQdANvxQUtJSaxiGgBq9Gops9zS7rJS62avwEaHbwMThXwQBEYntt5jTmPjz
8lB1QEChq01RTJSmpJ2VALMbTY0uXra4bzPgeZpPXDzJOgX+O1Mhd5q2mVczhKeg
99DSVLQgxelG4Hrn+djxoEqw6r9/SjjSfO/dd88CgYEAnXdZLr+u96CH9MF5N1W+
yLjtf4FW+9N8I4QvMrnbR81sAAJQSRHaK5wldIYVRl0AXGH2zGLbFDnvlaziACDO
YHIfb7fWzMXLGN2TacuCJyKL4y7CCew96dP7Fw1ACgbx78epeGVnO9hkITWqFGFk
OwZ7FHzOh5Yhlb5s9XZ/BVsCgYAICMy/Eu1LkaBdSLajOm5QlOsb93D8rPmxENpa
4pEg4leRacmnnlS4lgCwvrmfYBrYRNfY6n5g4uk3QNdz6ddOWn6zQ1ZMSsLKp+VB
QUmNnZmGp0DEzd16WT7UYzjPd5Snnqp9cjABcf5jqFHHmiypLXP491ZSMun+cZMb
o5UREwKBgQDLwhLAT5GIz8PsXDaS0ESWoelKRf9GhKDyHrJfXmqYPBFjm9sAp/em
/GA8BqGQrYf2fKMrm8o6s73MnSuYUtb+Kw/Dpw71I+iVQkIsFOktnPZEO4tMJQIJ
Q+ynTMTFONDH9WU2273AXlcbyxPI0eVArDLFRYcLtrdKupcYsjKc6g==
-----END RSA PRIVATE KEY-----
`
	// fakePublicRS256Key is generated after generating private key
	// using following command.
	// $ openssl rsa -in public.pem -pubin -RSAPublicKey_out
	// Since we extracted private cert using openssl, we need to
	// convert it to RSA formatm hence the flag `-RSAPublicKey_out`.
	fakePublicRS256Key = `
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAtsenCilHdsl2HWmHKDPlMshO6YZDXFASvGOilvMa0hzsIAlLOZPg
z6GchuWUbSSTnt5aCsSw/VbkQwfN58dMN/ASn7XXbtoXsmdpQtL65veQSwsDU+L/
B1rmz7/UW+uwbB0VtW7EvSz1/st5DprD3KyVIoUUTKPft93NFPWHZdd+ZAQmZKk6
VYJyQUA0+a6S1w1NT9CGAB1JrWCm6Zqr1wzOm6JIy3Wyelucv/cPELHV4yonVj1s
xqvk2RDNiPCZaBikJM+UuO2nSjUjA6ogSbHwf1CcyOyepPZLpo3t0/0y/RjUwC8N
qJRBKeavjkOHZBkz4FtkUok5KfwCt0WsIQIDAQAB
-----END RSA PUBLIC KEY-----
`
)

func TestNewMethodRSA(t *testing.T) {
	readerPriv := strings.NewReader(fakePrivateRS256Key)
	readerPub := strings.NewReader(fakePublicRS256Key)

	rsa, err := NewMethodRSA(readerPriv, readerPub)
	if err != nil {
		t.Error(err)
		return
	}
	if rsa == nil {
		t.Error(err)
		return
	}
}

func TestSignAndVerify(t *testing.T) {
	readerPriv := strings.NewReader(fakePrivateRS256Key)
	readerPub := strings.NewReader(fakePublicRS256Key)

	rsa, _ := NewMethodRSA(readerPriv, readerPub)

	s := "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do."
	r := strings.NewReader(s)
	signature, err := rsa.Sign(r)
	if err != nil {
		t.Error(err)
	}
	if len(signature) == 0 {
		t.Error("signed string is nil")
	}

	err = rsa.Verify(strings.NewReader(s), bytes.NewReader(signature))
	if err != nil {
		t.Error(err)
	}
}
