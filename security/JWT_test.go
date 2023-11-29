package security

import (
	"embed"
	"github.com/SermoDigital/jose/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

var (
	//go:embed testkey
	keyFs embed.FS
)

func TestGoClaim_MarshalUnmarshal(t *testing.T) {
	//privKey, pubKey, err := GenerateKeyPair(2048)
	//assert.NoError(t, err)

	claim := &GoClaim{
		Issuer:     "Issuer.com",
		Subscriber: "subs@Issuer.com",
		TokenType:  AccessToken,
		Audience:   []string{},
		NotBefore:  time.Time{},
		IssuedAt:   time.Time{},
		ExpireAt:   time.Time{},
		Tokenid:    "",
	}

	//privateBytes, err := keyFs.ReadFile("testkey/ori_pri.pem")
	privateBytes, err := keyFs.ReadFile("testkey/private.pem")
	assert.NoError(t, err)
	assert.NotNil(t, privateBytes)

	privk, err := BytesToPrivateKey(privateBytes)
	assert.NoError(t, err)

	token, err := claim.ToToken(privk, crypto.SigningMethodRS512)
	assert.NoError(t, err)

	//publicBytes, err := keyFs.ReadFile("testkey/ori_pub.pem")
	publicBytes, err := keyFs.ReadFile("testkey/public.pem")
	assert.NoError(t, err)
	assert.NotNil(t, publicBytes)

	pubk, err := BytesToPublicKey(publicBytes)
	assert.NoError(t, err)

	klaim, err := NewGoClaimFromToken(token, pubk, crypto.SigningMethodRS512)
	assert.NoError(t, err)

	assert.Equal(t, claim.Issuer, klaim.Issuer)
	assert.Equal(t, claim.Subscriber, klaim.Subscriber)

	assert.Equal(t, string(claim.TokenType), string(klaim.TokenType))

	//assert.Equal(t, claim.Audience, klaim.Audience)

	assert.Equal(t, 0, len(klaim.Audience))
	assert.Equal(t, 0, len(claim.Audience))
	assert.Equal(t, claim.NotBefore, klaim.NotBefore)
	assert.Equal(t, claim.IssuedAt, klaim.IssuedAt)
	assert.Equal(t, claim.ExpireAt, klaim.ExpireAt)
	assert.Equal(t, claim.Tokenid, klaim.Tokenid)
}

func TestNewGoClaimFromToken(t *testing.T) {
	refreshToken := "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJSSURAVElEIiwiZXhwIjoxNzY1NTA1NzgwLCJpYXQiOjE3MDEyMjQxODAsImlzcyI6IlNvbWVPcmdhbml6YXRpb25BQUEiLCJuYmYiOjE3MDEyMjQxODAsInN1YiI6IlVJRCIsInR5cCI6ImFwcGxpY2F0aW9uL3J0K2p3dCJ9.GUTxWTzNGNn4opgyOianSl2BqE-bOLJlaiHaZePHuAS6BAHsXGq_frtxTXOPu-3N-Bi841ba4rHK92YY47UdP1BwZQ41Gqf55kTtD4Z4-6VtLjopRvjDFkUoxv6IKvJltnJQFNuXRpY-8uCVtBpoAi0gglaBua8Y5bCX1dylmAFG03TGSTwyw_VylkLmx3m-R2FECPXsifGN-LhJ-ooLlVoslFQ1spGWf8TpPuT2mL_65xAlXj464mn4pBb5e0OOGSuIUO35YqSboTGfdin1wDMHbma239ta451I2I20P2suIBQSigWpyqJ2nRlNSndWYeCIOPBU2d6a27f1LT3tFA"
	DefaultPublicPEM := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsZ6vq7T+E6UnFHf1i5wl
js4c+dpXTsIa1fk6S6Z74v/V7AjWqXzJ52aI+N18yf+PD4HuZN/AvDOqIjQgaGUJ
H9W5F4Ppz1dNIJBU5qYsJOEwIl1/uRkBPtKPRtYESVbYPPU6va7ttZv0lZEvPpJ1
l+axo5ULaBnWW0IJqYipMU58IlVRc+sJEV0sC4vvPHk62/VixpjskHuGeD0fmNu8
U+cnv7wav+N/2G4hSgakYJofhkx+watP2wHBCrSDMq8rc4socdWebmISQhoCkwI/
Gr1F29l4A1wGjQt0oA3eTATFng+jD0MLmR3lP7elATNTmHawpBH6IqWX9eKVSJ8M
9wIDAQAB
-----END PUBLIC KEY-----`

	pubKey, err := BytesToPublicKey([]byte(DefaultPublicPEM))
	assert.NoError(t, err)

	claim, err := NewGoClaimFromToken(refreshToken, pubKey, crypto.SigningMethodRS512)
	assert.NoError(t, err)

	assert.NotNil(t, claim)

}
