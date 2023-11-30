package dokku_common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_RequestMayThrough(t *testing.T) {
	// todo Finish this test
}
func Test_UserTokenContextMiddleware(t *testing.T) {
	// todo Finish this test
}
func Test_KeyLoadEmpty(t *testing.T) {
	privateKey := GetPrivateKey(nil)
	assert.NotNil(t, privateKey)
	publicKey := GetPublicKey(nil)
	assert.NotNil(t, publicKey)
}

func Test_KeyLoadLoaded(t *testing.T) {
	privateKey := GetPrivateKey([]byte(DefaultPrivatePEM))
	assert.NotNil(t, privateKey)
	publicKey := GetPublicKey([]byte(DefaultPublicPEM))
	assert.NotNil(t, publicKey)
}
