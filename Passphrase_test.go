package dokku_common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGeneratePassprhase(t *testing.T) {
	for i := 1; i <= 10; i++ {
		gen := MakeRandomPassphrase()
		t.Logf("#%d = \"%s\"", i, gen)
		assert.True(t, IsPassphraseAcceptable(gen))
	}
}

func TestIsPassphraseAcceptable(t *testing.T) {
	assert.True(t, IsPassphraseAcceptable("one Two ThreE"))
	assert.True(t, IsPassphraseAcceptable("one Two ThreE Four"))
	assert.False(t, IsPassphraseAcceptable(" one Two ThreE"))
	assert.False(t, IsPassphraseAcceptable("one Two ThreE "))
	assert.False(t, IsPassphraseAcceptable("one Two  ThreE"))
	assert.False(t, IsPassphraseAcceptable("one Two ThreE fo ur"))
}
