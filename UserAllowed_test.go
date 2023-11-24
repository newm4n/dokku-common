package dokku_common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUserIsAllowedInAudience(t *testing.T) {
	assert.True(t, UserIsAllowedInAudience([]string{"r1,r2,r3@t1", "r1,r2,r3@t2", "r1,r2,r3@t3"}, "t1", "r1"))
}

func TestUserIsAllowed(t *testing.T) {
	assert.True(t, userIsAllowed("r1,r2,r3@t1", "t1", "r1"))
	assert.True(t, userIsAllowed("r1,r2,r3@t1", "t1", "r2"))
	assert.True(t, userIsAllowed("r1,r2,r3@t1", "t1", "r3"))
	assert.True(t, userIsAllowed("r1@t1", "t1", "r1"))
	assert.False(t, userIsAllowed("r1,r2,r3@t1", "t3", "r1"))
	assert.False(t, userIsAllowed("r1,r2,r3@t1", "t3", "r2"))
	assert.False(t, userIsAllowed("r1,r2,r3@t1", "t3", "r3"))
}

func TestStringInArray(t *testing.T) {
	assert.True(t, StringInArray([]string{"r1", "r2", "r3"}, "r1"))
	assert.True(t, StringInArray([]string{"r1", "r2", "r3"}, "r2"))
	assert.True(t, StringInArray([]string{"r1", "r2", "r3"}, "r3"))
	assert.False(t, StringInArray([]string{"r1", "r2", "r3"}, "r4"))
}
