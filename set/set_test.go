package set

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSet(t *testing.T) {
	set := New[int]()
	set.Add(1)
	set.Add(2)
	set.Add(3)
	set.Add(4)
	set.Add(5)

	assert.True(t, set.Has(5))
	assert.True(t, set.Len() == 5)
	set.Delete(5)
	assert.False(t, set.Has(5))
}
