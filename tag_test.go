package sanitize_test

import (
	"testing"

	"github.com/sonalys/sanitize"
	"github.com/stretchr/testify/require"
)

func Test_Tag_UpsertAttr(t *testing.T) {
	t.Run("should compare normalized values", func(t *testing.T) {
		tag := sanitize.Tag{}

		tag.UpsertAttr("a", "key", "value")

		attrs := tag.Attrs()
		require.Len(t, attrs, 1)

		tag.UpsertAttr("A", "Key", "value")

		attrs = tag.Attrs()
		require.Len(t, attrs, 1)
	})

	t.Run("should consider namespace", func(t *testing.T) {
		tag := sanitize.Tag{}

		tag.UpsertAttr("1", "key", "value")

		attrs := tag.Attrs()
		require.Len(t, attrs, 1)

		tag.UpsertAttr("2", "Key", "value")

		attrs = tag.Attrs()
		require.Len(t, attrs, 2)
	})
}

func Test_Tag_HasAttr(t *testing.T) {
	t.Run("should return false", func(t *testing.T) {
		tag := sanitize.Tag{}

		got := tag.HasAttr("key")
		require.False(t, got)
	})

	t.Run("should return true", func(t *testing.T) {
		tag := sanitize.Tag{}
		tag.UpsertAttr("1", "key", "value")

		got := tag.HasAttr("Key")
		require.True(t, got)
	})
}
