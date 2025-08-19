package sanitize_test

import (
	"testing"

	"github.com/sonalys/sanitize"
	"github.com/stretchr/testify/require"
)

func Test_WhitelistEmailAttrs(t *testing.T) {
	t.Run("should normalize new keys", func(t *testing.T) {
		policy := sanitize.WhitelistEmailAttrs("Key")

		tag := &sanitize.Tag{}
		tag.UpsertAttr("", "key", "value")

		sanitize.Blacklist().Apply(tag)
		policy.Apply(tag)

		attr := tag.Attrs()[0]
		require.False(t, attr.IsBlocked())
	})
}

func Test_BlacklistExternalSources(t *testing.T) {
	t.Run("should normalize src", func(t *testing.T) {
		tag := &sanitize.Tag{}
		tag.UpsertAttr("", "src", " cid:id")

		sanitize.BlacklistExternalSources().Apply(tag)

		attr := tag.Attrs()[0]
		require.False(t, attr.IsBlocked())
	})
}
