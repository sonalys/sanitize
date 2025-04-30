package sanitize_test

import (
	"bytes"
	"testing"

	"github.com/sonalys/sanitize"
	"github.com/stretchr/testify/require"
)

func Test_SanitizeEmail(t *testing.T) {
	content := []byte(`<html><head></head><body style="color:red"></body></html>`)

	out := bytes.NewBuffer(make([]byte, 0, 1024))
	err := sanitize.HTML(bytes.NewReader(content), out,
		sanitize.
			SecureEmailPolicy().
			Extend(
				sanitize.AllowAttrs("style"),
			),
	)
	require.NoError(t, err)

	require.Equal(t, string(content), out.String())
}
