package sanitize_test

import (
	"bytes"
	"testing"

	"github.com/sonalys/sanitize"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html/atom"
)

func Test_SanitizeEmail(t *testing.T) {
	content := []byte(`<html><head></head><body style="color:red"></body></html>`)

	out := bytes.NewBuffer(make([]byte, 0, 1024))
	err := sanitize.HTML(bytes.NewReader(content), out,
		sanitize.DefaultEmailPolicies(),
		sanitize.AllowAttrs("style"),
	)
	require.NoError(t, err)

	require.Equal(t, string(content), out.String())
}

func Test_BlockAttrs(t *testing.T) {
	content := []byte(`<html><head></head><body Style="color:red"></body></html>`)
	out := bytes.NewBuffer(make([]byte, 0, 1024))
	err := sanitize.HTML(bytes.NewReader(content), out,
		sanitize.BlockAttrs("style"),
	)
	require.NoError(t, err)

	require.Equal(t, "<html><head></head><body></body></html>", out.String())
}

func Test_BlockTags(t *testing.T) {
	content := []byte(`<html><head></head><body><A/></body></html>`)
	out := bytes.NewBuffer(make([]byte, 0, 1024))
	err := sanitize.HTML(bytes.NewReader(content), out,
		sanitize.BlockTags(atom.A),
	)
	require.NoError(t, err)

	require.Equal(t, "<html><head></head><body></body></html>", out.String())
}

func Test_AllowTags(t *testing.T) {
	content := []byte(`<html><head></head><body><A/></body></html>`)
	out := bytes.NewBuffer(make([]byte, 0, 1024))
	err := sanitize.HTML(bytes.NewReader(content), out,
		sanitize.Blacklist(),
		sanitize.AllowTags(atom.Html, atom.Body, atom.A),
	)
	require.NoError(t, err)

	require.Equal(t, "<html><body><a></a></body></html>", out.String())
}
