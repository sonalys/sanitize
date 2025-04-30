package sanitize_test

import (
	"bytes"
	"html"
	"strings"
	"testing"

	"github.com/sonalys/sanitize"
	"github.com/stretchr/testify/require"
)

func TestSanitize(t *testing.T) {
	t.Run("case 1", func(t *testing.T) {
		inputHTML := `<html><body onerror="hacked"><a>test</a><img src="cid:attachment1"/><script style="">alert("test")</script></body><img src="javascript:alert('1')"/></html>`
		expectedOutput := `<html><head></head><body><a>test</a><img src="translated://cid:attachment1"/><img/></body></html>`

		reader := strings.NewReader(inputHTML)
		writer := bytes.NewBuffer(make([]byte, 0, len(inputHTML)))

		err := sanitize.HTML(reader, writer,
			sanitize.SecureEmailPolicy(),
			sanitize.TranslateURL(func(s string) string {
				return "translated://" + s
			}),
		)
		require.NoError(t, err)

		result := writer.String()
		require.Equal(t, expectedOutput, result)
	})

	t.Run("escaped", func(t *testing.T) {
		in := html.EscapeString("<img/>")
		reader := strings.NewReader(in)
		writer := bytes.NewBuffer(make([]byte, 0, len(in)))

		err := sanitize.HTML(reader, writer)
		require.NoError(t, err)

		require.Equal(t, "<html><head></head><body>&lt;img/&gt;</body></html>", writer.String())
	})

	t.Run("normalization verification", func(t *testing.T) {
		reader := strings.NewReader("<scrİpt/>")
		writer := bytes.NewBuffer(make([]byte, 0, reader.Len()))

		err := sanitize.HTML(reader, writer)
		require.NoError(t, err)
		require.Equal(t, `<html><head></head><body><scr\u0130pt></scr\u0130pt></body></html>`, writer.String())
	})
}
