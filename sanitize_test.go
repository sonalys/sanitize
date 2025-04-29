package sanitize_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sonalys/sanitize"
	"github.com/stretchr/testify/require"
)

func TestSanitize(t *testing.T) {
	inputHTML := `<html><body onerror="hacked"><a>test</a><img src="cid:attachment1"/><script style="">alert("test")</script></body><img src="javascript:alert('1')"/></html>`
	expectedOutput := `<html><body><a>test</a><img src="translated://cid:attachment1"/></body><img/></html>`

	reader := strings.NewReader(inputHTML)
	writer := bytes.NewBuffer(make([]byte, 0, len(inputHTML)))

	err := sanitize.HTML(reader, writer,
		sanitize.SecureEmailPolicy(),
		sanitize.URLPolicy(func(s string) string {
			return "translated://" + s
		}),
	)
	require.NoError(t, err)

	result := writer.String()
	require.Equal(t, expectedOutput, result)
}
