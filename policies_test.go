package sanitize_test

import (
	"bytes"
	"testing"

	"github.com/sonalys/sanitize"
	"github.com/stretchr/testify/require"
)

func Test_SanitizeEmail(t *testing.T) {
	content := []byte(`<html>
<head>
</head>
<body>
</body>
</html>`)

	policy := sanitize.SecureEmailPolicy

	out := bytes.NewBuffer(make([]byte, 0, 1024))

	err := sanitize.HTML(bytes.NewReader(content), out, policy)
	require.NoError(t, err)

	require.Equal(t, ``, out.String())
}
