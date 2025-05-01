# Sanitize

[![Go Reference](https://pkg.go.dev/badge/github.com/sonalys/sanitize.svg)](https://pkg.go.dev/github.com/sonalys/sanitize)
[![Tests](https://github.com/sonalys/sanitize/actions/workflows/test.yml/badge.svg)](https://github.com/sonalys/sanitize/actions/workflows/test.yml)

Sanitize is a sanitization library.  
It's purpose is to allow content policy enforcement.
This library currently supports **HTML**.

## Examples

```go
package sanitize_test

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/sonalys/sanitize"
)

const testEmail = `` +
	`<html><head>
<title>My Email</title>
</head>
<body>
<script>
	alert('not allowed');
</script>
<img onload="alert('not allowed')" src="a" />
<a href="http://visit.me">click here</a></body></html>
`

func ExampleHTML() {
	r := strings.NewReader(testEmail)
	w := bytes.NewBuffer(make([]byte, 0, len(testEmail)))

	err := sanitize.HTML(r, w,
		sanitize.SecureEmailPolicies(),
	)
	if err != nil {
		panic(err)
	}

	fmt.Print(w.String())
	// Output:
	// <html><head>
	// <title>My Email</title>
	// </head>
	// <body>
	//
	// <img/>
	// <a href="http://visit.me" rel="noreferrer nofollow">click here</a>
	// </body></html>
}

```

## License

This repository is licensed under the [MIT License](./LICENSE)