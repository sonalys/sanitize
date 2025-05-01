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
		sanitize.SecureEmailPolicy(),
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
	// <a rel="noreferrer nofollow">click here</a>
	// </body></html>
}
