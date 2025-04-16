package sanitize_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sonalys/sanitize"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
)

type policyFn func(*sanitize.Token)

func (m policyFn) SanitizeToken(token *sanitize.Token) {
	m(token)
}

var policyNoScript policyFn = func(token *sanitize.Token) {
	if !(token.Type == html.StartTagToken || token.Type == html.EndTagToken) {
		return
	}

	if token.Data == "script" {
		token.Block()
		return
	}
}

var policyBlockLinks policyFn = func(token *sanitize.Token) {
	if !token.IsTag() {
		return
	}

	if token.Data == "a" {
		token.Block()
	}
}

var noScriptLinks policyFn = func(token *sanitize.Token) {
	if !token.IsTag() {
		return
	}
	token.AttributePolicy(func(a *sanitize.Attribute) {
		if a.Key == "href" || a.Key == "src" {
			if strings.HasPrefix(a.Val, "javascript:") {
				a.Block()
			}
		}
	})
}

var noScriptAttr policyFn = func(token *sanitize.Token) {
	token.AttributePolicy(func(a *sanitize.Attribute) {
		if strings.HasPrefix(a.Key, "on") {
			a.Block()
		}
	})
}

func TestSanitize(t *testing.T) {
	inputHTML := `<html><body onerror="hacked"><a>test</a><img src="cid:attachment1"/><script style="">alert("test")</script></body><img src="javascript:alert('1')"/></html>`
	expectedOutput := `<html><body><a>test</a><img src="translated://cid:attachment1"/></body><img/></html>`

	reader := strings.NewReader(inputHTML)
	writer := bytes.NewBuffer(make([]byte, 0, len(inputHTML)))

	policy := sanitize.SecureEmailPolicy

	policy = append(policy, sanitize.TranslateURL(func(s string) string {
		return "translated://" + s
	}))

	err := sanitize.HTML(reader, writer,
		policy,
	)
	require.NoError(t, err)

	result := writer.String()
	require.Equal(t, expectedOutput, result)
}
