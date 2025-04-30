package sanitize

import (
	"io"
	"strconv"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

type (
	Token struct {
		DataAtom atom.Atom
		Data     string
		Attr     []Attribute
		remove   bool
	}

	Attribute struct {
		Namespace, Key, Val string
		remove              bool
	}

	Policy func(token *Token)
)

func (t *Token) Block() {
	t.remove = true
}

func (t *Token) Allow() {
	t.remove = false
}

func (a *Attribute) Block() {
	a.remove = true
}

func (a *Attribute) Allow() {
	a.remove = false
}

func (t *Token) AttributePolicy(handler func(attr *Attribute)) {
	for i := range t.Attr {
		attr := &t.Attr[i]
		handler(attr)
	}
}

func (t *Token) HasAttr(key string) bool {
	for i := range t.Attr {
		if t.Attr[i].Key == key {
			return true
		}
	}

	return false
}

func (t *Token) UpsertAttr(attr Attribute) {
	for i := range t.Attr {
		if t.Attr[i].Key == attr.Key {
			t.Attr[i] = attr
		}
	}

	t.Attr = append(t.Attr, attr)
}

func mapAttrs(from []html.Attribute) []Attribute {
	to := make([]Attribute, len(from))
	for i := range from {
		to[i] = Attribute{
			Namespace: normaliseElementName(from[i].Namespace),
			Key:       normaliseElementName(from[i].Key),
			Val:       from[i].Val,
		}
	}
	return to
}

func returnAttrs(from []Attribute) []html.Attribute {
	to := make([]html.Attribute, 0, len(from))
	for i := range from {
		if from[i].remove {
			continue
		}
		to = append(to, html.Attribute{
			Namespace: from[i].Namespace,
			Key:       from[i].Key,
			Val:       from[i].Val,
		})
	}
	return to
}

func sanitizeNode(node *html.Node, policies ...Policy) {
	if node.Type != html.ElementNode {
		for node := range node.ChildNodes() {
			sanitizeNode(node, policies...)
		}
		return
	}

	token := &Token{
		DataAtom: node.DataAtom,
		Data:     normaliseElementName(node.Data),
		Attr:     mapAttrs(node.Attr),
	}

	for _, policy := range policies {
		policy(token)
	}

	if token.remove {
		node.Type = html.RawNode
		node.Data = ""
		node.DataAtom = atom.A
		node.Attr = nil
		node.FirstChild = nil
		node.LastChild = nil
		node.Namespace = ""
		return
	}

	node.Data = token.Data
	node.Attr = returnAttrs(token.Attr)

	for node := range node.ChildNodes() {
		sanitizeNode(node, policies...)
	}
}

func HTML(r io.Reader, w io.Writer, policies ...Policy) error {
	node, err := html.ParseWithOptions(r)
	if err != nil {
		return err
	}
	sanitizeNode(node, policies...)
	return html.Render(w, node)
}

// normaliseElementName takes a HTML element like <script> which is user input
// and returns a lower case version of it that is immune to UTF-8 to ASCII
// conversion tricks (like the use of upper case cyrillic i scrİpt which a
// strings.ToLower would convert to script). Instead this func will preserve
// all non-ASCII as their escaped equivalent, i.e. \u0130 which reveals the
// characters when lower cased
func normaliseElementName(str string) string {
	// that useful QuoteToASCII put quote marks at the start and end
	// so those are trimmed off
	return strings.TrimSuffix(
		strings.TrimPrefix(
			strings.ToLower(
				strconv.QuoteToASCII(str),
			),
			`"`),
		`"`,
	)
}
