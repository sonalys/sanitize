package sanitize

import (
	"io"

	"golang.org/x/net/html"
)

type Policy func(token *Token)

func (p Policy) Extend(policies ...Policy) Policy {
	return func(token *Token) {
		p(token)
		for _, policy := range policies {
			policy(token)
		}
	}
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
		Data:     normalize(node.Data),
		Attr:     mapAttrs(node.Attr),
	}

	for _, policy := range policies {
		policy(token)
	}

	if token.remove {
		node.Type = html.RawNode
		node.Data = ""
		node.DataAtom = 0
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
