package sanitize

import (
	"io"
	"slices"

	"golang.org/x/net/html"
)

func sanitizeNode(node *html.Node, policies ...Policy) {
	if node.Type != html.ElementNode {
		for _, node := range slices.Collect(node.ChildNodes()) {
			sanitizeNode(node, policies...)
		}
		return
	}

	tag := &Tag{
		Atom: node.DataAtom,
		data: node.Data,
		attr: fromAttrs(node.Attr),
	}

	for _, policy := range policies {
		policy.Apply(tag)
	}

	if tag.blocked {
		node.Parent.RemoveChild(node)
		return
	}

	node.Data = tag.data
	node.Attr = toAttrs(tag.attr)

	for _, node := range slices.Collect(node.ChildNodes()) {
		sanitizeNode(node, policies...)
	}
}

// HTML will sanitize the HTML content for the given policies.
// By default, this function will correct the HTML tree, adding html, body and header tags.
// It's extremelly recommended to start a secure policy from a Blacklist, and allow individual policies.
func HTML(r io.Reader, w io.Writer, policies ...Policy) error {
	node, err := html.ParseWithOptions(r)
	if err != nil {
		return err
	}
	sanitizeNode(node, policies...)
	return html.Render(w, node)
}
