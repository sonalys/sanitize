package sanitize

import (
	"io"
	"slices"

	"golang.org/x/net/html"
)

// HTMLPolicy is a generalized sanitization rule that can be applied to html content.
type HTMLPolicy interface {
	apply(*Tag)
}

type HTMLPolicies []HTMLPolicy

func (p HTMLPolicies) apply(tag *Tag) {
	for _, policy := range p {
		policy.apply(tag)
	}
}

func sanitizeNode(node *html.Node, policies ...HTMLPolicy) {
	if node.Type != html.ElementNode {
		for _, node := range slices.Collect(node.ChildNodes()) {
			sanitizeNode(node, policies...)
		}
		return
	}

	tag := &Tag{
		atom: node.DataAtom,
		attr: mapAttrs(node.Attr),
	}

	for _, policy := range policies {
		policy.apply(tag)
	}

	if tag.blocked {
		node.Parent.RemoveChild(node)
		return
	}

	node.Attr = returnAttrs(tag.attr)

	for _, node := range slices.Collect(node.ChildNodes()) {
		sanitizeNode(node, policies...)
	}
}

// HTML will sanitize the HTML content for the given policies.
// By default, this function will correct the HTML tree, adding html, body and header tags.
func HTML(r io.Reader, w io.Writer, policies ...HTMLPolicy) error {
	node, err := html.ParseWithOptions(r)
	if err != nil {
		return err
	}
	sanitizeNode(node, policies...)
	return html.Render(w, node)
}
