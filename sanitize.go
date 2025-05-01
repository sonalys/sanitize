package sanitize

import (
	"io"
	"slices"

	"golang.org/x/net/html"
)

type (
	// HTMLPolicy is a generalized sanitization rule that can be applied to html content.
	HTMLPolicy interface {
		apply(*Tag)
	}

	// HTMLPolicies is a collection of HTML Policies stored together.
	// It also implements the HTMLPolicy interface.
	HTMLPolicies []HTMLPolicy
)

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
		attr: fromAttrs(node.Attr),
	}

	for _, policy := range policies {
		policy.apply(tag)
	}

	if tag.blocked {
		node.Parent.RemoveChild(node)
		return
	}

	node.Data = Normalize(node.Data)
	node.Attr = toAttrs(tag.attr)

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
