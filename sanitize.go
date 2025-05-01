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

// TagPolicy is a tag supervisor. It allows or blocks tags and it's attributes.
// Any modifications will be propagated to the content rendering.
type TagPolicy func(token *Tag)

// TagPolicy is an attribute supervisor. It allows or blocks tag's attributes.
// Any modifications will be propagated to the content rendering.
type AttrPolicy func(attr *Attribute)

// Extend merges any set of policies together.
// It's useful for extending existing predefined policies with custom rules.
func (p TagPolicy) Extend(policies ...HTMLPolicy) TagPolicy {
	return func(tag *Tag) {
		p(tag)
		for _, policy := range policies {
			policy.apply(tag)
		}
	}
}

func (p TagPolicy) apply(tag *Tag) {
	p(tag)
}

// Extend merges any set of policies together.
// It's useful for extending existing predefined policies with custom rules.
func (p AttrPolicy) Extend(policies ...AttrPolicy) AttrPolicy {
	return func(attr *Attribute) {
		p(attr)
		for _, policy := range policies {
			policy(attr)
		}
	}
}

func (p AttrPolicy) apply(tag *Tag) {
	tag.AttrPolicy(p)
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
