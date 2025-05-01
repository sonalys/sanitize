package sanitize

import (
	"golang.org/x/net/html/atom"
)

// TranslateURL creates a policy for translating any href or src attributes.
// It receives a [translator] func that receives the current value of the attribute.
// Any returned value will be escaped for the attribute quoted representation.
func TranslateURL(translator func(string) string) TagPolicy {
	return func(token *Tag) {
		token.AttrPolicy(func(attr *Attribute) {
			if attr.Key == "href" || attr.Key == "src" {
				attr.Val = translator(attr.Val)
			}
		})
	}
}

// AllowTags will mark tags as allowed.
// By default all tags are allowed. This is a tool for
// extending any existing tag policy.
func AllowTags(tags ...atom.Atom) TagPolicy {
	set := make(map[atom.Atom]struct{}, len(tags))

	for _, tag := range tags {
		set[tag] = struct{}{}
	}

	return func(token *Tag) {
		if _, allowed := set[token.atom]; allowed {
			token.Allow()
		}
	}
}

// BlockTags will mark tags as blocked.
// By default all tags are allowed. This is a tool for
// extending any existing tag policy.
func BlockTags(tags ...atom.Atom) TagPolicy {
	set := make(map[atom.Atom]struct{}, len(tags))

	for _, tag := range tags {
		set[tag] = struct{}{}
	}

	return func(token *Tag) {
		if _, allowed := set[token.atom]; allowed {
			token.Block()
		}
	}
}

// AllowAttrs will mark an attribute as allowed.
// By default all attributes are allowed. This is a tool for
// extending any existing attribute policy.
func AllowAttrs(attrs ...string) AttrPolicy {
	set := make(map[string]struct{}, len(attrs))

	for _, attr := range attrs {
		set[attr] = struct{}{}
	}

	return func(attr *Attribute) {
		if _, allowed := set[attr.Key]; allowed {
			attr.Allow()
		}
	}
}

// BlockAttrs will mark an attribute as blocked.
// By default all attributes are allowed. This is a tool for
// extending any existing attribute policy.
func BlockAttrs(attrs ...string) AttrPolicy {
	set := make(map[string]struct{}, len(attrs))

	for _, attr := range attrs {
		set[attr] = struct{}{}
	}

	return func(attr *Attribute) {
		if _, allowed := set[attr.Key]; allowed {
			attr.Block()
		}
	}
}
