package sanitize

import "golang.org/x/net/html/atom"

type (
	// Tag represents an HTML tag.
	//
	// Any modifications to this structure will impact on the sanitization result.
	//
	// All tags and it's attributes are allowed by default.
	Tag struct {
		Atom    atom.Atom
		attr    []Attribute
		blocked bool
	}

	// TagPolicy is a tag supervisor. It allows or blocks tags and it's attributes.
	// Any modifications will be propagated to the content rendering.
	TagPolicy func(tag *Tag)
)

// Block will remove the tag from the sanitized output.
// All inner content will also be blocked.
//
// Blocked tags can still be allowed by subsequent policies.
//
// Tags are allowed by default.
func (t *Tag) Block() {
	t.blocked = true
}

// Allow will allow the tag in the sanitized output.
// Inner content will still be sanitized.
//
// Allowing a previously blocked tag will return it to the output.
//
// Tags are allowed by default.
func (t *Tag) Allow() {
	t.blocked = false
}

// AttrPolicy will enforce any attribute scoped policy into the parent tag.
// Attributes can be added, removed or updated.
// All attributes are allowed by default.
func (t *Tag) AttrPolicy(handler AttrPolicy) {
	for i := range t.attr {
		attr := &t.attr[i]
		handler(attr)
	}
}

// HasAttr checks if the tag has an attribute with the given key.
// It returns true if the attribute is found, false otherwise.
func (t *Tag) HasAttr(key string) bool {
	for i := range t.attr {
		if t.attr[i].Key == key {
			return true
		}
	}

	return false
}

// UpsertAttr will update a tag's attribute, if it already exists, or create a new one.
func (t *Tag) UpsertAttr(attr Attribute) {
	for i := range t.attr {
		if t.attr[i].Key == attr.Key {
			t.attr[i] = attr
		}
	}

	t.attr = append(t.attr, attr)
}

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
