package sanitize

import "golang.org/x/net/html/atom"

type (
	// Tag is an html tag representation.
	//
	// Any modifications to this structure will impact on the sanitization result.
	//
	// By default, all attribute keys and namespace are normalized.
	//
	// All tags and attributes are allowed by default.
	Tag struct {
		atom    atom.Atom
		attr    []Attribute
		blocked bool
	}
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
