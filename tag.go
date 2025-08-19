package sanitize

import "golang.org/x/net/html/atom"

// Tag represents an HTML tag.
//
// Any modifications to this structure will impact on the sanitization result.
//
// All tags and it's attributes are allowed by default.
type Tag struct {
	Atom    atom.Atom
	attr    []*Attribute
	data    string
	blocked bool
}

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
func (t *Tag) AttrPolicy(handler attrPolicy) {
	for i := range t.attr {
		handler(t.attr[i])
	}
}

// HasAttr checks if the tag has an attribute with the given key.
// It returns true if the attribute is found, false otherwise.
func (t *Tag) HasAttr(key string) bool {
	normalizedKey := Normalize(key)
	for i := range t.attr {
		if t.attr[i].Key() == normalizedKey {
			return true
		}
	}

	return false
}

// UpsertAttr will update a tag's attribute, if it already exists, or create a new one.
func (t *Tag) UpsertAttr(namespace, key, value string) {
	attr := NewAttribute(namespace, key, value)

	for i := range t.attr {
		if cur := t.attr[i]; cur.Namespace() != attr.Namespace() || cur.Key() != attr.Key() {
			continue
		}
		t.attr[i] = attr
		return
	}

	t.attr = append(t.attr, attr)
}

func (t *Tag) Attrs() []*Attribute {
	return t.attr
}

func (t *Tag) Data() string {
	return t.data
}

func (t *Tag) SetData(value string) {
	t.data = value
}
