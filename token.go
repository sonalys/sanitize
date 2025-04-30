package sanitize

import "golang.org/x/net/html/atom"

type (
	Token struct {
		atom atom.Atom
		attr     []Attribute
		remove   bool
	}
)

func (t *Token) Block() {
	t.remove = true
}

func (t *Token) Allow() {
	t.remove = false
}

func (t *Token) AttributePolicy(handler func(attr *Attribute)) {
	for i := range t.attr {
		attr := &t.attr[i]
		handler(attr)
	}
}

func (t *Token) HasAttr(key string) bool {
	for i := range t.attr {
		if t.attr[i].Key == key {
			return true
		}
	}

	return false
}

func (t *Token) UpsertAttr(attr Attribute) {
	for i := range t.attr {
		if t.attr[i].Key == attr.Key {
			t.attr[i] = attr
		}
	}

	t.attr = append(t.attr, attr)
}
