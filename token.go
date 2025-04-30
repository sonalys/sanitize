package sanitize

import "golang.org/x/net/html/atom"

type (
	Token struct {
		DataAtom atom.Atom
		Data     string
		Attr     []Attribute
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
	for i := range t.Attr {
		attr := &t.Attr[i]
		handler(attr)
	}
}

func (t *Token) HasAttr(key string) bool {
	for i := range t.Attr {
		if t.Attr[i].Key == key {
			return true
		}
	}

	return false
}

func (t *Token) UpsertAttr(attr Attribute) {
	for i := range t.Attr {
		if t.Attr[i].Key == attr.Key {
			t.Attr[i] = attr
		}
	}

	t.Attr = append(t.Attr, attr)
}
