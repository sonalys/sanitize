package sanitize

import (
	"golang.org/x/net/html/atom"
)

type (
	// Policy is a tag supervisor. It allows or blocks tags and it's attributes.
	// Any modifications will be propagated to the content rendering.
	Policy interface {
		Apply(tag *Tag)
	}

	// Policies are a set of policies.
	Policies []Policy

	TagPolicy func(*Tag)
)

func (p TagPolicy) Apply(tag *Tag) {
	p(tag)
}

func (p Policies) Apply(tag *Tag) {
	for _, policy := range p {
		policy.Apply(tag)
	}
}

// Blacklist blocks all tags and attributes by default.
// Starting from a Blacklist is considered more safe as it will block new parts by default.
func Blacklist() Policy {
	return TagPolicy(func(tag *Tag) {
		tag.AttrPolicy(func(attr *Attribute) {
			attr.Block()
		})
		tag.Block()
	})
}

// BlockUnknownAtoms will block all atoms that could not be parsed.
// Example: non-standard atoms like <myAtom/>
func BlockUnknownAtoms() Policy {
	return TagPolicy(func(tag *Tag) {
		if tag.atom == atom.Atom(0) {
			tag.Block()
		}
	})
}

// TranslateSources creates a policy for translating any href or src attributes.
// It receives a [translator] func that receives the current value of the attribute.
// Any returned value will be escaped for the attribute quoted representation.
func TranslateSources(translator func(string) string) Policy {
	return TagPolicy(func(tag *Tag) {
		tag.AttrPolicy(func(attr *Attribute) {
			if key := attr.Key(); key == "href" || key == "src" {
				attr.SetValue(translator(attr.value))
			}
		})
	})
}

// AllowTags will mark tags as allowed.
// By default all tags are allowed. This is a tool for
// extending any existing tag policy.
func AllowTags(atoms ...atom.Atom) Policy {
	set := make(map[atom.Atom]struct{}, len(atoms))

	for _, atom := range atoms {
		set[atom] = struct{}{}
	}

	return TagPolicy(func(tag *Tag) {
		if _, allowed := set[tag.atom]; allowed {
			tag.Allow()
		}
	})
}

// BlockTags will mark tags as blocked.
// By default all tags are allowed. This is a tool for
// extending any existing tag policy.
func BlockTags(atoms ...atom.Atom) Policy {
	set := make(map[atom.Atom]struct{}, len(atoms))

	for _, atom := range atoms {
		set[atom] = struct{}{}
	}

	return TagPolicy(func(tag *Tag) {
		if _, blocked := set[tag.atom]; blocked {
			tag.Block()
		}
	})
}

// AllowAttrs will mark an attribute as allowed.
// By default all attributes are allowed. This is a tool for
// extending any existing attribute policy.
func AllowAttrs(keys ...string) Policy {
	set := make(map[string]struct{}, len(keys))

	for _, key := range keys {
		normalizedKey := Normalize(key)
		set[normalizedKey] = struct{}{}
	}

	return AttributePolicy(func(attr *Attribute) {
		if _, allowed := set[attr.Key()]; allowed {
			attr.Allow()
		}
	})
}

// BlockAttrs will mark an attribute as blocked.
// By default all attributes are allowed. This is a tool for
// extending any existing attribute policy.
func BlockAttrs(keys ...string) Policy {
	set := make(map[string]struct{}, len(keys))

	for _, key := range keys {
		normalizedKey := Normalize(key)
		set[normalizedKey] = struct{}{}
	}

	return AttributePolicy(func(attr *Attribute) {
		if _, blocked := set[attr.Key()]; blocked {
			attr.Block()
		}
	})
}
