package sanitize

import "golang.org/x/net/html"

type (
	// Attribute represents an HTML tag's attribute.
	//
	// Any modifications to this structure will impact on the sanitization result.
	//
	// Namespace and Key are normalized by default to prevent charset attacks.
	// Val is quoted when rendering the sanitized output.
	Attribute struct {
		Namespace string
		Key       string
		Val       string
		blocked   bool
	}

	// TagPolicy is an attribute supervisor. It allows or blocks tag's attributes.
	// Any modifications will be propagated to the content rendering.
	AttrPolicy func(attr *Attribute)
)

func (a *Attribute) Block() {
	a.blocked = true
}

func (a *Attribute) Allow() {
	a.blocked = false
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

func mapAttrs(from []html.Attribute) []Attribute {
	to := make([]Attribute, len(from))
	for i := range from {
		to[i] = Attribute{
			Namespace: Normalize(from[i].Namespace),
			Key:       Normalize(from[i].Key),
			Val:       from[i].Val,
		}
	}
	return to
}

func returnAttrs(from []Attribute) []html.Attribute {
	to := make([]html.Attribute, 0, len(from))
	for i := range from {
		if from[i].blocked {
			continue
		}
		to = append(to, html.Attribute{
			Namespace: from[i].Namespace,
			Key:       from[i].Key,
			Val:       from[i].Val,
		})
	}
	return to
}
