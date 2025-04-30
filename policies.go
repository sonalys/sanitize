package sanitize

import (
	"golang.org/x/net/html/atom"
)

func TranslateURL(translator func(string) string) Policy {
	return func(token *Token) {
		token.AttributePolicy(func(attr *Attribute) {
			if attr.Key == "href" || attr.Key == "src" {
				attr.Val = translator(attr.Val)
			}
		})
	}
}

func AllowTags(tags ...atom.Atom) Policy {
	set := make(map[atom.Atom]struct{}, len(tags))

	for _, tag := range tags {
		set[tag] = struct{}{}
	}

	return func(token *Token) {
		if _, allowed := set[token.atom]; allowed {
			token.Allow()
		}
	}
}

func AllowAttrs(attrs ...string) Policy {
	set := make(map[string]struct{}, len(attrs))

	for _, attr := range attrs {
		set[attr] = struct{}{}
	}

	return func(token *Token) {
		token.AttributePolicy(func(attr *Attribute) {
			if _, allowed := set[attr.Key]; allowed {
				attr.Allow()
			}
		})
	}
}
