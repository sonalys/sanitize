package sanitize

import (
	"strings"

	"golang.org/x/net/html/atom"
)

// WhitelistEmailTags whitelists the most common html tags used in emails.
// It accepts tags as additional HTML tags to be whitelisted.
func WhitelistEmailTags(tags ...atom.Atom) Policy {
	whitelist := map[atom.Atom]struct{}{
		atom.A:      {},
		atom.B:      {},
		atom.Body:   {},
		atom.Br:     {},
		atom.Div:    {},
		atom.Font:   {},
		atom.H1:     {},
		atom.H2:     {},
		atom.H3:     {},
		atom.H4:     {},
		atom.H5:     {},
		atom.H6:     {},
		atom.Head:   {},
		atom.Html:   {},
		atom.Hr:     {},
		atom.Img:    {},
		atom.Label:  {},
		atom.Li:     {},
		atom.Ol:     {},
		atom.P:      {},
		atom.Span:   {},
		atom.Strong: {},
		atom.Table:  {},
		atom.Tbody:  {},
		atom.Td:     {},
		atom.Th:     {},
		atom.Title:  {},
		atom.Tr:     {},
		atom.U:      {},
		atom.Ul:     {},
	}

	for _, tag := range tags {
		whitelist[tag] = struct{}{}
	}

	return policy(func(tag *Tag) {
		if _, allowed := whitelist[tag.Atom]; allowed {
			tag.Allow()
		}
	})
}

// WhitelistEmailAttrs whitelists the most common html attributes used in emails.
// It blocks the "style" attribute, as it contains css that is not sanitized.
//
// It accepts attrs as additional attributes to be whitelisted.
func WhitelistEmailAttrs(keys ...string) Policy {
	whitelistedKeys := map[string]struct{}{
		"background":          {},
		"background-color":    {},
		"body":                {},
		"border":              {},
		"border-bottom":       {},
		"border-bottom-color": {},
		"border-bottom-style": {},
		"border-bottom-width": {},
		"border-color":        {},
		"border-left":         {},
		"border-left-color":   {},
		"border-left-style":   {},
		"border-left-width":   {},
		"border-right":        {},
		"border-right-color":  {},
		"border-right-style":  {},
		"border-right-width":  {},
		"border-style":        {},
		"border-top":          {},
		"border-top-color":    {},
		"border-width":        {},
		"color":               {},
		"display":             {},
		"font":                {},
		"font-family":         {},
		"font-size":           {},
		"font-style":          {},
		"font-variant":        {},
		"font-weight":         {},
		"height":              {},
		"html":                {},
		"letter-spacing":      {},
		"line-height":         {},
		"list-style-type":     {},
		"padding":             {},
		"padding-bottom":      {},
		"padding-left":        {},
		"padding-right":       {},
		"padding-top":         {},
		"table-layout":        {},
		"text-align":          {},
		"text-decoration":     {},
		"text-indent":         {},
		"text-transform":      {},
		"vertical-align":      {},
		"src":                 {},
		"href":                {},
		"width":               {},
	}

	for _, key := range keys {
		normalizedKey := Normalize(key)
		whitelistedKeys[normalizedKey] = struct{}{}
	}

	return policy(func(tag *Tag) {
		tag.AttrPolicy(func(attr *Attribute) {
			if _, allowed := whitelistedKeys[attr.Key()]; allowed {
				attr.Allow()
			}
		})
	})
}

// BlacklistExternalSources will only allow sources that are comming from CID references.
func BlacklistExternalSources() Policy {
	return policy(func(tag *Tag) {
		tag.AttrPolicy(func(attr *Attribute) {
			if attr.Key() == "src" && !strings.HasPrefix(attr.Value(), "cid:") {
				attr.Block()
			}
		})
	})
}

// EnforceLinkNoRefNoFollow injects noref nofollow to all href attributes.
// This enhances the privacy of the user when opening a given link.
func EnforceLinkNoRefNoFollow() Policy {
	return policy(func(tag *Tag) {
		if !tag.HasAttr("href") {
			return
		}

		tag.UpsertAttr("", "rel", "noreferrer nofollow")
	})
}

// SecureEmailPolicy is a basic set of policies that:
//   - Increases email privacy by blocking tracking attempts and external resources
//   - Prevents basic XSS attempts on HTML attributes, scripts or iframes.
//
// It does not sanitize CSS.
// This policy can be extended with:
//
//	sanitize.SecureEmailPolicy().Extend(newPolicy)
func DefaultEmailPolicies() Policy {
	return Policies{
		Blacklist(),
		WhitelistEmailAttrs(),
		WhitelistEmailTags(),
		BlacklistExternalSources(),
		EnforceLinkNoRefNoFollow(),
	}
}
