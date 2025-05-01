package sanitize

import (
	"strings"

	"golang.org/x/net/html/atom"
)

var whitelistedEmailAtoms = map[atom.Atom]struct{}{
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

var allowedEmailAttributes = map[string]struct{}{
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

func PolicyWhitelistEmailTags(token *Tag) {
	if _, allowed := whitelistedEmailAtoms[token.atom]; !allowed {
		token.Block()
	}
}

func PolicyWhitelistEmailAttrs(token *Tag) {
	token.AttrPolicy(func(attr *Attribute) {
		if _, allowed := allowedEmailAttributes[attr.Key]; !allowed {
			attr.Block()
		}
	})
}

func PolicyWhitelistCIDSrc(token *Tag) {
	token.AttrPolicy(func(attr *Attribute) {
		if attr.Key == "href" || attr.Key == "src" {
			if !strings.HasPrefix(attr.Val, "cid:") {
				attr.Block()
			}
		}
	})
}

func PolicyNoRefNoFollow(token *Tag) {
	if !token.HasAttr("href") {
		return
	}

	token.UpsertAttr(Attribute{
		Key: "rel",
		Val: "noreferrer nofollow",
	})
}

func SecureEmailPolicy() TagPolicy {
	return func(token *Tag) {
		PolicyWhitelistCIDSrc(token)
		PolicyWhitelistEmailTags(token)
		PolicyWhitelistEmailAttrs(token)
		PolicyNoRefNoFollow(token)
	}
}
