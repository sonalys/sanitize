package sanitize

import "strings"

var allowedEmailElements = map[string]struct{}{
	"a":      {},
	"b":      {},
	"body":   {},
	"br":     {},
	"div":    {},
	"font":   {},
	"h1":     {},
	"h2":     {},
	"h3":     {},
	"h4":     {},
	"h5":     {},
	"h6":     {},
	"head":   {},
	"html":   {},
	"hr":     {},
	"img":    {},
	"label":  {},
	"li":     {},
	"ol":     {},
	"p":      {},
	"span":   {},
	"strong": {},
	"table":  {},
	"tbody":  {},
	"td":     {},
	"th":     {},
	"title":  {},
	"tr":     {},
	"u":      {},
	"ul":     {},
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

func WhitelistEmailTags(token *Token) {
	if _, allowed := allowedEmailElements[token.Data]; !allowed {
		token.Block()
	}
}

func WhitelistEmailAttrs(token *Token) {
	token.AttributePolicy(func(attr *Attribute) {
		if _, allowed := allowedEmailAttributes[attr.Key]; !allowed {
			attr.Block()
		}
	})
}

func WhitelistCIDReferences(token *Token) {
	token.AttributePolicy(func(attr *Attribute) {
		if attr.Key == "href" || attr.Key == "src" {
			if !strings.HasPrefix(attr.Val, "cid:") {
				attr.Block()
			}
		}
	})
}

type EmailPolicy struct {
	AllowedTags        map[string]struct{}
	AllowedAttrs       map[string]struct{}
	AllowExternalMedia bool
}

func SecureEmailPolicy() func(*Token) {
	return func(t *Token) {
		WhitelistCIDReferences(t)
		WhitelistEmailTags(t)
		WhitelistEmailAttrs(t)
	}
}

func URLPolicy(translator func(string) string) func(*Token) {
	return func(token *Token) {
		token.AttributePolicy(func(attr *Attribute) {
			if attr.Key == "href" || attr.Key == "src" {
				attr.Val = translator(attr.Val)
			}
		})
	}
}
