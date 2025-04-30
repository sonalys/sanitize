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

func whitelistEmailTags(token *Token) {
	if _, allowed := allowedEmailElements[token.Data]; !allowed {
		token.Block()
	}
}

func whitelistEmailAttrs(token *Token) {
	token.AttributePolicy(func(attr *Attribute) {
		if _, allowed := allowedEmailAttributes[attr.Key]; !allowed {
			attr.Block()
		}
	})
}

func whitelistCIDReferences(token *Token) {
	token.AttributePolicy(func(attr *Attribute) {
		if attr.Key == "href" || attr.Key == "src" {
			if !strings.HasPrefix(attr.Val, "cid:") {
				attr.Block()
			}
		}
	})
}

func SecureEmailPolicy() Policy {
	return func(t *Token) {
		whitelistCIDReferences(t)
		whitelistEmailTags(t)
		whitelistEmailAttrs(t)
	}
}

func TranslateURL(translator func(string) string) Policy {
	return func(token *Token) {
		token.AttributePolicy(func(attr *Attribute) {
			if attr.Key == "href" || attr.Key == "src" {
				attr.Val = translator(attr.Val)
			}
		})
	}
}

func AllowTags(tags ...string) Policy {
	set := make(map[string]struct{}, len(tags))

	for _, tag := range tags {
		set[tag] = struct{}{}
	}

	return func(token *Token) {
		if _, allowed := set[token.DataAtom.String()]; allowed {
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
