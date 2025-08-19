package sanitize

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
)

const (
	lowerhex = "0123456789abcdef"
)

func ASCII(str string) string {
	buf := make([]byte, 0, len(str))

	for _, r := range str {
		if r < utf8.RuneSelf && strconv.IsPrint(r) {
			buf = append(buf, byte(r))
			continue
		}

		switch r {
		case '\a':
			buf = append(buf, `\a`...)
		case '\b':
			buf = append(buf, `\b`...)
		case '\f':
			buf = append(buf, `\f`...)
		case '\n':
			buf = append(buf, `\n`...)
		case '\r':
			buf = append(buf, `\r`...)
		case '\t':
			buf = append(buf, `\t`...)
		case '\v':
			buf = append(buf, `\v`...)
		default:
			switch {
			case r < ' ' || r == 0x7f:
				buf = append(buf, `\x`...)
				buf = append(buf, lowerhex[byte(r)>>4])
				buf = append(buf, lowerhex[byte(r)&0xF])
			case !utf8.ValidRune(r):
				r = 0xFFFD
				fallthrough
			case r < 0x10000:
				buf = append(buf, `\u`...)
				for s := 12; s >= 0; s -= 4 {
					buf = append(buf, lowerhex[r>>uint(s)&0xF])
				}
			default:
				buf = append(buf, `\U`...)
				for s := 28; s >= 0; s -= 4 {
					buf = append(buf, lowerhex[r>>uint(s)&0xF])
				}
			}
		}
	}

	return string(buf)
}

// Normalize takes a user input and returns a lower case version of it
// that is immune to UTF-8 to ASCII conversion tricks
// (like the use of upper case cyrillic i scrİpt which a
// strings.ToLower would convert to script). Instead this func will preserve
// all non-ASCII as their escaped equivalent, i.e. \u0130 which reveals the
// characters when lower cased
func Normalize(str string) string {
	return strings.TrimSpace(strings.ToLower(ASCII(str)))
}

func fromAttrs(from []html.Attribute) []*Attribute {
	to := make([]*Attribute, len(from))
	for i := range from {
		cur := from[i]
		to[i] = NewAttribute(cur.Namespace, cur.Key, cur.Val)
	}
	return to
}

func toAttrs(from []*Attribute) []html.Attribute {
	to := make([]html.Attribute, 0, len(from))
	for i := range from {
		if from[i].blocked {
			continue
		}
		to = append(to, html.Attribute{
			Namespace: from[i].namespace,
			Key:       from[i].key,
			Val:       from[i].value,
		})
	}
	return to
}
