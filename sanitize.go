package sanitize

import (
	"bytes"
	"io"
	"strconv"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

type (
	Token struct {
		Type     html.TokenType
		DataAtom atom.Atom
		Data     string
		Attr     []Attribute
		remove   bool
	}

	Attribute struct {
		Namespace, Key, Val string
		remove              bool
	}

	TagSanitizer interface {
		SanitizeToken(token *Token)
	}
)

func (t Token) String() string {
	switch t.Type {
	case html.ErrorToken:
		return ""
	case html.TextToken:
		return t.Data
	case html.StartTagToken:
		return "<" + t.tagString() + ">"
	case html.EndTagToken:
		return "</" + t.tagString() + ">"
	case html.SelfClosingTagToken:
		return "<" + t.tagString() + "/>"
	case html.CommentToken:
		return "<!--" + t.Data + "-->"
	case html.DoctypeToken:
		return "<!DOCTYPE " + t.Data + ">"
	}
	return "Invalid(" + strconv.Itoa(int(t.Type)) + ")"
}

// tagString returns a string representation of a tag Token's Data and Attr.
func (t Token) tagString() string {
	if len(t.Attr) == 0 {
		return t.Data
	}
	buf := bytes.NewBufferString(t.Data)
	for _, a := range t.Attr {
		buf.WriteByte(' ')
		buf.WriteString(a.Key)
		buf.WriteString(`="`)
		buf.WriteString(a.Val)
		buf.WriteByte('"')
	}
	return buf.String()
}

func (t *Token) IsTag() bool {
	return t.Type == html.StartTagToken || t.Type == html.EndTagToken || t.Type == html.SelfClosingTagToken
}

func (t *Token) Block() {
	t.remove = true
}

func (t *Token) Allow() {
	t.remove = false
}

func (a *Attribute) Block() {
	a.remove = true
}

func (a *Attribute) Allow() {
	a.remove = false
}

func (t *Token) AttributePolicy(handler func(attr *Attribute)) {
	allowedAttrs := make([]Attribute, 0, len(t.Attr))

	for i := range t.Attr {
		attr := &t.Attr[i]
		handler(attr)

		if attr.remove {
			continue
		}

		allowedAttrs = append(allowedAttrs, *attr)
	}

	t.Attr = allowedAttrs
}

func mapAttrs(from []html.Attribute) []Attribute {
	to := make([]Attribute, len(from))

	for i := range from {
		to[i] = Attribute{
			Namespace: normaliseElementName(from[i].Namespace),
			Key:       normaliseElementName(from[i].Key),
			Val:       from[i].Val,
		}
	}

	return to
}

func HTML(r io.Reader, w io.Writer, policies ...TagSanitizer) error {
	tokenizer := html.NewTokenizer(r)

	var blockUntil *string
	for {
		tt := tokenizer.Next()

		if tt == html.ErrorToken {
			err := tokenizer.Err()
			if err != io.EOF {
				return err
			}
			return nil
		}

		curToken := tokenizer.Token()

		token := Token{
			Type:     curToken.Type,
			DataAtom: curToken.DataAtom,
			Data:     curToken.Data,
			Attr:     mapAttrs(curToken.Attr),
		}

		if blockUntil != nil {
			if token.Type == html.EndTagToken && token.Data == *blockUntil {
				blockUntil = nil
			}
			continue
		}

		for _, policy := range policies {
			policy.SanitizeToken(&token)
		}

		if token.remove {
			if token.Type == html.StartTagToken {
				blockUntil = &token.Data
			}
			continue
		}

		if _, err := w.Write([]byte(token.String())); err != nil {
			return err
		}
	}
}

// normaliseElementName takes a HTML element like <script> which is user input
// and returns a lower case version of it that is immune to UTF-8 to ASCII
// conversion tricks (like the use of upper case cyrillic i scrİpt which a
// strings.ToLower would convert to script). Instead this func will preserve
// all non-ASCII as their escaped equivalent, i.e. \u0130 which reveals the
// characters when lower cased
func normaliseElementName(str string) string {
	// that useful QuoteToASCII put quote marks at the start and end
	// so those are trimmed off
	return strings.TrimSuffix(
		strings.TrimPrefix(
			strings.ToLower(
				strconv.QuoteToASCII(str),
			),
			`"`),
		`"`,
	)
}
