package sanitize

import "golang.org/x/net/html"

type (
	Attribute struct {
		Namespace, Key, Val string
		remove              bool
	}
)

func (a *Attribute) Block() {
	a.remove = true
}

func (a *Attribute) Allow() {
	a.remove = false
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
		if from[i].remove {
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
