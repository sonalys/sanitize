package sanitize

type (
	// Attribute represents an HTML tag's attribute.
	//
	// Any modifications to this structure will impact on the sanitization result.
	//
	// Namespace and Key are normalized by default to prevent charset attacks.
	// Val is quoted when rendering the sanitized output.
	Attribute struct {
		namespace string
		key       string
		value     string
		blocked   bool

		safeNamespace string
		safeKey       string
		safeValue     string
	}

	// AttributePolicy is an attribute supervisor. It allows or blocks tag's attributes.
	// Any modifications will be propagated to the content rendering.
	AttributePolicy func(a *Attribute)
)

func NewAttribute(namespace, key, value string) *Attribute {
	return &Attribute{
		namespace:     namespace,
		key:           key,
		value:         value,
		safeNamespace: Normalize(namespace),
		safeKey:       Normalize(key),
		safeValue:     Normalize(value),
	}
}

func (p AttributePolicy) Apply(tag *Tag) {
	tag.AttrPolicy(p)
}

func (a *Attribute) IsBlocked() bool {
	return a.blocked
}

func (a *Attribute) Block() {
	a.blocked = true
}

func (a *Attribute) Allow() {
	a.blocked = false
}

func (a *Attribute) UnsafeKey() string {
	return a.key
}

func (a *Attribute) Key() string {
	return a.safeKey
}

func (a *Attribute) UnsafeValue() string {
	return a.value
}

func (a *Attribute) Value() string {
	return a.safeValue
}

func (a *Attribute) UnsafeNamespace() string {
	return a.namespace
}

func (a *Attribute) Namespace() string {
	return a.safeNamespace
}

func (a *Attribute) SetKey(value string) {
	a.key = value
	a.safeKey = value
}

func (a *Attribute) SetValue(value string) {
	a.value = value
	a.safeValue = a.value
}

func (a *Attribute) SetNamespace(value string) {
	a.namespace = value
	a.safeNamespace = value
}
