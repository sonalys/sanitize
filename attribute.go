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

	// attrPolicy is an attribute supervisor. It allows or blocks tag's attributes.
	// Any modifications will be propagated to the content rendering.
	attrPolicy func(attr *Attribute)
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

func (p attrPolicy) Apply(tag *Tag) {
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

func (a *Attribute) Key() string {
	return a.safeKey
}

func (a *Attribute) Value() string {
	return a.safeValue
}

func (a *Attribute) Namespace() string {
	return a.safeNamespace
}

func (a *Attribute) SetKey(value string) {
	normalizedValue := Normalize(value)
	a.key = normalizedValue
	a.safeKey = normalizedValue
}

func (a *Attribute) SetValue(value string) {
	a.value = Normalize(value)
	a.safeValue = a.value
}

func (a *Attribute) SetNamespace(value string) {
	normalizedValue := Normalize(value)
	a.namespace = normalizedValue
	a.safeNamespace = normalizedValue
}
