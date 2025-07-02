package mapper

import (
	"regexp"
	"testing"
)

// Regular expression SpiceDB enforces for object IDs.
var spiceRegexp = regexp.MustCompile(`^[a-zA-Z0-9/_|\-=+]{1,}$`)

type ridCase struct {
	name      string
	cluster   string
	namespace string
	resName   string
}

var ridCases = []ridCase{
	{
		name:      "simple namespaced",
		cluster:   "cluster1",
		namespace: "default",
		resName:   "my-configmap",
	},
	{
		name:      "rbac with colons",
		cluster:   "prod",
		namespace: "kube-system",
		resName:   "system:controller:deployment-controller",
	},
	{
		name:      "cluster scoped with colon",
		cluster:   "prod",
		namespace: "", // cluster-scoped
		resName:   "system:masters",
	},
	{
		name:      "dots and equals",
		cluster:   "dev",
		namespace: "my-ns",
		resName:   "example.com=foo",
	},
}

// TestSpiceStringRegexCompatibility ensures encoded IDs satisfy the SpiceDB
// object-id regular expression.
func TestSpiceStringRegexCompatibility(t *testing.T) {
	for _, tc := range ridCases {
		rid := NewResourceId(tc.cluster, tc.namespace, tc.resName)
		encoded := rid.String()

		if !spiceRegexp.MatchString(encoded) {
			t.Fatalf("case %q: encoded ID %q does not satisfy SpiceDB regexp", tc.name, encoded)
		}
	}
}

// TestSpiceStringRoundTrip ensures we can encode and decode without losing
// information.
func TestSpiceStringRoundTrip(t *testing.T) {
	for _, tc := range ridCases {
		rid := NewResourceId(tc.cluster, tc.namespace, tc.resName)
		encoded := rid.String()

		got, err := NewResourceIdFromString(encoded)
		if err != nil {
			t.Fatalf("case %q: failed to decode spice string: %v", tc.name, err)
		}

		if got.Cluster != tc.cluster || got.Namespace != tc.namespace || got.Name != tc.resName {
			t.Fatalf("case %q: round-trip mismatch. have %+v", tc.name, got)
		}
	}
}
