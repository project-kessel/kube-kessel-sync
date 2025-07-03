/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package mapper

import (
	"fmt"
	"strconv"
	"strings"
)

type ResourceId struct {
	Cluster   string
	Namespace string // Optional for cluster-scoped resources
	Name      string
}

func (r *ResourceId) GetNamespace() string {
	return r.Namespace
}

func (r *ResourceId) GetName() string {
	return r.Name
}

// String returns the full resource ID in the format cluster/namespace/name (namespace may be empty for cluster-scoped resources)
func (r *ResourceId) String() string {
	return fmt.Sprintf("%s/%s/%s", EncodeSegment(r.Cluster), EncodeSegment(r.Namespace), EncodeSegment(r.Name))
}

// WithSegment extends the resource ID with an additional segment
func (r *ResourceId) WithSegment(segment interface{}) string {
	return fmt.Sprintf("%s/%v", r.String(), segment)
}

// WithSegments extends the resource ID with multiple additional segments
func (r *ResourceId) WithSegments(segments ...interface{}) string {
	result := r.String()
	for _, segment := range segments {
		result = fmt.Sprintf("%s/%v", result, segment)
	}
	return result
}

// NewResourceId creates a new ResourceId
func NewResourceId(cluster, namespace, name string) *ResourceId {
	return &ResourceId{
		Cluster:   cluster,
		Namespace: namespace,
		Name:      name,
	}
}

// NewClusterResourceId creates a new ResourceId for cluster-scoped resources
func NewClusterResourceId(cluster, name string) *ResourceId {
	return &ResourceId{
		Cluster: cluster,
		Name:    name,
	}
}

// NewResourceIdFromNamespacedName creates a ResourceId from a NamespacedName object
func NewResourceIdFromNamespacedName(cluster string, obj NamespacedName) *ResourceId {
	return &ResourceId{
		Cluster:   cluster,
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
	}
}

// NewResourceIdFromString creates a ResourceId by parsing a string in the format "cluster/namespace/name" (namespace may be empty for cluster-scoped resources)
// Any additional segments after the name are ignored
func NewResourceIdFromString(resourceIdStr string) (*ResourceId, error) {
	parts := strings.Split(resourceIdStr, "/")

	// Need at least cluster, namespace, and name (namespace may be empty)
	if len(parts) < 3 {
		return nil, fmt.Errorf("resource ID %q has %d parts; expected at least 3", resourceIdStr, len(parts))
	}

	cluster, err := DecodeSegment(parts[0])
	if err != nil {
		return nil, err
	}
	namespace, err := DecodeSegment(parts[1])
	if err != nil {
		return nil, err
	}
	name, err := DecodeSegment(parts[2])
	if err != nil {
		return nil, err
	}

	return &ResourceId{
		Cluster:   cluster,
		Namespace: namespace,
		Name:      name,
	}, nil
}

// SpiceString is deprecated; use String().
func (r *ResourceId) SpiceString() string {
	return r.String()
}

// NewResourceIdFromSpiceString is deprecated; use NewResourceIdFromString().
func NewResourceIdFromSpiceString(s string) (*ResourceId, error) {
	return NewResourceIdFromString(s)
}

// -----------------------------------------------------------------------------
// SpiceDB-compatible encoding helpers
// -----------------------------------------------------------------------------

// Allowed characters for SpiceDB object IDs are a-z, A-Z, 0-9, and the symbols
// "/ _ | - = +".
// We additionally reserve '=' and '/' for escape sequences and path separators,
// so those – along with any other byte outside the allowed set – are percent-
// encoded using '=' followed by two upper-case hexadecimal digits (e.g. ':' –>
// "=3A"). This keeps the result human-readable and 100 % reversible while
// guaranteeing compliance with the allowed character set.

// isSafe reports whether b can appear in a SpiceDB segment unescaped.
func isSafe(b byte) bool {
	if ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z') || ('0' <= b && b <= '9') {
		return true
	}
	switch b {
	case '_', '|', '\\', '-', '+':
		return true
	default:
		return false
	}
}

// EncodeSegment escapes a single path segment to satisfy SpiceDB rules.
func EncodeSegment(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isSafe(c) {
			b.WriteByte(c)
		} else {
			// Escape everything else with =XX (uppercase hex)
			fmt.Fprintf(&b, "=%02X", c)
		}
	}
	return b.String()
}

// DecodeSegment performs the inverse of EncodeSegment.
func DecodeSegment(enc string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(enc); i++ {
		if enc[i] == '=' {
			if i+2 >= len(enc) {
				return "", fmt.Errorf("truncated escape sequence in %q", enc)
			}
			val, err := strconv.ParseUint(enc[i+1:i+3], 16, 8)
			if err != nil {
				return "", fmt.Errorf("invalid escape sequence %q: %v", enc[i:i+3], err)
			}
			b.WriteByte(byte(val))
			i += 2 // Skip the two hex digits we've just consumed
		} else {
			b.WriteByte(enc[i])
		}
	}
	return b.String(), nil
}
