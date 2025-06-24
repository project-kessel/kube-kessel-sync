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
	"strings"
)

type ResourceId struct {
	Cluster   string
	Namespace string
	Name      string
}

func (r *ResourceId) GetNamespace() string {
	return r.Namespace
}

func (r *ResourceId) GetName() string {
	return r.Name
}

// String returns the full resource ID in the format cluster/namespace/name
func (r *ResourceId) String() string {
	return fmt.Sprintf("%s/%s/%s", r.Cluster, r.Namespace, r.Name)
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

// NewResourceIdFromNamespacedName creates a ResourceId from a NamespacedName object
func NewResourceIdFromNamespacedName(cluster string, obj NamespacedName) *ResourceId {
	return &ResourceId{
		Cluster:   cluster,
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
	}
}

// NewResourceIdFromString creates a ResourceId by parsing a string in the format "cluster/namespace/name"
// Any additional segments after the name are ignored
func NewResourceIdFromString(resourceIdStr string) *ResourceId {
	parts := strings.Split(resourceIdStr, "/")

	// Need at least cluster, namespace, and name
	if len(parts) < 3 {
		return nil
	}

	cluster := parts[0]
	namespace := parts[1]
	name := parts[2]

	return &ResourceId{
		Cluster:   cluster,
		Namespace: namespace,
		Name:      name,
	}
}
