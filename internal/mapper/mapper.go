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
	"context"
	"fmt"
	"strings"

	spicedbv1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	spicedb "github.com/authzed/authzed-go/v1"
	"github.com/project-kessel/kube-kessel-sync/internal/streamutil"
)

var fullyConsistent = &spicedbv1.Consistency{
	Requirement: &spicedbv1.Consistency_FullyConsistent{FullyConsistent: true},
}

type NamespacedName interface {
	GetNamespace() string
	GetName() string
}

// TODO: kessel, but simplifying for POC
type KubeRbacToKessel struct {
	ClusterId    string
	Kube         Getter
	SpiceDb      *spicedb.Client
	SchemaSource SchemaSource
}

type Getter interface {
	Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error
}

// supportedResourceVerbs defines, for each supported Kubernetes resource type,
// the set of verbs that are currently mapped to SpiceDB tuples.
var supportedResourceVerbs = map[string]map[string]struct{}{
	"pods": {
		"get":    {},
		"list":   {},
		"update": {},
	},
	"configmaps": {
		"get":    {},
		"list":   {},
		"update": {},
	},
}

// isSupportedPermission returns true if the supplied apiGroup, resource and verb are currently supported
// by the mapper. We only support core (empty apiGroup) resources "pods" and "configmaps" with the verbs
// "get", "list" and "update" for the POC.
// In the future, we would either use a generic schema not coupled to resource types,
// or template the schema by discovering types in the cluster and updating the schema in realtime.
func isSupportedPermission(apiGroup, resource, verb string) bool {
	// Only the core API group ("" or "core") is supported at the moment.
	if apiGroup != "" && apiGroup != "core" {
		return false
	}

	// Normalize case for comparison.
	resource = strings.ToLower(resource)
	verb = strings.ToLower(verb)

	verbs, ok := supportedResourceVerbs[resource]
	if !ok {
		return false
	}

	_, ok = verbs[verb]
	return ok
}

// isSupportedResourceType returns true if the supplied apiGroup and resource are currently supported
// by the mapper for binding relationships. This is used to filter out unsupported resource types
// when creating denormalized relationships to track resource name bindings.
func isSupportedResourceType(apiGroup, resource string) bool {
	// Only the core API group ("" or "core") is supported at the moment.
	if apiGroup != "" && apiGroup != "core" {
		return false
	}

	// Normalize case for comparison.
	resource = strings.ToLower(resource)

	_, ok := supportedResourceVerbs[resource]
	return ok
}

func (m *KubeRbacToKessel) ObjectAddedOrChanged(ctx context.Context, obj client.Object) error {
	log := logf.FromContext(ctx)

	switch o := obj.(type) {
	case *rbacv1.Role:
		return m.MapRole(ctx, o)
	case *rbacv1.RoleBinding:
		return m.MapRoleBinding(ctx, o)
	case *rbacv1.ClusterRole:
		return m.MapClusterRole(ctx, o)
	case *rbacv1.ClusterRoleBinding:
		return m.MapClusterRoleBinding(ctx, o)
	case *corev1.Namespace:
		return m.MapNamespace(ctx, o)
	default:
		gvk := obj.GetObjectKind().GroupVersionKind()
		log.Info("Unknown object type",
			"group", gvk.Group,
			"version", gvk.Version,
			"kind", gvk.Kind,
			"namespace", obj.GetNamespace(),
			"name", obj.GetName())
	}
	return nil
}

func (m *KubeRbacToKessel) ObjectDeleted(ctx context.Context, obj client.Object) error {
	log := logf.FromContext(ctx)

	switch o := obj.(type) {
	case *rbacv1.Role:
		return m.DeleteRole(ctx, o)
	case *rbacv1.RoleBinding:
		return m.DeleteRoleBinding(ctx, o)
	case *rbacv1.ClusterRole:
		return m.DeleteClusterRole(ctx, o)
	case *rbacv1.ClusterRoleBinding:
		return m.DeleteClusterRoleBinding(ctx, o)
	case *corev1.Namespace:
		log.Info("Namespace deleted", "name", o.Name)
	default:
		gvk := obj.GetObjectKind().GroupVersionKind()
		log.Info("Unknown object type deleted",
			"group", gvk.Group,
			"version", gvk.Version,
			"kind", gvk.Kind,
			"namespace", obj.GetNamespace(),
			"name", obj.GetName())
	}
	return nil
}

func (m *KubeRbacToKessel) SetUpSchema(ctx context.Context) error {
	schema, err := m.SchemaSource.GetSchema(ctx)
	if err != nil {
		return fmt.Errorf("failed to get schema: %w", err)
	}

	request := &spicedbv1.WriteSchemaRequest{Schema: schema}
	_, err = m.SpiceDb.WriteSchema(ctx, request)
	return err
}

func (m *KubeRbacToKessel) MapRole(ctx context.Context, role *rbacv1.Role) error {
	if role == nil {
		return fmt.Errorf("role is nil")
	}

	log := logf.FromContext(ctx)
	log.Info("Mapping Role", "name", role.Name, "namespace", role.Namespace)

	updates := []*spicedbv1.RelationshipUpdate{}

	roleResourceId := NewResourceIdFromNamespacedName(m.ClusterId, role)

	// TODO: Get current relationships for the role, diff, and add/remove
	// This read-modify-write cycle would require fencing (e.g. precondition on lock tuple)
	// but would be atomic & consistent in that case.
	// With Kessel this is the same except just at a Resource level
	// (e.g. query on some kube_role_id or relationship vs resource ID prefix)
	// and some of the lower level stuff is taken care of for you.
	// To deal with resource names, we would need to also get the current state of bindings,
	// which should be queryable by the role they are bound to.
	// This may require tracking the original kube role identity,
	// since the RBAC role is split into multiple.

	// For now, we delete all previous permission relations
	// This is not atomic, because it requires its own request separate from the updates.
	// That means there is a period of (potentially arbitrary) time where
	// the Role has no permissions, resulting in lost access.
	// It also results in lots of extra unwanted snapshots in spicedb.
	// This is all not good for a production solution, but okay for POC.
	res, err := m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
		RelationshipFilter: &spicedbv1.RelationshipFilter{
			ResourceType: "rbac/role",
			// Use a prefix so that it matches ALL role-rules
			// We do not know how many there were before, so we cannot delete by ID.
			OptionalResourceIdPrefix: roleResourceId.String() + "/",
		},
	})
	if err != nil {
		log.Error(err, "Failed to delete previous relationships for Role", "name", role.Name, "namespace", role.Namespace)
		return fmt.Errorf("failed to delete previous relationships for Role %s/%s: %w", role.Namespace, role.Name, err)
	}
	log.Info("Deleted previous relationships for Role", "name", role.Name, "namespace", role.Namespace, "deletedCount", res.RelationshipsDeletedCount)

	// Each Role-Rule gets mapped to a RBAC Role (set of permissions)
	for rI, rule := range role.Rules {
		log.Info("Processing added Role Rule", "apiGroups", rule.APIGroups, "resources", rule.Resources, "verbs", rule.Verbs)

		// ID the RBAC Role after the role's kube cluster, namespace, role name,
		// and the rule's index within the Role.
		roleId := roleResourceId.WithSegment(rI)

		// Create relationships for each resource and verb combination
		// Resource name is ignored here because it affects the location of the binding,
		// not the permissions granted.

		for _, apiGroup := range rule.APIGroups {
			for _, resource := range rule.Resources {
				for _, verb := range rule.Verbs {
					if !isSupportedPermission(apiGroup, resource, verb) {
						// Skip unsupported permissions
						continue
					}

					// Format the verb to be compatible with RBAC Role relation
					verb, tuple := permissionToTuple(apiGroup, resource, verb, roleId)
					update := &spicedbv1.RelationshipUpdate{
						Operation:    spicedbv1.RelationshipUpdate_OPERATION_TOUCH,
						Relationship: tuple,
					}

					updates = append(updates, update)
					log.Info("Adding tuple", "resource", roleId, "verb", verb, "role", role.Name)
				}
			}
		}
	}

	// We also need to redo any existing role bindings,
	// because ksl bindings are a function of the kube binding *and* and the kube role.
	// As above, we'd normally want to do a diff of what resources were bound currently,
	// with what resources should be bound given resourcenames in the role-rules,
	// and then add/remove the relationships as needed.
	// For POC, we'll continue to just remove and recreate like we do for Roles.
	bindingIds, err := m.getKesselBindingIds(ctx, roleResourceId)
	if err != nil {
		return fmt.Errorf("failed to get binding IDs for Role %s/%s: %w", role.Namespace, role.Name, err)
	}

	if len(bindingIds) > 0 {
		// Get the subjects for the first binding. They will all be the same,
		// and we need this to be able to reconstitute new bindings later.
		firstBindingId := bindingIds[0]
		subjects, err := m.getRbacBindingSubjects(ctx, firstBindingId)
		if err != nil {
			log.Error(err, "Failed to get subjects for binding", "bindingId", firstBindingId)
			return fmt.Errorf("failed to get subjects for binding %s: %w", firstBindingId, err)
		}
		log.Info("Found subjects for binding", "bindingId", firstBindingId, "subjectCount", len(subjects))

		distinctKubeBindingIds := make(map[string]*ResourceId)
		for _, bindingId := range bindingIds {
			// Determine the underlying Kubernetes binding for each RBAC binding.
			// This is a set because we may have multiple RBAC bindings for the same Kubernetes binding.
			resourceId, err := NewResourceIdFromString(bindingId)
			if err == nil {
				distinctKubeBindingIds[resourceId.String()] = resourceId
			}

			_, err = m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
				RelationshipFilter: &spicedbv1.RelationshipFilter{
					OptionalSubjectFilter: &spicedbv1.SubjectFilter{
						SubjectType:       "rbac/role_binding",
						OptionalSubjectId: bindingId,
					},
				},
			})
			if err != nil {
				return fmt.Errorf("failed to delete relationships for Role %s/%s: %w", role.Namespace, role.Name, err)
			}

			// Now for each kubernetes binding implied by the RBAC bindings, recreate the RBAC bindings.
			for _, kubeBindingId := range distinctKubeBindingIds {
				// Delete all the binding relationships where the binding is the resource
				// (i.e. to role & subjects)
				// Done in this loop since we can use prefix matching to delete all.
				// With Kessel, I think we could design schema & API to simplify this stuff.
				_, err = m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
					RelationshipFilter: &spicedbv1.RelationshipFilter{
						ResourceType:             "rbac/role_binding",
						OptionalResourceIdPrefix: kubeBindingId.String(),
					},
				})
				if err != nil {
					return fmt.Errorf("failed to delete relationships for Role Binding %s: %w", kubeBindingId.String(), err)
				}

				bindingUpdates, err := m.getNamespaceBindingUpdates(ctx, roleResourceId, role.Rules, kubeBindingId, subjects)
				if err != nil {
					return fmt.Errorf("failed to get namespace binding updates for Role Binding %s: %w", kubeBindingId.String(), err)
				}
				updates = append(updates, bindingUpdates...)
			}
		}
	}

	if len(updates) > 0 {
		_, err := m.SpiceDb.WriteRelationships(ctx, &spicedbv1.WriteRelationshipsRequest{
			Updates: updates,
		})
		if err != nil {
			log.Error(err, "Failed to write relationships to SpiceDB", "updates", updates)
			return err
		}
	}
	return nil
}

func (m *KubeRbacToKessel) getKesselBindingIds(ctx context.Context, kubeRoleId *ResourceId) ([]string, error) {
	bindingIds := []string{}
	err := streamutil.ForEach(
		func() (spicedbv1.PermissionsService_LookupSubjectsClient, error) {
			return m.SpiceDb.LookupSubjects(ctx, &spicedbv1.LookupSubjectsRequest{
				Consistency: fullyConsistent,
				Resource: &spicedbv1.ObjectReference{
					ObjectType: "kubernetes/role",
					ObjectId:   kubeRoleId.String(),
				},
				Permission:        "rbac_binding",
				SubjectObjectType: "rbac/role_binding",
			})
		},
		func(response *spicedbv1.LookupSubjectsResponse) error {
			bindingIds = append(bindingIds, response.Subject.SubjectObjectId)
			return nil
		},
	)
	return bindingIds, err
}

func (m *KubeRbacToKessel) getRbacBindingSubjects(ctx context.Context, bindingId string) ([]string, error) {
	subjects := []string{}
	err := streamutil.ForEach(
		func() (spicedbv1.PermissionsService_ReadRelationshipsClient, error) {
			return m.SpiceDb.ReadRelationships(ctx, &spicedbv1.ReadRelationshipsRequest{
				Consistency: fullyConsistent,
				RelationshipFilter: &spicedbv1.RelationshipFilter{
					ResourceType:       "rbac/role_binding",
					OptionalResourceId: bindingId,
					OptionalRelation:   "t_subject",
				},
			})
		},
		func(response *spicedbv1.ReadRelationshipsResponse) error {
			// TODO: for now we know these are only principals, in future could be groups
			// may also need special handling for service accounts vs users.
			subjects = append(subjects, response.Relationship.Subject.Object.ObjectId)
			return nil
		},
	)
	return subjects, err
}

func (m *KubeRbacToKessel) MapRoleBinding(ctx context.Context, binding *rbacv1.RoleBinding) error {
	if binding == nil {
		return fmt.Errorf("role binding is nil")
	}

	log := logf.FromContext(ctx)
	log.Info("Mapping RoleBinding", "name", binding.Name, "namespace", binding.Namespace)

	var (
		roleResourceId *ResourceId
		rules          []rbacv1.PolicyRule
	)

	if strings.EqualFold(binding.RoleRef.Kind, "ClusterRole") {
		// Reference to a ClusterRole
		clusterRole := &rbacv1.ClusterRole{}
		if err := m.Kube.Get(ctx, client.ObjectKey{Name: binding.RoleRef.Name}, clusterRole); err != nil {
			log.Error(err, "Failed to get ClusterRole for RoleBinding", "name", binding.Name, "namespace", binding.Namespace)
			return fmt.Errorf("failed to get ClusterRole %s for RoleBinding %s/%s: %w", binding.RoleRef.Name, binding.Namespace, binding.Name, err)
		}

		rules = clusterRole.Rules
		roleResourceId = NewClusterResourceId(m.ClusterId, clusterRole.Name)
	} else {
		// Assume Role (namespaced)
		role := &rbacv1.Role{}
		if err := m.Kube.Get(ctx, client.ObjectKey{Name: binding.RoleRef.Name, Namespace: binding.Namespace}, role); err != nil {
			log.Error(err, "Failed to get Role for RoleBinding", "name", binding.Name, "namespace", binding.Namespace)
			return fmt.Errorf("failed to get Role %s/%s for RoleBinding %s/%s: %w", binding.Namespace, binding.RoleRef.Name, binding.Namespace, binding.Name, err)
		}

		rules = role.Rules
		roleResourceId = NewResourceIdFromNamespacedName(m.ClusterId, role)
	}

	// Like with roles, delete all possible previous binding relationships
	log.Info("Deleting previous relationships for RoleBinding", "name", binding.Name, "namespace", binding.Namespace)
	m.deleteBindingRelationships(ctx, binding)

	principalIds := m.convertSubjectsToPrincipalIds(binding.Subjects)
	updates, err := m.getNamespaceBindingUpdates(ctx, roleResourceId, rules, NewResourceIdFromNamespacedName(m.ClusterId, binding), principalIds)
	if err != nil {
		log.Error(err, "Failed to map RoleBinding", "name", binding.Name, "namespace", binding.Namespace)
		return fmt.Errorf("failed to map RoleBinding %s/%s: %w", binding.Namespace, binding.Name, err)
	}

	// Updates collected, write them to SpiceDB
	if len(updates) > 0 {
		_, err := m.SpiceDb.WriteRelationships(ctx, &spicedbv1.WriteRelationshipsRequest{
			Updates: updates,
		})
		if err != nil {
			log.Error(err, "Failed to write relationships to SpiceDB for RoleBinding", "name", binding.Name, "namespace", binding.Namespace, "updates", updates)
			return fmt.Errorf("failed to write relationships to SpiceDB for RoleBinding %s/%s: %w", binding.Namespace, binding.Name, err)
		}
		log.Info("Successfully wrote RoleBinding relationships to SpiceDB", "name", binding.Name, "namespace", binding.Namespace)
	} else {
		log.Info("No updates to write for RoleBinding", "name", binding.Name, "namespace", binding.Namespace)
	}
	// If we reach here, the mapping was successful
	log.Info("Successfully mapped RoleBinding", "name", binding.Name, "namespace", binding.Namespace)

	return nil
}

// convertSubjectsToPrincipalIds converts a slice of RBAC subjects to principal resource IDs
func (m *KubeRbacToKessel) convertSubjectsToPrincipalIds(subjects []rbacv1.Subject) []string {
	principalIds := make([]string, 0, len(subjects))
	for _, subject := range subjects {
		if strings.EqualFold(subject.Kind, "Group") {
			logf.Log.Info("Skipping group subject", "name", subject.Name)
			continue
		}
		// TODO: rethink principal identifiers for kubernetes principals
		principalId := fmt.Sprintf("kubernetes/%s", EncodeSegment(subject.Name))
		principalIds = append(principalIds, principalId)
	}
	return principalIds
}

// getNamespaceBindingUpdates generates binding updates for a namespaced RoleBinding to either a Role or ClusterRole.
// It is parameterised by the set of policy rules and the role's ResourceID, allowing callers to remain agnostic
// to whether the underlying RBAC object is a Role or ClusterRole.
func (m *KubeRbacToKessel) getNamespaceBindingUpdates(ctx context.Context, roleResourceId *ResourceId, rules []rbacv1.PolicyRule, kubeBindingId *ResourceId, principals []string) ([]*spicedbv1.RelationshipUpdate, error) {
	log := logf.FromContext(ctx)

	updates := []*spicedbv1.RelationshipUpdate{}

	// Track from the kube role to the binding so we can traverse later.
	// This is so we can traverse from the kube role to rbac bindings later.
	updates = append(updates, relationshipTouch(&spicedbv1.ObjectReference{
		ObjectType: "kubernetes/role",
		ObjectId:   roleResourceId.String(),
	}, "t_role_binding", &spicedbv1.SubjectReference{
		Object: &spicedbv1.ObjectReference{
			ObjectType: "kubernetes/role_binding",
			ObjectId:   kubeBindingId.String(),
		},
	}))

	// For each rule, create a binding to the RBAC role-rule and attach subjects.
	for rI, rule := range rules {
		log.Info("Processing Role Rule", "apiGroups", rule.APIGroups, "resources", rule.Resources, "verbs", rule.Verbs)

		// Identify the RBAC binding ID (one per role rule).
		rbacBindingId := kubeBindingId.WithSegment(rI)

		// Track that this binding relates to the kube RoleBinding for later look-ups.
		updates = append(updates, relationshipTouch(&spicedbv1.ObjectReference{
			ObjectType: "kubernetes/role_binding",
			ObjectId:   kubeBindingId.String(),
		}, "t_rbac_binding", &spicedbv1.SubjectReference{
			Object: &spicedbv1.ObjectReference{
				ObjectType: "rbac/role_binding",
				ObjectId:   rbacBindingId,
			},
		}))

		// Decide where to attach the binding based on the rule's ResourceNames.
		if len(rule.ResourceNames) > 0 {
			// Resource-level binding.
			for _, apiGroup := range rule.APIGroups {
				for _, resource := range rule.Resources {
					if !isSupportedResourceType(apiGroup, resource) {
						// Skip unsupported resource types to avoid creating relationships
						// for resources not defined in the schema
						continue
					}
					for _, resourceName := range rule.ResourceNames {
						resourceType := fmt.Sprintf("kubernetes/%s", pluralToSingular(resource))
						resourceId := NewResourceId(m.ClusterId, kubeBindingId.Namespace, resourceName)

						updates = append(updates, relationshipTouch(&spicedbv1.ObjectReference{
							ObjectType: resourceType,
							ObjectId:   resourceId.String(),
						}, "t_role_binding", &spicedbv1.SubjectReference{
							Object: &spicedbv1.ObjectReference{
								ObjectType: "rbac/role_binding",
								ObjectId:   rbacBindingId,
							},
						}))
					}
				}
			}

		} else {
			// Namespace-level binding.
			resourceType := "kubernetes/knamespace"
			resourceId := fmt.Sprintf("%s/%s", m.ClusterId, kubeBindingId.Namespace)

			updates = append(updates, relationshipTouch(&spicedbv1.ObjectReference{
				ObjectType: resourceType,
				ObjectId:   resourceId,
			}, "t_role_binding", &spicedbv1.SubjectReference{
				Object: &spicedbv1.ObjectReference{
					ObjectType: "rbac/role_binding",
					ObjectId:   rbacBindingId,
				},
			}))
		}

		// Binding -> role-rule.
		updates = append(updates, relationshipTouch(&spicedbv1.ObjectReference{
			ObjectType: "rbac/role_binding",
			ObjectId:   rbacBindingId,
		}, "t_role", &spicedbv1.SubjectReference{
			Object: &spicedbv1.ObjectReference{
				ObjectType: "rbac/role",
				ObjectId:   roleResourceId.WithSegment(rI),
			},
		}))

		// Binding -> subjects.
		for _, principalId := range principals {
			updates = append(updates, relationshipTouch(&spicedbv1.ObjectReference{
				ObjectType: "rbac/role_binding",
				ObjectId:   rbacBindingId,
			}, "t_subject", &spicedbv1.SubjectReference{
				Object: &spicedbv1.ObjectReference{
					ObjectType: "rbac/principal",
					ObjectId:   principalId,
				},
			}))
		}
	}

	return updates, nil
}

func (m *KubeRbacToKessel) MapClusterRole(ctx context.Context, clusterRole *rbacv1.ClusterRole) error {
	if clusterRole == nil {
		return fmt.Errorf("cluster role is nil")
	}

	log := logf.FromContext(ctx)
	log.Info("Mapping ClusterRole", "name", clusterRole.Name)

	updates := []*spicedbv1.RelationshipUpdate{}

	roleResourceId := NewClusterResourceId(m.ClusterId, clusterRole.Name)

	// Delete all previous permission relations for this cluster role
	// This is not atomic, but okay for POC
	res, err := m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
		RelationshipFilter: &spicedbv1.RelationshipFilter{
			ResourceType: "rbac/role",
			// Use a prefix so that it matches ALL role-rules
			// We do not know how many there were before, so we cannot delete by ID.
			OptionalResourceIdPrefix: roleResourceId.String() + "/",
		},
	})
	if err != nil {
		log.Error(err, "Failed to delete previous relationships for ClusterRole", "name", clusterRole.Name)
		return fmt.Errorf("failed to delete previous relationships for ClusterRole %s: %w", clusterRole.Name, err)
	}
	log.Info("Deleted previous relationships for ClusterRole", "name", clusterRole.Name, "deletedCount", res.RelationshipsDeletedCount)

	// Each ClusterRole-Rule gets mapped to a RBAC Role (set of permissions)
	for rI, rule := range clusterRole.Rules {
		log.Info("Processing added ClusterRole Rule", "apiGroups", rule.APIGroups, "resources", rule.Resources, "verbs", rule.Verbs)

		// ID the RBAC Role after the role's kube cluster, role name,
		// and the rule's index within the ClusterRole.
		roleId := roleResourceId.WithSegment(rI)

		// Create relationships for each resource and verb combination
		// Resource name is ignored here because it affects the location of the binding,
		// not the permissions granted.

		for _, apiGroup := range rule.APIGroups {
			for _, resource := range rule.Resources {
				for _, verb := range rule.Verbs {
					if !isSupportedPermission(apiGroup, resource, verb) {
						// Skip unsupported permissions
						continue
					}

					// Format the verb to be compatible with RBAC Role relation
					verb, tuple := permissionToTuple(apiGroup, resource, verb, roleId)
					update := &spicedbv1.RelationshipUpdate{
						Operation:    spicedbv1.RelationshipUpdate_OPERATION_TOUCH,
						Relationship: tuple,
					}

					updates = append(updates, update)
					log.Info("Adding tuple", "resource", roleId, "verb", verb, "role", clusterRole.Name)
				}
			}
		}
	}

	// We also need to redo any existing cluster role bindings,
	// because ksl bindings are a function of the kube binding *and* and the kube role.
	// As above, we'd normally want to do a diff of what resources were bound currently,
	// with what resources should be bound given resourcenames in the role-rules,
	// and then add/remove the relationships as needed.
	// For POC, we'll continue to just remove and recreate like we do for Roles.
	bindingIds, err := m.getKesselBindingIds(ctx, roleResourceId)
	if err != nil {
		return fmt.Errorf("failed to get binding IDs for ClusterRole %s: %w", clusterRole.Name, err)
	}

	if len(bindingIds) > 0 {
		// Get the subjects for the first binding. They will all be the same,
		// and we need this to be able to reconstitute new bindings later.
		firstBindingId := bindingIds[0]
		subjects, err := m.getRbacBindingSubjects(ctx, firstBindingId)
		if err != nil {
			log.Error(err, "Failed to get subjects for binding", "bindingId", firstBindingId)
			return fmt.Errorf("failed to get subjects for binding %s: %w", firstBindingId, err)
		}
		log.Info("Found subjects for binding", "bindingId", firstBindingId, "subjectCount", len(subjects))

		uniqueResourceIds := make(map[string]*ResourceId)
		for _, bindingId := range bindingIds {
			// Determine the underlying Kubernetes binding for each RBAC binding.
			// This is a set because we may have multiple RBAC bindings for the same Kubernetes binding.
			resourceId, err := NewResourceIdFromString(bindingId)
			if err == nil {
				uniqueResourceIds[resourceId.String()] = resourceId
			}

			_, err = m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
				RelationshipFilter: &spicedbv1.RelationshipFilter{
					OptionalSubjectFilter: &spicedbv1.SubjectFilter{
						SubjectType:       "rbac/role_binding",
						OptionalSubjectId: bindingId,
					},
				},
			})
			if err != nil {
				return fmt.Errorf("failed to delete relationships for ClusterRole %s: %w", clusterRole.Name, err)
			}

			// Now for each kubernetes binding implied by the RBAC bindings, recreate the RBAC bindings.
			for _, resourceId := range uniqueResourceIds {
				// Delete all the binding relationships where the binding is the resource
				// (i.e. to role & subjects)
				// Done in this loop since we can use prefix matching to delete all.
				// With Kessel, I think we could design schema & API to simplify this stuff.
				_, err = m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
					RelationshipFilter: &spicedbv1.RelationshipFilter{
						ResourceType:             "rbac/role_binding",
						OptionalResourceIdPrefix: resourceId.String() + "/",
					},
				})
				if err != nil {
					return fmt.Errorf("failed to delete relationships for Cluster Role Binding %s: %w", resourceId.String(), err)
				}

				bindingUpdates, err := m.getClusterBindingUpdates(ctx, clusterRole, resourceId, subjects)
				if err != nil {
					return fmt.Errorf("failed to get cluster binding updates for Cluster Role Binding %s: %w", resourceId.String(), err)
				}
				updates = append(updates, bindingUpdates...)
			}
		}
	}

	if len(updates) > 0 {
		_, err := m.SpiceDb.WriteRelationships(ctx, &spicedbv1.WriteRelationshipsRequest{
			Updates: updates,
		})
		if err != nil {
			log.Error(err, "Failed to write relationships to SpiceDB", "updates", updates)
			return err
		}
	}
	return nil
}

func (m *KubeRbacToKessel) MapClusterRoleBinding(ctx context.Context, clusterRoleBinding *rbacv1.ClusterRoleBinding) error {
	if clusterRoleBinding == nil {
		return fmt.Errorf("cluster role binding is nil")
	}

	log := logf.FromContext(ctx)
	log.Info("Mapping ClusterRoleBinding", "name", clusterRoleBinding.Name)

	// Lookup the referenced cluster role
	clusterRole := &rbacv1.ClusterRole{}
	if err := m.Kube.Get(ctx, client.ObjectKey{
		Name: clusterRoleBinding.RoleRef.Name,
	}, clusterRole); err != nil {
		log.Error(err, "Failed to get ClusterRole for ClusterRoleBinding", "name", clusterRoleBinding.Name)
		return fmt.Errorf("failed to get ClusterRole %s for ClusterRoleBinding %s: %w", clusterRoleBinding.RoleRef.Name, clusterRoleBinding.Name, err)
	}

	// Like with roles, delete all possible previous binding relationships
	// TODO: Could diff and compare to be more efficient and make atomic
	log.Info("Deleting previous relationships for ClusterRoleBinding", "name", clusterRoleBinding.Name)
	m.deleteClusterBindingRelationships(ctx, clusterRoleBinding)

	kubeBindingId := NewClusterResourceId(m.ClusterId, clusterRoleBinding.Name)

	principalIds := m.convertSubjectsToPrincipalIds(clusterRoleBinding.Subjects)
	updates, err := m.getClusterBindingUpdates(ctx, clusterRole, kubeBindingId, principalIds)
	if err != nil {
		log.Error(err, "Failed to map ClusterRoleBinding", "name", clusterRoleBinding.Name)
		return fmt.Errorf("failed to map ClusterRoleBinding %s: %w", clusterRoleBinding.Name, err)
	}

	// Updates collected, write them to SpiceDB
	if len(updates) > 0 {
		log.Info("Writing ClusterRoleBinding relationships to SpiceDB", "updatesCount", len(updates))
		_, err := m.SpiceDb.WriteRelationships(ctx, &spicedbv1.WriteRelationshipsRequest{
			Updates: updates,
		})
		if err != nil {
			log.Error(err, "Failed to write relationships to SpiceDB for ClusterRoleBinding", "name", clusterRoleBinding.Name, "updates", updates)
			return fmt.Errorf("failed to write relationships to SpiceDB for ClusterRoleBinding %s: %w", clusterRoleBinding.Name, err)
		}
		log.Info("Successfully wrote ClusterRoleBinding relationships to SpiceDB", "name", clusterRoleBinding.Name)
	} else {
		log.Info("No updates to write for ClusterRoleBinding", "name", clusterRoleBinding.Name)
	}
	// If we reach here, the mapping was successful
	log.Info("Successfully mapped ClusterRoleBinding", "name", clusterRoleBinding.Name)

	return nil
}

func (m *KubeRbacToKessel) deleteBindingRelationships(ctx context.Context, binding *rbacv1.RoleBinding) error {
	log := logf.FromContext(ctx)

	// We need to find all of the bindings,
	// which we cannot do with a single delete.
	// This kind of read-modify-write cycle is not only not atomic
	// but would require fencing for complete concurrency control.

	// We track how role bindings have exploded in the graph.
	// With Kessel, this could just be an attribute on a kube role binding object.
	// gather all subject IDs from the relationships stream
	var currentRbacBindings []string

	err := streamutil.ForEach(
		func() (spicedbv1.PermissionsService_ReadRelationshipsClient, error) {
			return m.SpiceDb.ReadRelationships(ctx, &spicedbv1.ReadRelationshipsRequest{
				Consistency: fullyConsistent,
				RelationshipFilter: &spicedbv1.RelationshipFilter{
					ResourceType:       "kubernetes/role_binding",
					OptionalResourceId: NewResourceId(m.ClusterId, binding.Namespace, binding.Name).String(),
					OptionalRelation:   "t_rbac_binding",
				},
			})
		},
		func(response *spicedbv1.ReadRelationshipsResponse) error {
			currentRbacBindings = append(currentRbacBindings, response.Relationship.Subject.Object.ObjectId)
			return nil
		},
	)
	if err != nil {
		log.Error(err, "Failed to read relationships for RoleBinding", "name", binding.Name, "namespace", binding.Namespace)
		return fmt.Errorf("failed to read relationships for RoleBinding %s/%s: %w", binding.Namespace, binding.Name, err)
	}

	// Now remove all of these bindings and any role_binding relationships to these.

	for _, bindingId := range currentRbacBindings {
		log.Info("Deleting binding relationships", "bindingId", bindingId)
		_, err := m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
			RelationshipFilter: &spicedbv1.RelationshipFilter{
				ResourceType:       "rbac/role_binding",
				OptionalResourceId: bindingId,
			},
		})
		if err != nil {
			log.Error(err, "Failed to delete relationships for RoleBinding", "name", binding.Name, "namespace", binding.Namespace)
			return fmt.Errorf("failed to delete relationships for RoleBinding %s/%s: %w", binding.Namespace, binding.Name, err)
		}
		// Also delete where the binding is the subject
		_, err = m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
			RelationshipFilter: &spicedbv1.RelationshipFilter{
				OptionalSubjectFilter: &spicedbv1.SubjectFilter{
					SubjectType:       "rbac/role_binding",
					OptionalSubjectId: bindingId,
				},
			},
		})

		if err != nil {
			log.Error(err, "Failed to delete subject relationships for RoleBinding", "name", binding.Name, "namespace", binding.Namespace)
			return fmt.Errorf("failed to delete subject relationships for RoleBinding %s/%s: %w", binding.Namespace, binding.Name, err)
		}

		log.Info("Deleted binding relationships", "bindingId", bindingId)
	}

	return nil
}

func permissionToTuple(apiGroup string, resource string, verb string, roleId string) (string, *spicedbv1.Relationship) {
	// Kessel relationships do not require t_ prefix
	// but because we're going straight to SpiceDB we add it.
	relation := fmt.Sprintf("t_kubernetes_%s%s_%s", apiGroup, resource, verb)

	// Create relationship tuple
	tuple := &spicedbv1.Relationship{
		Resource: &spicedbv1.ObjectReference{
			ObjectType: "rbac/role",
			ObjectId:   roleId,
		},
		Relation: relation,

		Subject: &spicedbv1.SubjectReference{
			Object: &spicedbv1.ObjectReference{
				ObjectType: "rbac/principal",
				ObjectId:   "*",
			},
		},
	}

	return relation, tuple
}

// pluralToSingular converts common Kubernetes plural resource names to singular
// TODO: also just consider a 1-1 mapping of resource types to kessel resource types
// or an aliasing feature, w/e
func pluralToSingular(resource string) string {
	switch resource {
	case "configmaps":
		return "configmap"
	case "pods":
		return "pod"
	case "services":
		return "service"
	case "deployments":
		return "deployment"
	case "secrets":
		return "secret"
	case "nodes":
		return "node"
	case "namespaces":
		return "namespace"
	case "persistentvolumes":
		return "persistentvolume"
	case "persistentvolumeclaims":
		return "persistentvolumeclaim"
	default:
		// Simple heuristic: remove 's' if it ends with 's'
		if len(resource) > 1 && resource[len(resource)-1] == 's' {
			return resource[:len(resource)-1]
		}
		return resource
	}
}

// Create a RelationshipUpdate with TOUCH operation
func relationshipTouch(resource *spicedbv1.ObjectReference, relation string, subject *spicedbv1.SubjectReference) *spicedbv1.RelationshipUpdate {
	return &spicedbv1.RelationshipUpdate{
		Operation: spicedbv1.RelationshipUpdate_OPERATION_TOUCH,
		Relationship: &spicedbv1.Relationship{
			Resource: resource,
			Relation: relation,
			Subject:  subject,
		},
	}
}

// Given a ClusterRole and a corresponding Kube ClusterRoleBinding, generate binding updates.
func (m *KubeRbacToKessel) getClusterBindingUpdates(ctx context.Context, clusterRole *rbacv1.ClusterRole, kubeBindingId *ResourceId, principals []string) ([]*spicedbv1.RelationshipUpdate, error) {
	log := logf.FromContext(ctx)

	roleResourceId := NewClusterResourceId(m.ClusterId, clusterRole.Name)
	updates := []*spicedbv1.RelationshipUpdate{}

	// Track from the kube role to the kube binding ONCE to avoid duplicate relationships added per rule.
	// This is so we can traverse from the kube role to rbac bindings
	updates = append(updates, relationshipTouch(&spicedbv1.ObjectReference{
		ObjectType: "kubernetes/role",
		ObjectId:   roleResourceId.String(),
	}, "t_role_binding", &spicedbv1.SubjectReference{
		Object: &spicedbv1.ObjectReference{
			ObjectType: "kubernetes/role_binding",
			ObjectId:   kubeBindingId.String(),
		},
	}))

	// Get all existing namespaces once if we need them for resource name bindings
	var namespaces []string
	var err error
	if m.clusterRoleHasResourceNames(clusterRole) {
		namespaces, err = m.getNamespaces(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get existing namespaces: %w", err)
		}
		log.Info("Found existing namespaces for resource name binding", "namespaceCount", len(namespaces), "namespaces", namespaces)
	}

	// For each rule in the cluster role, create a binding to that RBAC role.
	// Then, attach each subject to that binding.
	// We explode the binding into a binding per role-rule combination, because each role-rule
	// maybe have a different target resource, due to resource name being a property of the rule.
	for rI, rule := range clusterRole.Rules {
		log.Info("Processing ClusterRole Rule", "apiGroups", rule.APIGroups, "resources", rule.Resources, "verbs", rule.Verbs)

		// ID the RoleBinding after the role's kube cluster, role name,
		// and the rule's index within the ClusterRole.
		rbacBindingId := kubeBindingId.WithSegment(rI)

		// Track that this binding relates to the kubernetes binding for lookups later.
		// See: deleteClusterBindingRelationships
		updates = append(updates, relationshipTouch(&spicedbv1.ObjectReference{
			ObjectType: "kubernetes/role_binding",
			ObjectId:   kubeBindingId.String(),
		}, "t_rbac_binding", &spicedbv1.SubjectReference{
			Object: &spicedbv1.ObjectReference{
				ObjectType: "rbac/role_binding",
				ObjectId:   rbacBindingId,
			},
		}))

		// Handle resource names if specified
		if len(rule.ResourceNames) > 0 {
			// If resource names are specified, create denormalized relationships to track
			// which specific resources are bound at the cluster level
			for _, apiGroup := range rule.APIGroups {
				for _, resource := range rule.Resources {
					if !isSupportedResourceType(apiGroup, resource) {
						// Skip unsupported resource types to avoid creating relationships
						// for resources not defined in the schema
						continue
					}
					for _, resourceName := range rule.ResourceNames {
						resourceType := fmt.Sprintf("kubernetes/%s", pluralToSingular(resource))

						// Create denormalized relationship to track this resource name binding
						// This is used when namespaces are added,
						// so that we can easily lookup what resources to bind to in that namespace.
						// Use empty namespace to indicate cluster-level resource name binding
						resourceId := NewResourceId(m.ClusterId, "", resourceName)
						updates = append(updates, relationshipTouch(&spicedbv1.ObjectReference{
							ObjectType: resourceType,
							ObjectId:   resourceId.String(),
						}, "t_role_binding", &spicedbv1.SubjectReference{
							Object: &spicedbv1.ObjectReference{
								ObjectType: "rbac/role_binding",
								ObjectId:   rbacBindingId,
							},
						}))

						// Create resource-level bindings for each existing namespace
						for _, namespace := range namespaces {
							// Create namespace-specific resource ID
							namespaceResourceId := NewResourceId(m.ClusterId, namespace, resourceName)

							// Create a relationship from the namespace-specific resource to the role binding
							// This is what grants access to the specific resource in this namespace
							updates = append(updates, relationshipTouch(&spicedbv1.ObjectReference{
								ObjectType: resourceType,
								ObjectId:   namespaceResourceId.String(),
							}, "t_role_binding", &spicedbv1.SubjectReference{
								Object: &spicedbv1.ObjectReference{
									ObjectType: "rbac/role_binding",
									ObjectId:   rbacBindingId,
								},
							}))

							log.Info("Created resource-level binding", "resourceType", resourceType, "resourceId", namespaceResourceId.String(), "bindingId", rbacBindingId, "namespace", namespace)
						}
					}
				}
			}

		} else {
			// If no resource names, bind to the cluster level (grants access to all resources of the specified type)
			resourceType := "kubernetes/cluster"
			resourceId := m.ClusterId

			updates = append(updates, relationshipTouch(&spicedbv1.ObjectReference{
				ObjectType: resourceType,
				ObjectId:   resourceId,
			}, "t_role_binding", &spicedbv1.SubjectReference{
				Object: &spicedbv1.ObjectReference{
					ObjectType: "rbac/role_binding",
					ObjectId:   rbacBindingId,
				},
			}))
		}

		// Create a relationship from the binding to the role-rule
		updates = append(updates, relationshipTouch(&spicedbv1.ObjectReference{
			ObjectType: "rbac/role_binding",
			ObjectId:   rbacBindingId,
		}, "t_role", &spicedbv1.SubjectReference{
			Object: &spicedbv1.ObjectReference{
				ObjectType: "rbac/role",
				ObjectId:   roleResourceId.WithSegment(rI),
			},
		}))

		// Create relationships from the binding to each subject
		for _, principalId := range principals {
			updates = append(updates, relationshipTouch(&spicedbv1.ObjectReference{
				ObjectType: "rbac/role_binding",
				ObjectId:   rbacBindingId,
			}, "t_subject", &spicedbv1.SubjectReference{
				Object: &spicedbv1.ObjectReference{
					ObjectType: "rbac/principal",
					ObjectId:   principalId,
				},
			}))
		}
	}

	return updates, nil
}

func (m *KubeRbacToKessel) deleteClusterBindingRelationships(ctx context.Context, binding *rbacv1.ClusterRoleBinding) error {
	log := logf.FromContext(ctx)

	// We need to find all of the bindings,
	// which we cannot do with a single delete.
	// This kind of read-modify-write cycle is not only not atomic
	// but would require fencing for complete concurrency control.

	// We track how cluster role bindings have exploded in the graph.
	// With Kessel, this could just be an attribute on a kube cluster role binding object.
	// gather all subject IDs from the relationships stream
	var currentRbacBindings []string

	err := streamutil.ForEach(
		func() (spicedbv1.PermissionsService_ReadRelationshipsClient, error) {
			return m.SpiceDb.ReadRelationships(ctx, &spicedbv1.ReadRelationshipsRequest{
				Consistency: fullyConsistent,
				RelationshipFilter: &spicedbv1.RelationshipFilter{
					ResourceType:       "kubernetes/role_binding",
					OptionalResourceId: NewClusterResourceId(m.ClusterId, binding.Name).String(),
					OptionalRelation:   "t_rbac_binding",
				},
			})
		},
		func(response *spicedbv1.ReadRelationshipsResponse) error {
			currentRbacBindings = append(currentRbacBindings, response.Relationship.Subject.Object.ObjectId)
			return nil
		},
	)
	if err != nil {
		log.Error(err, "Failed to read relationships for ClusterRoleBinding", "name", binding.Name)
		return fmt.Errorf("failed to read relationships for ClusterRoleBinding %s: %w", binding.Name, err)
	}

	// Now remove all of these bindings and any role_binding relationships to these.

	for _, bindingId := range currentRbacBindings {
		log.Info("Deleting cluster binding relationships", "bindingId", bindingId)
		_, err := m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
			RelationshipFilter: &spicedbv1.RelationshipFilter{
				ResourceType:       "rbac/role_binding",
				OptionalResourceId: bindingId,
			},
		})
		if err != nil {
			log.Error(err, "Failed to delete relationships for ClusterRoleBinding", "name", binding.Name)
			return fmt.Errorf("failed to delete relationships for ClusterRoleBinding %s: %w", binding.Name, err)
		}
		// Also delete where the binding is the subject
		_, err = m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
			RelationshipFilter: &spicedbv1.RelationshipFilter{
				OptionalSubjectFilter: &spicedbv1.SubjectFilter{
					SubjectType:       "rbac/role_binding",
					OptionalSubjectId: bindingId,
				},
			},
		})

		if err != nil {
			log.Error(err, "Failed to delete subject relationships for ClusterRoleBinding", "name", binding.Name)
			return fmt.Errorf("failed to delete subject relationships for ClusterRoleBinding %s: %w", binding.Name, err)
		}

		log.Info("Deleted cluster binding relationships", "bindingId", bindingId)
	}

	return nil
}

func (m *KubeRbacToKessel) MapNamespace(ctx context.Context, namespace *corev1.Namespace) error {
	if namespace == nil {
		return fmt.Errorf("namespace is nil")
	}

	log := logf.FromContext(ctx)
	log.Info("Mapping Namespace", "name", namespace.Name)

	updates := []*spicedbv1.RelationshipUpdate{}

	// Create relationship from namespace to cluster
	updates = append(updates, relationshipTouch(&spicedbv1.ObjectReference{
		ObjectType: "kubernetes/knamespace",
		ObjectId:   fmt.Sprintf("%s/%s", m.ClusterId, namespace.Name),
	}, "t_cluster", &spicedbv1.SubjectReference{
		Object: &spicedbv1.ObjectReference{
			ObjectType: "kubernetes/cluster",
			ObjectId:   m.ClusterId,
		},
	}))

	// Process resource name bindings for this new namespace
	resourceNameUpdates, err := m.processResourceNameBindingsForNamespace(ctx, namespace.Name)
	if err != nil {
		log.Error(err, "Failed to process resource name bindings for namespace", "namespace", namespace.Name)
		return fmt.Errorf("failed to process resource name bindings for namespace %s: %w", namespace.Name, err)
	}
	updates = append(updates, resourceNameUpdates...)

	if len(updates) > 0 {
		_, err := m.SpiceDb.WriteRelationships(ctx, &spicedbv1.WriteRelationshipsRequest{
			Updates: updates,
		})
		if err != nil {
			log.Error(err, "Failed to write namespace relationships to SpiceDB", "updates", updates)
			return err
		}
		log.Info("Successfully wrote namespace relationships to SpiceDB", "name", namespace.Name)
	}

	return nil
}

func (m *KubeRbacToKessel) processResourceNameBindingsForNamespace(ctx context.Context, namespace string) ([]*spicedbv1.RelationshipUpdate, error) {
	log := logf.FromContext(ctx)
	updates := []*spicedbv1.RelationshipUpdate{}

	// Look up all resource-level t_role_binding relationships using the prefix {cluster_id}//
	// This finds all cluster-level resource name bindings
	prefix := fmt.Sprintf("%s//", m.ClusterId)

	err := streamutil.ForEach(
		func() (spicedbv1.PermissionsService_ReadRelationshipsClient, error) {
			return m.SpiceDb.ReadRelationships(ctx, &spicedbv1.ReadRelationshipsRequest{
				Consistency: fullyConsistent,
				RelationshipFilter: &spicedbv1.RelationshipFilter{
					OptionalResourceIdPrefix: prefix,
					OptionalRelation:         "t_role_binding",
					OptionalSubjectFilter: &spicedbv1.SubjectFilter{
						SubjectType: "rbac/role_binding",
					},
				},
			})
		},
		func(response *spicedbv1.ReadRelationshipsResponse) error {
			// Extract the binding ID from the relationship
			bindingId := response.Relationship.Subject.Object.ObjectId

			// Parse the resource ID to get the resource type and name
			resourceId, err := NewResourceIdFromString(response.Relationship.Resource.ObjectId)
			if err == nil {
				// Create namespace-specific resource binding
				// The resource ID format is {cluster_id}/{namespace}/{resource_name}
				namespaceResourceId := NewResourceId(m.ClusterId, namespace, resourceId.Name)

				// Create the namespace-specific resource binding relationship
				updates = append(updates, relationshipTouch(&spicedbv1.ObjectReference{
					ObjectType: response.Relationship.Resource.ObjectType,
					ObjectId:   namespaceResourceId.String(),
				}, "t_role_binding", &spicedbv1.SubjectReference{
					Object: &spicedbv1.ObjectReference{
						ObjectType: "rbac/role_binding",
						ObjectId:   bindingId,
					},
				}))
			}

			return nil
		},
	)

	if err != nil {
		return nil, fmt.Errorf("failed to process resource name bindings: %w", err)
	}

	log.Info("Processed resource name bindings for namespace", "namespace", namespace, "updatesCount", len(updates))
	return updates, nil
}

func (m *KubeRbacToKessel) clusterRoleHasResourceNames(clusterRole *rbacv1.ClusterRole) bool {
	for _, rule := range clusterRole.Rules {
		if len(rule.ResourceNames) > 0 {
			return true
		}
	}
	return false
}

func (m *KubeRbacToKessel) getNamespaces(ctx context.Context) ([]string, error) {
	namespaces := []string{}
	err := streamutil.ForEach(
		func() (spicedbv1.PermissionsService_ReadRelationshipsClient, error) {
			return m.SpiceDb.ReadRelationships(ctx, &spicedbv1.ReadRelationshipsRequest{
				Consistency: fullyConsistent,
				RelationshipFilter: &spicedbv1.RelationshipFilter{
					ResourceType:     "kubernetes/knamespace",
					OptionalRelation: "t_cluster",
				},
			})
		},
		func(response *spicedbv1.ReadRelationshipsResponse) error {
			// Extract namespace name from the resource ID (format: {cluster_id}/{namespace})
			resourceId := response.Relationship.Resource.ObjectId
			parts := strings.Split(resourceId, "/")
			if len(parts) == 2 {
				namespaces = append(namespaces, parts[1])
			}
			return nil
		},
	)
	return namespaces, err
}

// DeleteRole handles the deletion of a Kubernetes Role by cleaning up all related RBAC objects and relationships
func (m *KubeRbacToKessel) DeleteRole(ctx context.Context, role *rbacv1.Role) error {
	if role == nil {
		return fmt.Errorf("role is nil")
	}

	log := logf.FromContext(ctx)
	log.Info("Deleting Role", "name", role.Name, "namespace", role.Namespace)

	roleResourceId := NewResourceIdFromNamespacedName(m.ClusterId, role)

	// Step 1: Find all kube role bindings that reference this role (via t_role_binding)
	var kubeBindingIds []string
	err := streamutil.ForEach(
		func() (spicedbv1.PermissionsService_ReadRelationshipsClient, error) {
			return m.SpiceDb.ReadRelationships(ctx, &spicedbv1.ReadRelationshipsRequest{
				Consistency: fullyConsistent,
				RelationshipFilter: &spicedbv1.RelationshipFilter{
					ResourceType:       "kubernetes/role",
					OptionalResourceId: roleResourceId.String(),
					OptionalRelation:   "t_role_binding",
				},
			})
		},
		func(response *spicedbv1.ReadRelationshipsResponse) error {
			kubeBindingIds = append(kubeBindingIds, response.Relationship.Subject.Object.ObjectId)
			return nil
		},
	)
	if err != nil {
		log.Error(err, "Failed to read kube role binding relationships for Role", "name", role.Name, "namespace", role.Namespace)
		return fmt.Errorf("failed to read kube role binding relationships for Role %s/%s: %w", role.Namespace, role.Name, err)
	}

	log.Info("Found kube role bindings for Role", "name", role.Name, "namespace", role.Namespace, "bindingCount", len(kubeBindingIds))

	// Step 2: For each kube role binding, perform a standard cascade deletion
	for _, kubeBindingId := range kubeBindingIds {
		if err := m.deleteKubeBindingCascade(ctx, kubeBindingId); err != nil {
			return err
		}
	}

	// Step 3: deleteKubeBindingCascade already removed t_role_binding edges. No additional work needed here.
	// Proceed to delete all rbac/role objects for this role.
	// Step 3: Delete all rbac/role objects with prefix matching this role
	res, err := m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
		RelationshipFilter: &spicedbv1.RelationshipFilter{
			ResourceType: "rbac/role",
			// Use a prefix so that it matches ALL role-rules
			OptionalResourceIdPrefix: roleResourceId.String() + "/",
		},
	})
	if err != nil {
		log.Error(err, "Failed to delete rbac role objects for Role", "name", role.Name, "namespace", role.Namespace)
		return fmt.Errorf("failed to delete rbac role objects for Role %s/%s: %w", role.Namespace, role.Name, err)
	}

	log.Info("Successfully deleted Role", "name", role.Name, "namespace", role.Namespace, "deletedRbacRoleCount", res.RelationshipsDeletedCount)
	return nil
}

// DeleteRoleBinding handles the deletion of a Kubernetes RoleBinding by cleaning up all related RBAC binding objects and relationships
func (m *KubeRbacToKessel) DeleteRoleBinding(ctx context.Context, binding *rbacv1.RoleBinding) error {
	if binding == nil {
		return fmt.Errorf("role binding is nil")
	}

	log := logf.FromContext(ctx)
	log.Info("Deleting RoleBinding", "name", binding.Name, "namespace", binding.Namespace)

	kubeBindingId := NewResourceIdFromNamespacedName(m.ClusterId, binding)

	// Step 1: Find all rbac binding IDs for this kube binding (we need these for subject relationship deletion)
	var rbacBindingIds []string
	err := streamutil.ForEach(
		func() (spicedbv1.PermissionsService_ReadRelationshipsClient, error) {
			return m.SpiceDb.ReadRelationships(ctx, &spicedbv1.ReadRelationshipsRequest{
				Consistency: fullyConsistent,
				RelationshipFilter: &spicedbv1.RelationshipFilter{
					ResourceType:       "kubernetes/role_binding",
					OptionalResourceId: kubeBindingId.String(),
					OptionalRelation:   "t_rbac_binding",
				},
			})
		},
		func(response *spicedbv1.ReadRelationshipsResponse) error {
			rbacBindingIds = append(rbacBindingIds, response.Relationship.Subject.Object.ObjectId)
			return nil
		},
	)
	if err != nil {
		log.Error(err, "Failed to read rbac binding relationships for RoleBinding", "name", binding.Name, "namespace", binding.Namespace)
		return fmt.Errorf("failed to read rbac binding relationships for RoleBinding %s/%s: %w", binding.Namespace, binding.Name, err)
	}

	log.Info("Found rbac bindings for RoleBinding", "name", binding.Name, "namespace", binding.Namespace, "rbacBindingCount", len(rbacBindingIds))

	// Step 2: Delete the t_rbac_binding tracking relationships
	_, err = m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
		RelationshipFilter: &spicedbv1.RelationshipFilter{
			ResourceType:       "kubernetes/role_binding",
			OptionalResourceId: kubeBindingId.String(),
			OptionalRelation:   "t_rbac_binding",
		},
	})
	if err != nil {
		log.Error(err, "Failed to delete t_rbac_binding tracking relationships", "name", binding.Name, "namespace", binding.Namespace)
		return fmt.Errorf("failed to delete t_rbac_binding tracking relationships for RoleBinding %s/%s: %w", binding.Namespace, binding.Name, err)
	}

	// Step 3: Delete all rbac/role_binding objects with prefix matching this kube binding
	// The rbac binding IDs are created as: kubeBindingId.WithSegment(ruleIndex)
	// So we can delete all rbac bindings for this kube binding using prefix matching
	rbacBindingPrefix := kubeBindingId.String() + "/"
	_, err = m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
		RelationshipFilter: &spicedbv1.RelationshipFilter{
			ResourceType:             "rbac/role_binding",
			OptionalResourceIdPrefix: rbacBindingPrefix,
		},
	})
	if err != nil {
		log.Error(err, "Failed to delete rbac role bindings for RoleBinding", "name", binding.Name, "namespace", binding.Namespace, "prefix", rbacBindingPrefix)
		return fmt.Errorf("failed to delete rbac role bindings for RoleBinding %s/%s: %w", binding.Namespace, binding.Name, err)
	}

	// Step 4: Delete all relationships where any of the deleted rbac bindings are subjects
	// This includes resource-level and namespace-level t_role_binding relationships
	// Since SubjectFilter doesn't support prefix matching, we need to delete them individually
	for _, rbacBindingId := range rbacBindingIds {
		_, err = m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
			RelationshipFilter: &spicedbv1.RelationshipFilter{
				OptionalSubjectFilter: &spicedbv1.SubjectFilter{
					SubjectType:       "rbac/role_binding",
					OptionalSubjectId: rbacBindingId,
				},
			},
		})
		if err != nil {
			log.Error(err, "Failed to delete subject relationships for rbac binding", "rbacBindingId", rbacBindingId)
			return fmt.Errorf("failed to delete subject relationships for rbac binding %s: %w", rbacBindingId, err)
		}
	}

	// Step 5: Delete the t_role_binding tracking relationships from kube role to kube binding
	// This removes the relationship from the kubernetes/role to this kubernetes/role_binding
	_, err = m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
		RelationshipFilter: &spicedbv1.RelationshipFilter{
			OptionalSubjectFilter: &spicedbv1.SubjectFilter{
				SubjectType:       "kubernetes/role_binding",
				OptionalSubjectId: kubeBindingId.String(),
			},
		},
	})
	if err != nil {
		log.Error(err, "Failed to delete t_role_binding tracking relationships for RoleBinding", "name", binding.Name, "namespace", binding.Namespace)
		return fmt.Errorf("failed to delete t_role_binding tracking relationships for RoleBinding %s/%s: %w", binding.Namespace, binding.Name, err)
	}

	log.Info("Successfully deleted RoleBinding", "name", binding.Name, "namespace", binding.Namespace)
	return nil
}

// DeleteClusterRoleBinding cleans up all RBAC binding objects and relationships for a cluster-scoped binding.
func (m *KubeRbacToKessel) DeleteClusterRoleBinding(ctx context.Context, binding *rbacv1.ClusterRoleBinding) error {
	if binding == nil {
		return fmt.Errorf("cluster role binding is nil")
	}

	log := logf.FromContext(ctx)
	log.Info("Deleting ClusterRoleBinding", "name", binding.Name)

	// Cluster-scoped kube binding id has empty namespace segment
	kubeBindingId := NewClusterResourceId(m.ClusterId, binding.Name)

	// Step 1: gather all rbac/role_binding ids attached to this kube binding (via t_rbac_binding)
	var rbacBindingIds []string
	err := streamutil.ForEach(
		func() (spicedbv1.PermissionsService_ReadRelationshipsClient, error) {
			return m.SpiceDb.ReadRelationships(ctx, &spicedbv1.ReadRelationshipsRequest{
				Consistency: fullyConsistent,
				RelationshipFilter: &spicedbv1.RelationshipFilter{
					ResourceType:       "kubernetes/role_binding",
					OptionalResourceId: kubeBindingId.String(),
					OptionalRelation:   "t_rbac_binding",
				},
			})
		},
		func(res *spicedbv1.ReadRelationshipsResponse) error {
			rbacBindingIds = append(rbacBindingIds, res.Relationship.Subject.Object.ObjectId)
			return nil
		},
	)
	if err != nil {
		log.Error(err, "Failed to read rbac binding relationships for ClusterRoleBinding", "name", binding.Name)
		return fmt.Errorf("failed to read rbac binding relationships for ClusterRoleBinding %s: %w", binding.Name, err)
	}

	log.Info("Found rbac bindings for ClusterRoleBinding", "name", binding.Name, "rbacBindingCount", len(rbacBindingIds))

	// Step 2: delete t_rbac_binding tracking relationships on kube binding
	_, err = m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
		RelationshipFilter: &spicedbv1.RelationshipFilter{
			ResourceType:       "kubernetes/role_binding",
			OptionalResourceId: kubeBindingId.String(),
			OptionalRelation:   "t_rbac_binding",
		},
	})
	if err != nil {
		log.Error(err, "Failed to delete t_rbac_binding tracking relationships", "name", binding.Name)
		return fmt.Errorf("failed to delete t_rbac_binding tracking relationships for ClusterRoleBinding %s: %w", binding.Name, err)
	}

	// Step 3: delete all rbac/role_binding objects prefixed by kubeBindingId
	rbacBindingPrefix := kubeBindingId.String() + "/"
	_, err = m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
		RelationshipFilter: &spicedbv1.RelationshipFilter{
			ResourceType:             "rbac/role_binding",
			OptionalResourceIdPrefix: rbacBindingPrefix,
		},
	})
	if err != nil {
		log.Error(err, "Failed to delete rbac role bindings for ClusterRoleBinding", "name", binding.Name, "prefix", rbacBindingPrefix)
		return fmt.Errorf("failed to delete rbac role bindings for ClusterRoleBinding %s: %w", binding.Name, err)
	}

	// Step 4: delete all relationships where those rbacBindingIds are subjects
	for _, id := range rbacBindingIds {
		_, err = m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
			RelationshipFilter: &spicedbv1.RelationshipFilter{
				OptionalSubjectFilter: &spicedbv1.SubjectFilter{
					SubjectType:       "rbac/role_binding",
					OptionalSubjectId: id,
				},
			},
		})
		if err != nil {
			log.Error(err, "Failed to delete subject relationships for rbac binding", "rbacBindingId", id)
			return fmt.Errorf("failed to delete subject relationships for rbac binding %s: %w", id, err)
		}
	}

	// Step 5: delete t_role_binding relationships from kubernetes/role (clusterRole) to this kube binding
	_, err = m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
		RelationshipFilter: &spicedbv1.RelationshipFilter{
			OptionalSubjectFilter: &spicedbv1.SubjectFilter{
				SubjectType:       "kubernetes/role_binding",
				OptionalSubjectId: kubeBindingId.String(),
			},
		},
	})
	if err != nil {
		log.Error(err, "Failed to delete t_role_binding tracking relationships", "name", binding.Name)
		return fmt.Errorf("failed to delete t_role_binding tracking relationships for ClusterRoleBinding %s: %w", binding.Name, err)
	}

	log.Info("Successfully deleted ClusterRoleBinding", "name", binding.Name)
	return nil
}

// DeleteClusterRole removes a ClusterRole and all derived RBAC data.
func (m *KubeRbacToKessel) DeleteClusterRole(ctx context.Context, clusterRole *rbacv1.ClusterRole) error {
	if clusterRole == nil {
		return fmt.Errorf("cluster role is nil")
	}
	log := logf.FromContext(ctx)
	log.Info("Deleting ClusterRole", "name", clusterRole.Name)

	roleResourceId := NewClusterResourceId(m.ClusterId, clusterRole.Name)

	// Step 1: Find all kube role bindings that reference this role (via t_role_binding)
	// This requires a tuple query because the bindings are not named after the role
	// (and therefore we cannot just do a prefix match).
	var kubeBindingIds []string
	err := streamutil.ForEach(
		func() (spicedbv1.PermissionsService_ReadRelationshipsClient, error) {
			return m.SpiceDb.ReadRelationships(ctx, &spicedbv1.ReadRelationshipsRequest{
				Consistency: fullyConsistent,
				RelationshipFilter: &spicedbv1.RelationshipFilter{
					ResourceType:       "kubernetes/role",
					OptionalResourceId: roleResourceId.String(),
					OptionalRelation:   "t_role_binding",
				},
			})
		},
		func(response *spicedbv1.ReadRelationshipsResponse) error {
			kubeBindingIds = append(kubeBindingIds, response.Relationship.Subject.Object.ObjectId)
			return nil
		},
	)
	if err != nil {
		log.Error(err, "Failed to read kube role binding relationships for ClusterRole", "name", clusterRole.Name)
		return fmt.Errorf("failed to read kube role binding relationships for ClusterRole %s: %w", clusterRole.Name, err)
	}
	log.Info("Found kube role bindings for ClusterRole", "name", clusterRole.Name, "bindingCount", len(kubeBindingIds))

	// Step 2: For each kube role binding, perform a standard cascade deletion
	for _, kubeBindingId := range kubeBindingIds {
		if err := m.deleteKubeBindingCascade(ctx, kubeBindingId); err != nil {
			return err
		}
	}

	// Step 3: deleteKubeBindingCascade already removed t_role_binding edges. No additional work needed here.
	// Proceed to delete all rbac/role objects for this role.
	// Step 3: Delete all rbac/role objects with prefix matching this role
	res, err := m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
		RelationshipFilter: &spicedbv1.RelationshipFilter{
			ResourceType: "rbac/role",
			// Use a prefix so that it matches ALL role-rules
			OptionalResourceIdPrefix: roleResourceId.String() + "/",
		},
	})
	if err != nil {
		log.Error(err, "Failed to delete rbac role objects for ClusterRole", "name", clusterRole.Name)
		return fmt.Errorf("failed to delete rbac role objects for ClusterRole %s: %w", clusterRole.Name, err)
	}

	log.Info("Successfully deleted ClusterRole", "name", clusterRole.Name, "deletedRbacRoleCount", res.RelationshipsDeletedCount)
	return nil
}

// deleteKubeBindingCascade removes all derived RBAC objects and tracking relationships for the supplied
// kubernetes/role_binding resource ID (namespaced or cluster-scoped). It is used by RoleBinding deletion directly
// and by Role / ClusterRole deletion when they clean up each binding that referenced the role.
func (m *KubeRbacToKessel) deleteKubeBindingCascade(ctx context.Context, kubeBindingId string) error {
	log := logf.FromContext(ctx)

	// Step 1: list derived rbac/role_binding objects associated via t_rbac_binding
	var rbacBindingIds []string
	if err := streamutil.ForEach(
		func() (spicedbv1.PermissionsService_ReadRelationshipsClient, error) {
			return m.SpiceDb.ReadRelationships(ctx, &spicedbv1.ReadRelationshipsRequest{
				Consistency: fullyConsistent,
				RelationshipFilter: &spicedbv1.RelationshipFilter{
					ResourceType:       "kubernetes/role_binding",
					OptionalResourceId: kubeBindingId,
					OptionalRelation:   "t_rbac_binding",
				},
			})
		},
		func(resp *spicedbv1.ReadRelationshipsResponse) error {
			rbacBindingIds = append(rbacBindingIds, resp.Relationship.Subject.Object.ObjectId)
			return nil
		},
	); err != nil {
		log.Error(err, "enumerating rbac bindings for kube binding", "kubeBindingId", kubeBindingId)
		return fmt.Errorf("failed to enumerate rbac bindings for kube binding %s: %w", kubeBindingId, err)
	}

	// Step 2: remove t_rbac_binding edges on the kube binding itself
	// This is for the kube binding, so no prefix match is needed.
	if _, err := m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
		RelationshipFilter: &spicedbv1.RelationshipFilter{
			ResourceType:       "kubernetes/role_binding",
			OptionalResourceId: kubeBindingId,
			OptionalRelation:   "t_rbac_binding",
		},
	}); err != nil {
		log.Error(err, "deleting t_rbac_binding edges", "kubeBindingId", kubeBindingId)
		return fmt.Errorf("failed to delete t_rbac_binding edges for %s: %w", kubeBindingId, err)
	}

	// Step 3: Delete all rbac/role_binding objects with prefix matching this kube binding
	// The rbac binding IDs are created as: kubeBindingId.WithSegment(ruleIndex)
	// So we can delete all rbac bindings for this kube binding using prefix matching
	if _, err := m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
		RelationshipFilter: &spicedbv1.RelationshipFilter{
			ResourceType:             "rbac/role_binding",
			OptionalResourceIdPrefix: kubeBindingId + "/",
		},
	}); err != nil {
		log.Error(err, "deleting derived rbac/role_binding objects", "kubeBindingId", kubeBindingId)
		return fmt.Errorf("failed to delete derived rbac role bindings for %s: %w", kubeBindingId, err)
	}

	// Step 4: delete any relationships where those rbacBindingIds are subjects
	// Since SubjectFilter doesn't support prefix matching, we need to delete them individually
	for _, rbacBindingId := range rbacBindingIds {
		if _, err := m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
			RelationshipFilter: &spicedbv1.RelationshipFilter{
				OptionalSubjectFilter: &spicedbv1.SubjectFilter{
					SubjectType:       "rbac/role_binding",
					OptionalSubjectId: rbacBindingId,
				},
			},
		}); err != nil {
			log.Error(err, "deleting subject relationships for derived binding", "rbacBindingId", rbacBindingId)
			return fmt.Errorf("failed to delete subject relationships for rbac binding %s: %w", rbacBindingId, err)
		}
	}

	// Step 5: delete t_role_binding edges where this kube binding is the SUBJECT
	if _, err := m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
		RelationshipFilter: &spicedbv1.RelationshipFilter{
			OptionalSubjectFilter: &spicedbv1.SubjectFilter{
				SubjectType:       "kubernetes/role_binding",
				OptionalSubjectId: kubeBindingId,
			},
		},
	}); err != nil {
		log.Error(err, "deleting t_role_binding edges where kube binding is subject", "kubeBindingId", kubeBindingId)
		return fmt.Errorf("failed to delete t_role_binding edges for %s: %w", kubeBindingId, err)
	}

	return nil
}
