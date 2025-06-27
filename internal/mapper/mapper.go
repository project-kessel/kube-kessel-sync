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
	"errors"
	"fmt"
	"io"

	spicedbv1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	spicedb "github.com/authzed/authzed-go/v1"
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

func (m *KubeRbacToKessel) ObjectAddedOrChanged(ctx context.Context, obj client.Object) error {
	log := logf.FromContext(ctx)

	switch o := obj.(type) {
	case *rbacv1.Role:
		m.MapRole(ctx, o)
	case *rbacv1.RoleBinding:
		m.MapRoleBinding(ctx, o)
	case *rbacv1.ClusterRole:
		m.MapClusterRole(ctx, o)
	case *rbacv1.ClusterRoleBinding:
		m.MapClusterRoleBinding(ctx, o)
	case *corev1.Namespace:
		m.MapNamespace(ctx, o)
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
		log.Info("Role deleted", "name", o.Name, "namespace", o.Namespace)
	case *rbacv1.RoleBinding:
		log.Info("RoleBinding deleted", "name", o.Name, "namespace", o.Namespace)
	case *rbacv1.ClusterRole:
		log.Info("ClusterRole deleted", "name", o.Name)
	case *rbacv1.ClusterRoleBinding:
		log.Info("ClusterRoleBinding deleted", "name", o.Name)
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
	_, err = m.SpiceDb.WriteSchema(context.Background(), request)
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
			OptionalResourceIdPrefix: roleResourceId.String(),
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
					// TODO: allow-list resource/verb because not all may be in the schema

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
	bindingIds, err := m.getBindingIds(ctx, roleResourceId)
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

		uniqueResourceIds := make(map[string]*ResourceId)
		for _, bindingId := range bindingIds {
			// Determine the underlying Kubernetes binding for each RBAC binding.
			// This is a set because we may have multiple RBAC bindings for the same Kubernetes binding.
			resourceId := NewResourceIdFromString(bindingId)
			if resourceId != nil {
				uniqueResourceIds[resourceId.String()] = resourceId
			}

			_, err := m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
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
			for _, resourceId := range uniqueResourceIds {
				// Delete all the binding relationships where the binding is the resource
				// (i.e. to role & subjects)
				// Done in this loop since we can use prefix matching to delete all.
				// With Kessel, I think we could design schema & API to simplify this stuff.
				_, err = m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
					RelationshipFilter: &spicedbv1.RelationshipFilter{
						ResourceType:             "rbac/role_binding",
						OptionalResourceIdPrefix: resourceId.String(),
					},
				})
				if err != nil {
					return fmt.Errorf("failed to delete relationships for Role Binding %s: %w", resourceId.String(), err)
				}

				bindingUpdates, err := m.getNamespaceBindingUpdates(ctx, role, resourceId, subjects)
				if err != nil {
					return fmt.Errorf("failed to get namespace binding updates for Role Binding %s: %w", resourceId.String(), err)
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
			log.Error(err, "Failed to write relationships to SpiceDB")
			return err
		}
	}
	return nil
}

func (m *KubeRbacToKessel) getBindingIds(ctx context.Context, kubeRoleId *ResourceId) ([]string, error) {
	bindingIds := []string{}
	err := forEach(
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
	err := forEach(
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
			// TODO: assumes subjects are principals, but could be groups
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

	// Lookup the referenced role
	role := &rbacv1.Role{}
	if err := m.Kube.Get(ctx, client.ObjectKey{
		Name:      binding.RoleRef.Name,
		Namespace: binding.Namespace,
	}, role); err != nil {
		log.Error(err, "Failed to get Role for RoleBinding", "name", binding.Name, "namespace", binding.Namespace)
		return fmt.Errorf("failed to get Role %s/%s for RoleBinding %s/%s: %w", binding.Namespace, binding.RoleRef.Name, binding.Namespace, binding.Name, err)
	}

	// Like with roles, delete all possible previous binding relationships
	// TODO: Could diff and compare to be more efficient and make atomic
	log.Info("Deleting previous relationships for RoleBinding", "name", binding.Name, "namespace", binding.Namespace)
	m.deleteBindingRelationships(ctx, binding)

	principalIds := m.convertSubjectsToPrincipalIds(binding.Subjects)
	updates, err := m.getNamespaceBindingUpdates(ctx, role, NewResourceIdFromNamespacedName(m.ClusterId, binding), principalIds)
	if err != nil {
		log.Error(err, "Failed to map RoleBinding", "name", binding.Name, "namespace", binding.Namespace)
		return fmt.Errorf("failed to map RoleBinding %s/%s: %w", binding.Namespace, binding.Name, err)
	}

	// Updates collected, write them to SpiceDB
	if len(updates) > 0 {
		log.Info("Writing RoleBinding relationships to SpiceDB", "updatesCount", len(updates))
		_, err := m.SpiceDb.WriteRelationships(ctx, &spicedbv1.WriteRelationshipsRequest{
			Updates: updates,
		})
		if err != nil {
			log.Error(err, "Failed to write relationships to SpiceDB for RoleBinding", "name", binding.Name, "namespace", binding.Namespace)
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
		// TODO: rethink principal identifiers for kubernetes principals
		principalId := fmt.Sprintf("kubernetes/%s", subject.Name)
		principalIds = append(principalIds, principalId)
	}
	return principalIds
}

// Given a Role and a corresponding Kube RoleBinding, generate binding updates.
func (m *KubeRbacToKessel) getNamespaceBindingUpdates(ctx context.Context, role *rbacv1.Role, kubeBindingId *ResourceId, principals []string) ([]*spicedbv1.RelationshipUpdate, error) {
	log := logf.FromContext(ctx)

	roleResourceId := NewResourceIdFromNamespacedName(m.ClusterId, role)
	updates := []*spicedbv1.RelationshipUpdate{}

	// For each rule in the role, create a binding to that RBAC role.
	// Then, attach each subject to that binding.
	// We explode the binding into a binding per role-rule combination, because each role-rule
	// maybe have a different target resource, due to resource name being a property of the rule.
	for rI, rule := range role.Rules {
		log.Info("Processing Role Rule", "apiGroups", rule.APIGroups, "resources", rule.Resources, "verbs", rule.Verbs)

		// ID the RoleBinding after the role's kube cluster, namespace, role name,
		// and the rule's index within the Role.
		rbacBindingId := kubeBindingId.WithSegment(rI)

		// Track that this binding relates to the kubernetes binding for lookups later.
		// See: deleteBindingRelationships
		updates = append(updates, relationshipTouch(&spicedbv1.ObjectReference{
			ObjectType: "kubernetes/role_binding",
			ObjectId:   kubeBindingId.String(),
		}, "t_rbac_binding", &spicedbv1.SubjectReference{
			Object: &spicedbv1.ObjectReference{
				ObjectType: "rbac/role_binding",
				ObjectId:   rbacBindingId,
			},
		}))

		// Now also track from the kube role to the binding,
		// so we can traverse from the kube role to rbac bindings
		updates = append(updates, relationshipTouch(&spicedbv1.ObjectReference{
			ObjectType: "kubernetes/role",
			ObjectId:   roleResourceId.String(),
		}, "t_role_binding", &spicedbv1.SubjectReference{
			Object: &spicedbv1.ObjectReference{
				ObjectType: "kubernetes/role_binding",
				ObjectId:   kubeBindingId.String(),
			},
		}))

		// Create a relationship from the resource(s) to this binding
		// Where a role gets bound in RBAC depends on:
		// - the referenced role's rule's resource names (if specified, bind to specific resources)
		// - the role binding's namespace (if no resource names, bind to namespace)
		if len(rule.ResourceNames) > 0 {
			// If resource names are specified, bind to each specific resource
			for _, resource := range rule.Resources {
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
		} else {
			// If no resource names, bind to the namespace (grants access to all resources of the specified type)
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
					// TODO: allow-list resource/verb because not all may be in the schema

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
	bindingIds, err := m.getBindingIds(ctx, roleResourceId)
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
			resourceId := NewResourceIdFromString(bindingId)
			if resourceId != nil {
				uniqueResourceIds[resourceId.String()] = resourceId
			}

			_, err := m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
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
			log.Error(err, "Failed to write relationships to SpiceDB")
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

	principalIds := m.convertSubjectsToPrincipalIds(clusterRoleBinding.Subjects)
	updates, err := m.getClusterBindingUpdates(ctx, clusterRole, NewClusterResourceId(m.ClusterId, clusterRoleBinding.Name), principalIds)
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
			log.Error(err, "Failed to write relationships to SpiceDB for ClusterRoleBinding", "name", clusterRoleBinding.Name)
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

	err := forEach(
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

func forEach[T any, S interface {
	Recv() (T, error)
}](startStream func() (S, error), processResponse func(T) error) error {
	stream, err := startStream()
	if err != nil {
		return err
	}

	for {
		response, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		if err := processResponse(response); err != nil {
			return err
		}
	}

	return nil
}

// pluralToSingular converts common Kubernetes plural resource names to singular
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
		// See: deleteBindingRelationships
		updates = append(updates, relationshipTouch(&spicedbv1.ObjectReference{
			ObjectType: "kubernetes/role_binding",
			ObjectId:   kubeBindingId.String(),
		}, "t_rbac_binding", &spicedbv1.SubjectReference{
			Object: &spicedbv1.ObjectReference{
				ObjectType: "rbac/role_binding",
				ObjectId:   rbacBindingId,
			},
		}))

		// Now also track from the kube role to the binding,
		// so we can traverse from the kube role to rbac bindings
		updates = append(updates, relationshipTouch(&spicedbv1.ObjectReference{
			ObjectType: "kubernetes/role",
			ObjectId:   roleResourceId.String(),
		}, "t_role_binding", &spicedbv1.SubjectReference{
			Object: &spicedbv1.ObjectReference{
				ObjectType: "kubernetes/role_binding",
				ObjectId:   kubeBindingId.String(),
			},
		}))

		// Create a relationship from the cluster to this binding
		// Cluster roles are bound at the cluster level (kubernetes/cluster)
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

	err := forEach(
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

	if len(updates) > 0 {
		_, err := m.SpiceDb.WriteRelationships(ctx, &spicedbv1.WriteRelationshipsRequest{
			Updates: updates,
		})
		if err != nil {
			log.Error(err, "Failed to write namespace relationships to SpiceDB")
			return err
		}
		log.Info("Successfully wrote namespace relationships to SpiceDB", "name", namespace.Name)
	}

	return nil
}
