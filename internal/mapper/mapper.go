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
	// This is not atomic, because it requires its own request.
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

		// TODO: we could use the resource name to implicitly replicate the resource into the fabric,
		// assuming it existed in that namespace.
		// This could happen here or in the RoleBinding mapping.

		for _, apiGroup := range rule.APIGroups {
			for _, resource := range rule.Resources {
				for _, verb := range rule.Verbs {
					// TODO: allow-list resource/verb because not all may be in the schema

					// Format the verb to be compatible with RBAC Role relation
					verb, tuple := permissionToTuple(apiGroup, resource, verb, roleId)
					update := &spicedbv1.RelationshipUpdate{
						// Touch to allow idempotent retry
						Operation:    spicedbv1.RelationshipUpdate_OPERATION_TOUCH,
						Relationship: tuple,
					}

					updates = append(updates, update)
					log.Info("Adding tuple", "resource", roleId, "verb", verb, "role", role.Name)
				}
			}
		}
	}

	// We also need to get any existing role bindings,
	// because ksl bindings are a function of the kube binding *and* and the kube role.
	// We'd normally want to do a diff of what resources were bound currently,
	// with what resources should be bound given resourcenames in the role-rules,
	// and then add/remove the relationships as needed.
	// For POC, we'll just remove all existing RBAC role bindings and recreate.
	// To do this, we get all role bindings and their subjects.
	bindingIds := []string{}
	err = m.getBindingIds(ctx, roleResourceId, bindingIds)
	if err != nil {
		return err
	}
	// If any bindings, get the subjects of one of them, and then delete all relationships to each.
	// This is not atomic, but it is consistent.
	if len(bindingIds) > 0 {
		// Get the subjects for the first binding. They will all be the same,
		// and we need this to be able to reconstitute new bindings later.
		firstBindingId := bindingIds[0]
		subjects := []string{}
		err := m.getRbacBindingSubjects(ctx, firstBindingId, subjects)
		if err != nil {
			log.Error(err, "Failed to get subjects for binding", "bindingId", firstBindingId)
			return fmt.Errorf("failed to get subjects for binding %s: %w", firstBindingId, err)
		}
		log.Info("Found subjects for binding", "bindingId", firstBindingId, "subjectCount", len(subjects))

		// Collect unique resource IDs from binding IDs
		uniqueResourceIds := make(map[string]*ResourceId)
		for _, bindingId := range bindingIds {
			// Parse resource ID from binding ID and collect unique ones
			resourceId := NewResourceIdFromString(bindingId)
			if resourceId != nil {
				uniqueResourceIds[resourceId.String()] = resourceId
			}

			// Delete all relationships to the RBAC bindings,
			// because some may be deleted, and some may move to a different resource.
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

			// Delete all the binding relationships where the binding is the resource
			// (i.e. to role & subjects)
			_, err = m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
				RelationshipFilter: &spicedbv1.RelationshipFilter{
					ResourceType:       "rbac/role_binding",
					OptionalResourceId: bindingId,
				},
			})
			if err != nil {
				return fmt.Errorf("failed to delete relationships for Role %s/%s: %w", role.Namespace, role.Name, err)
			}

			// Now for each kubernetes binding implied by the RBAC bindings, recreate the RBAC bindings.
			for _, resourceId := range uniqueResourceIds {
				updates, err = m.getNamespaceBindingUpdates(ctx, role, resourceId, subjects, updates)
				if err != nil {
					return fmt.Errorf("failed to map namespace binding for Role %s/%s: %w", role.Namespace, role.Name, err)
				}
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

func (m *KubeRbacToKessel) getBindingIds(ctx context.Context, kubeRoleId *ResourceId, bindingIds []string) error {
	return forEach(
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
}

func (m *KubeRbacToKessel) getRbacBindingSubjects(ctx context.Context, bindingId string, subjects []string) error {
	return forEach(
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
	updates := []*spicedbv1.RelationshipUpdate{}
	updates, err := m.getNamespaceBindingUpdates(ctx, role, NewResourceIdFromNamespacedName(m.ClusterId, binding), principalIds, updates)
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

// Given a Role and a corresponding Kube RoleBinding, generate binding updates and append them to the provided slice.
func (m *KubeRbacToKessel) getNamespaceBindingUpdates(ctx context.Context, role *rbacv1.Role, kubeBindingId *ResourceId, principals []string, updates []*spicedbv1.RelationshipUpdate) ([]*spicedbv1.RelationshipUpdate, error) {
	log := logf.FromContext(ctx)

	roleResourceId := NewResourceIdFromNamespacedName(m.ClusterId, role)

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
		updates = append(updates, &spicedbv1.RelationshipUpdate{
			Operation: spicedbv1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &spicedbv1.Relationship{
				Resource: &spicedbv1.ObjectReference{
					ObjectType: "kubernetes/role_binding",
					ObjectId:   kubeBindingId.String(),
				},
				Relation: "t_rbac_binding",
				Subject: &spicedbv1.SubjectReference{
					Object: &spicedbv1.ObjectReference{
						ObjectType: "rbac/role_binding",
						ObjectId:   rbacBindingId,
					},
				},
			},
		}, &spicedbv1.RelationshipUpdate{
			// Now also track from the kube role to the binding,
			// so we can traverse from the kube role to rbac bindings
			Operation: spicedbv1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &spicedbv1.Relationship{
				Resource: &spicedbv1.ObjectReference{
					ObjectType: "kubernetes/role",
					ObjectId:   roleResourceId.String(),
				},
				Relation: "t_role_binding",
				Subject: &spicedbv1.SubjectReference{
					Object: &spicedbv1.ObjectReference{
						ObjectType: "kubernetes/role_binding",
						ObjectId:   kubeBindingId.String(),
					},
				},
			},
		})

		// Create a relationship from the resource(s) to this binding
		// Where a role gets bound in RBAC depends on:
		// - the referenced role's rule's resource names
		// - the role binding's namespace
		// ...in that order.
		// What is the resource? The namespace, unless the rule has any resource names.
		// TODO: support resource names, for now assume namespace only
		// In that case, it may result in multiple relationships to the same binding.
		resourceType := "kubernetes/knamespace"
		resourceId := fmt.Sprintf("%s/%s", m.ClusterId, kubeBindingId.Namespace)

		updates = append(updates, &spicedbv1.RelationshipUpdate{
			Operation: spicedbv1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &spicedbv1.Relationship{
				Resource: &spicedbv1.ObjectReference{
					ObjectType: resourceType,
					ObjectId:   resourceId,
				},
				Relation: "t_role_binding",
				Subject: &spicedbv1.SubjectReference{
					Object: &spicedbv1.ObjectReference{
						ObjectType: "rbac/role_binding",
						ObjectId:   rbacBindingId,
					},
				},
			},
		})

		// Create a relationship from the binding to the role-rule
		updates = append(updates, &spicedbv1.RelationshipUpdate{
			Operation: spicedbv1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &spicedbv1.Relationship{
				Resource: &spicedbv1.ObjectReference{
					ObjectType: "rbac/role_binding",
					ObjectId:   rbacBindingId,
				},
				Relation: "t_role",
				Subject: &spicedbv1.SubjectReference{
					Object: &spicedbv1.ObjectReference{
						ObjectType: "rbac/role",
						ObjectId:   roleResourceId.WithSegment(rI),
					},
				},
			},
		})

		// Create relationships from the binding to each subject
		for _, principalId := range principals {
			updates = append(updates, &spicedbv1.RelationshipUpdate{
				Operation: spicedbv1.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &spicedbv1.Relationship{
					Resource: &spicedbv1.ObjectReference{
						ObjectType: "rbac/role_binding",
						ObjectId:   rbacBindingId,
					},
					Relation: "t_subject",
					Subject: &spicedbv1.SubjectReference{
						Object: &spicedbv1.ObjectReference{
							ObjectType: "rbac/principal",
							ObjectId:   principalId,
						},
					},
				},
			})
		}
	}

	return updates, nil
}

func (m *KubeRbacToKessel) MapClusterRole(ctx context.Context, clusterRole *rbacv1.ClusterRole) error {
	log := logf.FromContext(ctx)
	log.Info("Mapping ClusterRole", "name", clusterRole.Name)

	// Implement mapping logic here
	// For now, we just log it
	log.Info("ClusterRole mapping not implemented yet", "name", clusterRole.Name)
	return nil
}

func (m *KubeRbacToKessel) MapClusterRoleBinding(ctx context.Context, clusterRoleBinding *rbacv1.ClusterRoleBinding) error {
	log := logf.FromContext(ctx)
	log.Info("Mapping ClusterRoleBinding", "name", clusterRoleBinding.Name)
	// Implement mapping logic here
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
