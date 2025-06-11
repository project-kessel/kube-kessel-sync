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
	"log"
	"os"

	spicedbv1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	spicedb "github.com/authzed/authzed-go/v1"
)

// InMemoryKesselSink is an in-memory implementation of the [KubeObjectSink] interface,
// which directly forwards the data to a mapper in memory,
// as opposed to a separate queue.
type InMemoryKesselSink struct {
	mapper *KubeRbacToKessel
}

func NewInMemoryKesselSink(mapper *KubeRbacToKessel) *InMemoryKesselSink {
	return &InMemoryKesselSink{mapper: mapper}
}

func (s *InMemoryKesselSink) ObjectAddedOrChanged(ctx context.Context, obj client.Object) error {
	log := logf.FromContext(ctx)

	switch o := obj.(type) {
	case *rbacv1.Role:
		s.mapper.MapRole(ctx, o)
	case *rbacv1.RoleBinding:
		s.mapper.MapRoleBinding(ctx, o)
	case *rbacv1.ClusterRole:
		s.mapper.MapClusterRole(ctx, o)
	case *rbacv1.ClusterRoleBinding:
		s.mapper.MapClusterRoleBinding(ctx, o)
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

func (s *InMemoryKesselSink) ObjectDeleted(ctx context.Context, obj client.Object) error {
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

type ObjectHistory interface {
	WhatChanged(ctx context.Context, obj client.Object) (removed, added client.Object, err error)
}

var fullyConsistent = &spicedbv1.Consistency{
	Requirement: &spicedbv1.Consistency_FullyConsistent{},
}

// TODO: kessel, but simplifying for POC
type KubeRbacToKessel struct {
	ClusterId string
	Kube      client.Client
	SpiceDb   *spicedb.Client
	// Experimental idea, not used currently
	History ObjectHistory
}

func (m *KubeRbacToKessel) SetUpSchema(ctx context.Context) error {
	// load schema from file baked into image
	schemaBytes, err := os.ReadFile("config/schema.zed")
	if err != nil {
		log.Fatalf("unable to read schema file: %v", err)
	}
	schema := string(schemaBytes)

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

	// Delete all previous permission relations
	// This is not atomic, because it requires its own request.
	// That means there is a period of (potentially arbitrary) time where
	// the Role has no permissions, resulting in lost access.
	// It also results in lots of extra unwanted snapshots in spicedb.
	// This is all not good for a production solution, but okay for POC.

	// TODO: Get current relationships for the role, diff, and add/remove
	// This read-modify-write cycle would require fencing (e.g. precondition on lock tuple)
	// but would be atomic & consistent in that case.
	// With Kessel this is the same except just at a Resource level
	// (e.g. query on some kube_role_id attribute vs resource ID prefix)
	// and some of the lower level stuff is taken care of for you.

	res, err := m.SpiceDb.DeleteRelationships(ctx, &spicedbv1.DeleteRelationshipsRequest{
		RelationshipFilter: &spicedbv1.RelationshipFilter{
			ResourceType: "rbac/role",
			// Use a prefix so that it matches ALL role-rules
			// We do not know how many there were before, so we cannot delete by ID.
			OptionalResourceIdPrefix: fmt.Sprintf("%s/%s/%s", m.ClusterId, role.Namespace, role.Name),
		},
	})
	if err != nil {
		log.Error(err, "Failed to delete previous relationships for Role", "name", role.Name, "namespace", role.Namespace)
		return fmt.Errorf("failed to delete previous relationships for Role %s/%s: %w", role.Namespace, role.Name, err)
	}
	log.Info("Deleted previous relationships for Role", "name", role.Name, "namespace", role.Namespace, "deletedCount", res.RelationshipsDeletedCount)

	// Each Role-Rule gets mapped to a RBAC Role (set of permissions)
	// We could group by resource name to reduce total RBAC Roles if desired
	for rI, rule := range role.Rules {
		log.Info("Processing added Role Rule", "apiGroups", rule.APIGroups, "resources", rule.Resources, "verbs", rule.Verbs)

		// ID the RBAC Role after the role's kube cluster, namespace, role name,
		// and the rule's index within the Role.
		roleId := fmt.Sprintf("%s/%s/%s/%d", role.Namespace, role.Name, rI)

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

	updates := []*spicedbv1.RelationshipUpdate{}

	// For each rule in the role, create a binding to that RBAC role.
	// Then, attach each subject to that binding.
	// We explode the binding into a binding per role-rule combination, because each role-rule
	// maybe have a different target resource, due to resource name being a property of the rule.
	for rI, rule := range role.Rules {
		log.Info("Processing Role Rule", "apiGroups", rule.APIGroups, "resources", rule.Resources, "verbs", rule.Verbs)

		// ID the RoleBinding after the role's kube cluster, namespace, role name,
		// and the rule's index within the Role.
		bindingId := fmt.Sprintf("%s/%s/%s/%d", m.ClusterId, binding.Namespace, binding.Name, rI)

		// Track that this binding relates to the kubernetes binding so we can find it on updates.
		// See: deleteBindingRelationships
		updates = append(updates, &spicedbv1.RelationshipUpdate{
			Operation: spicedbv1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &spicedbv1.Relationship{
				Resource: &spicedbv1.ObjectReference{
					ObjectType: "kubernetes/role_binding",
					ObjectId:   fmt.Sprintf("%s/%s/%s", m.ClusterId, binding.Namespace, binding.Name),
				},
				Relation: "t_role_binding",
				Subject: &spicedbv1.SubjectReference{
					Object: &spicedbv1.ObjectReference{
						ObjectType: "rbac/role_binding",
						ObjectId:   bindingId,
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
		resourceId := fmt.Sprintf("%s/%s/%s", m.ClusterId, binding.Namespace, binding.Name)

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
						ObjectId:   bindingId,
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
					ObjectId:   bindingId,
				},
				Relation: "t_role",
				Subject: &spicedbv1.SubjectReference{
					Object: &spicedbv1.ObjectReference{
						ObjectType: "rbac/role",
						ObjectId:   fmt.Sprintf("%s/%s/%s/%d", m.ClusterId, role.Namespace, role.Name, rI),
					},
				},
			},
		})

		// Create relationships from the binding to each subject
		for _, subject := range binding.Subjects {
			updates = append(updates, &spicedbv1.RelationshipUpdate{
				Operation: spicedbv1.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &spicedbv1.Relationship{
					Resource: &spicedbv1.ObjectReference{
						ObjectType: "rbac/role_binding",
						ObjectId:   bindingId,
					},
					Relation: "t_subject",
					Subject: &spicedbv1.SubjectReference{
						Object: &spicedbv1.ObjectReference{
							ObjectType: "rbac/principal",
							// TODO: rethink principal identifiers for kubernetes principals
							ObjectId: fmt.Sprintf("kubernetes/%s", subject.Name),
						},
					},
				},
			})
		}
	}

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
					OptionalResourceId: "kube/" + binding.Namespace + "/" + binding.Name,
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

func (m *KubeRbacToKessel) MapClusterRoleBinding(ctx context.Context, clusterRoleBinding *rbacv1.ClusterRoleBinding) error {
	log := logf.FromContext(ctx)
	log.Info("Mapping ClusterRoleBinding", "name", clusterRoleBinding.Name)
	// Implement mapping logic here
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
