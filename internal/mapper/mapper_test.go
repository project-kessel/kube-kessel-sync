package mapper_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"github.com/ory/dockertest/v3"
	"github.com/project-kessel/kube-kessel-sync/internal/mapper"
	"github.com/project-kessel/kube-kessel-sync/internal/streamutil"
	"github.com/project-kessel/kube-kessel-sync/internal/testutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func TestMapper(t *testing.T) {
	var err error
	ctx := context.Background()

	port, err := runSpiceDBTestServer(t)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("namespace bindings", func(t *testing.T) {
		t.Run("grant access when role and binding created", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			role := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "test-namespace",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get"}, //, "list", "create", "update"},
					},
				},
			}
			binding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "test-namespace",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "Role",
					Name:     role.Name,
				},
			}

			// By the time add or changed is called, it's already in the cluster.
			kube.AddOrReplace(role)
			kube.AddOrReplace(binding)

			k2k.ObjectAddedOrChanged(ctx, role)
			k2k.ObjectAddedOrChanged(ctx, binding)

			// Given a new role and binding, ensure the user has access to the namespace
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_get",
				"rbac/principal", "kubernetes/test-user")
		})

		t.Run("update access when role is updated", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			role := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "test-namespace",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get"}, //, "list", "create", "update"},
					},
				},
			}
			binding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "test-namespace",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "Role",
					Name:     role.Name,
				},
			}

			kube.AddOrReplace(role)
			kube.AddOrReplace(binding)

			k2k.ObjectAddedOrChanged(ctx, role)
			k2k.ObjectAddedOrChanged(ctx, binding)

			role.Rules[0].Verbs = append(role.Rules[0].Verbs, "list")
			kube.AddOrReplace(role)
			k2k.ObjectAddedOrChanged(ctx, role)

			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_list",
				"rbac/principal", "kubernetes/test-user")
		})

		t.Run("does not grant access to other resources", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			role := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "test-namespace",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get"}, //, "list", "create", "update"},
					},
				},
			}
			binding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "test-namespace",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "Role",
					Name:     role.Name,
				},
			}
			kube.AddOrReplace(role)
			kube.AddOrReplace(binding)
			k2k.ObjectAddedOrChanged(ctx, role)
			k2k.ObjectAddedOrChanged(ctx, binding)

			// Given a new role and binding, ensure the user doesn't have access to things not granted
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_list",
				"rbac/principal", "kubernetes/test-user")
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/test-user")
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/other-namespace", "pods_get",
				"rbac/principal", "kubernetes/test-user")
		})

		// Given a new role and binding, ensure a different user doesn't have access
		t.Run("does not grant access to other subjects when role an binding created", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			role := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "test-namespace",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get"}, //, "list", "create", "update"},
					},
				},
			}
			binding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "test-namespace",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "Role",
					Name:     role.Name,
				},
			}

			// By the time add or changed is called, it's already in the cluster.
			kube.AddOrReplace(role)
			kube.AddOrReplace(binding)

			k2k.ObjectAddedOrChanged(ctx, role)
			k2k.ObjectAddedOrChanged(ctx, binding)

			// Given a new role and binding, ensure the user has access to the namespace
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_get",
				"rbac/principal", "kubernetes/test-user-2")
		})

		t.Run("removes access when role binding is deleted", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			role := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "test-namespace",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get", "list"},
					},
				},
			}
			binding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "test-namespace",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "Role",
					Name:     role.Name,
				},
			}

			kube.AddOrReplace(role)
			kube.AddOrReplace(binding)

			k2k.ObjectAddedOrChanged(ctx, role)
			k2k.ObjectAddedOrChanged(ctx, binding)

			// Verify user has access initially
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_get",
				"rbac/principal", "kubernetes/test-user")
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_list",
				"rbac/principal", "kubernetes/test-user")

			// Remove the role binding
			kube.Remove(client.ObjectKey{
				Name:      binding.Name,
				Namespace: binding.Namespace,
			}, binding)
			k2k.ObjectDeleted(ctx, binding)

			// Verify user no longer has access
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_get",
				"rbac/principal", "kubernetes/test-user")
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_list",
				"rbac/principal", "kubernetes/test-user")

			// Verify no relationships remain for the kube binding or rbac bindings
			// Since this was the only binding, there should be no relationships left
			kubeBindingCount := countTotalRelationships(t, ctx, spicedb, "kubernetes/role_binding")
			if kubeBindingCount != 0 {
				t.Errorf("Expected 0 relationships for kubernetes/role_binding after RoleBinding deletion, got %d", kubeBindingCount)
			}

			rbacBindingCount := countTotalRelationships(t, ctx, spicedb, "rbac/role_binding")
			if rbacBindingCount != 0 {
				t.Errorf("Expected 0 relationships for rbac/role_binding after RoleBinding deletion, got %d", rbacBindingCount)
			}
		})

		// New tests: RoleBinding referencing a ClusterRole
		// ------------------------------------------------
		// A RoleBinding may reference a ClusterRole. According to Kubernetes semantics, such a
		// RoleBinding confers the ClusterRole's permissions, but scoped to the RoleBinding's
		// namespace. The following tests ensure that the mapper implements this behaviour.

		// Given a ClusterRole and a namespaced RoleBinding that references it, ensure the
		// subject receives the ClusterRole's permissions in the binding's namespace, and
		// NOT in other namespaces.
		t.Run("rolebinding with clusterrole ref grants namespace access only", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			// Namespaces that will exist in the cluster
			testNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}}
			otherNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "other-namespace"}}
			kube.AddOrReplace(testNamespace)
			kube.AddOrReplace(otherNamespace)
			k2k.ObjectAddedOrChanged(ctx, testNamespace)
			k2k.ObjectAddedOrChanged(ctx, otherNamespace)

			// ClusterRole granting pod get/list
			clusterRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cluster-role"},
				Rules: []rbacv1.PolicyRule{{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get", "list"},
				}},
			}

			// Namespaced RoleBinding referencing the ClusterRole
			binding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "test-namespace",
				},
				Subjects: []rbacv1.Subject{{Kind: "User", Name: "test-user"}},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     clusterRole.Name,
				},
			}

			// Load objects into fake kube and trigger mapping
			kube.AddOrReplace(clusterRole)
			kube.AddOrReplace(binding)
			k2k.ObjectAddedOrChanged(ctx, clusterRole)
			k2k.ObjectAddedOrChanged(ctx, binding)

			// Expect access in the RoleBinding's namespace
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_get",
				"rbac/principal", "kubernetes/test-user")
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_list",
				"rbac/principal", "kubernetes/test-user")

			// Expect NO access in a different namespace
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/other-namespace", "pods_get",
				"rbac/principal", "kubernetes/test-user")
		})

		// Given a ClusterRole with resource names and a namespaced RoleBinding referencing it,
		// ensure access is granted to the specific resource in the binding's namespace only.
		t.Run("rolebinding with clusterrole ref and resource names grants namespaced resource access", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			// Namespaces
			testNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}}
			otherNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "other-namespace"}}
			kube.AddOrReplace(testNamespace)
			kube.AddOrReplace(otherNamespace)
			k2k.ObjectAddedOrChanged(ctx, testNamespace)
			k2k.ObjectAddedOrChanged(ctx, otherNamespace)

			// ClusterRole granting get/update on a specific configmap name
			clusterRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "configmap-reader"},
				Rules: []rbacv1.PolicyRule{{
					APIGroups:     []string{""},
					Resources:     []string{"configmaps"},
					Verbs:         []string{"get", "update"},
					ResourceNames: []string{"special-config"},
				}},
			}

			binding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "configmap-reader-binding",
					Namespace: "test-namespace",
				},
				Subjects: []rbacv1.Subject{{Kind: "User", Name: "test-user"}},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     clusterRole.Name,
				},
			}

			kube.AddOrReplace(clusterRole)
			kube.AddOrReplace(binding)
			k2k.ObjectAddedOrChanged(ctx, clusterRole)
			k2k.ObjectAddedOrChanged(ctx, binding)

			// Expect access to the specific configmap in the binding's namespace
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/special-config", "get",
				"rbac/principal", "kubernetes/test-user")
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/special-config", "update",
				"rbac/principal", "kubernetes/test-user")

			// Expect NO access to the same-named resource in other namespace
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/other-namespace/special-config", "get",
				"rbac/principal", "kubernetes/test-user")

			// Expect NO namespace-level access even in binding namespace
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/test-user")
		})
	})

	t.Run("resource bindings", func(t *testing.T) {
		// Given a new role with resource name and binding, ensure the user has access to that resource
		t.Run("grant access to resource when role and binding created", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			role := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "test-namespace",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups:     []string{""},
						Resources:     []string{"configmaps"},
						Verbs:         []string{"get"}, //, "list", "create", "update"},
						ResourceNames: []string{"test-configmap"},
					},
				},
			}
			binding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "test-namespace",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "Role",
					Name:     role.Name,
				},
			}

			// By the time add or changed is called, it's already in the cluster.
			kube.AddOrReplace(role)
			kube.AddOrReplace(binding)

			k2k.ObjectAddedOrChanged(ctx, role)
			k2k.ObjectAddedOrChanged(ctx, binding)

			// Given a new role and binding, ensure the user has access to the namespace
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/test-configmap", "get",
				"rbac/principal", "kubernetes/test-user")
		})

		// Given a role with resource name, ensure the user doesn't have access to the namespace
		t.Run("deny access to namespace when role has resource name", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			role := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "test-namespace",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups:     []string{""},
						Resources:     []string{"configmaps"},
						Verbs:         []string{"get"},
						ResourceNames: []string{"test-configmap"},
					},
				},
			}
			binding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "test-namespace",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "Role",
					Name:     role.Name,
				},
			}

			kube.AddOrReplace(role)
			kube.AddOrReplace(binding)

			k2k.ObjectAddedOrChanged(ctx, role)
			k2k.ObjectAddedOrChanged(ctx, binding)

			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/test-user")
		})

		// Given a role update which adds a resource name, ensure user has access to the resource
		t.Run("moves access from namespace to resource when resourcename added to role", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			role := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "test-namespace",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get", "update"},
					},
				},
			}
			binding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "test-namespace",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "Role",
					Name:     role.Name,
				},
			}

			kube.AddOrReplace(role)
			kube.AddOrReplace(binding)

			k2k.ObjectAddedOrChanged(ctx, role)
			k2k.ObjectAddedOrChanged(ctx, binding)

			// Add a resource name to the role
			role.Rules[0].ResourceNames = []string{"test-pod"}

			kube.AddOrReplace(role)
			k2k.ObjectAddedOrChanged(ctx, role)

			assertAccess(t, ctx, spicedb,
				"kubernetes/pod", "test-cluster/test-namespace/test-pod", "update",
				"rbac/principal", "kubernetes/test-user")
		})

		t.Run("role update with resource name removes namespace access", func(t *testing.T) {
			spicedb, kube, k2k := setupTest(ctx, t, port)

			role := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "test-namespace",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get", "update"},
					},
				},
			}
			binding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "test-namespace",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "Role",
					Name:     role.Name,
				},
			}

			kube.AddOrReplace(role)
			kube.AddOrReplace(binding)

			k2k.ObjectAddedOrChanged(ctx, role)
			k2k.ObjectAddedOrChanged(ctx, binding)

			// Verify user has access to namespace-level resources initially
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_update",
				"rbac/principal", "kubernetes/test-user")

			// Add a resource name to the role, which should restrict access to only that specific resource
			role.Rules[0].ResourceNames = []string{"test-pod"}

			kube.AddOrReplace(role)
			k2k.ObjectAddedOrChanged(ctx, role)

			// Verify user no longer has access to namespace-level resources
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_update",
				"rbac/principal", "kubernetes/test-user")

			// Verify user still has access to the specific resource
			assertAccess(t, ctx, spicedb,
				"kubernetes/pod", "test-cluster/test-namespace/test-pod", "update",
				"rbac/principal", "kubernetes/test-user")
		})

		t.Run("role update with different resource names revokes old access and grants new access", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			role := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "test-namespace",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups:     []string{""},
						Resources:     []string{"configmaps"},
						Verbs:         []string{"get"},
						ResourceNames: []string{"old-configmap"},
					},
				},
			}
			binding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "test-namespace",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "Role",
					Name:     role.Name,
				},
			}

			kube.AddOrReplace(role)
			kube.AddOrReplace(binding)

			k2k.ObjectAddedOrChanged(ctx, role)
			k2k.ObjectAddedOrChanged(ctx, binding)

			// Verify user has access to the initial resource name
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/old-configmap", "get",
				"rbac/principal", "kubernetes/test-user")

			// Verify user does not have access to namespace-level resources
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/test-user")

			// Update the role with different resource names
			role.Rules[0].ResourceNames = []string{"new-configmap"}

			kube.AddOrReplace(role)
			k2k.ObjectAddedOrChanged(ctx, role)

			// Verify user no longer has access to the old resource name
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/old-configmap", "get",
				"rbac/principal", "kubernetes/test-user")

			// Verify user now has access to the new resource name
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/new-configmap", "get",
				"rbac/principal", "kubernetes/test-user")

			// Verify user still does not have access to namespace-level resources
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/test-user")
		})

		t.Run("removes access when role binding is deleted for resource-level permissions", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			role := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "test-namespace",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups:     []string{""},
						Resources:     []string{"configmaps"},
						Verbs:         []string{"get", "update"},
						ResourceNames: []string{"test-configmap"},
					},
				},
			}
			binding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "test-namespace",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "Role",
					Name:     role.Name,
				},
			}

			kube.AddOrReplace(role)
			kube.AddOrReplace(binding)

			k2k.ObjectAddedOrChanged(ctx, role)
			k2k.ObjectAddedOrChanged(ctx, binding)

			// Verify user has access to the specific resource initially
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/test-configmap", "get",
				"rbac/principal", "kubernetes/test-user")
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/test-configmap", "update",
				"rbac/principal", "kubernetes/test-user")

			// Remove the role binding
			kube.Remove(client.ObjectKey{
				Name:      binding.Name,
				Namespace: binding.Namespace,
			}, binding)
			k2k.ObjectDeleted(ctx, binding)

			// Verify user no longer has access to the specific resource
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/test-configmap", "get",
				"rbac/principal", "kubernetes/test-user")
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/test-configmap", "update",
				"rbac/principal", "kubernetes/test-user")

			// Verify no relationships remain for the kube binding or rbac bindings
			// Since this was the only binding, there should be no relationships left
			kubeBindingCount := countTotalRelationships(t, ctx, spicedb, "kubernetes/role_binding")
			if kubeBindingCount != 0 {
				t.Errorf("Expected 0 relationships for kubernetes/role_binding after RoleBinding deletion, got %d", kubeBindingCount)
			}

			rbacBindingCount := countTotalRelationships(t, ctx, spicedb, "rbac/role_binding")
			if rbacBindingCount != 0 {
				t.Errorf("Expected 0 relationships for rbac/role_binding after RoleBinding deletion, got %d", rbacBindingCount)
			}
		})
	})

	t.Run("cluster bindings", func(t *testing.T) {
		// Given a new cluster role with binding, ensure the user has access to all namespaces in the cluster
		t.Run("grant access to all namespaces when cluster role and binding created", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			// Create namespace objects first so they exist in the system
			testNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
				},
			}
			anotherNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "another-namespace",
				},
			}

			kube.AddOrReplace(testNamespace)
			kube.AddOrReplace(anotherNamespace)

			// Ensure namespace objects are mapped
			k2k.ObjectAddedOrChanged(ctx, testNamespace)
			k2k.ObjectAddedOrChanged(ctx, anotherNamespace)

			clusterRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get", "list"},
					},
				},
			}
			clusterBinding := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-binding",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     clusterRole.Name,
				},
			}

			kube.AddOrReplace(clusterRole)
			kube.AddOrReplace(clusterBinding)

			k2k.ObjectAddedOrChanged(ctx, clusterRole)
			k2k.ObjectAddedOrChanged(ctx, clusterBinding)

			// Given a new cluster role and binding, ensure the user has access to all namespaces
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_get",
				"rbac/principal", "kubernetes/test-user")
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/another-namespace", "pods_list",
				"rbac/principal", "kubernetes/test-user")
		})

		// Given a cluster role with resource names, ensure the user has access to resources with that name in any namespace
		t.Run("grant access to resources with specific names across all namespaces", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			// Create namespaces first
			testNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
				},
			}
			anotherNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "another-namespace",
				},
			}
			kube.AddOrReplace(testNamespace)
			kube.AddOrReplace(anotherNamespace)
			k2k.ObjectAddedOrChanged(ctx, testNamespace)
			k2k.ObjectAddedOrChanged(ctx, anotherNamespace)

			clusterRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups:     []string{""},
						Resources:     []string{"configmaps"},
						Verbs:         []string{"get", "update"},
						ResourceNames: []string{"test-configmap"},
					},
				},
			}
			clusterBinding := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-binding",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     clusterRole.Name,
				},
			}

			kube.AddOrReplace(clusterRole)
			kube.AddOrReplace(clusterBinding)

			k2k.ObjectAddedOrChanged(ctx, clusterRole)
			k2k.ObjectAddedOrChanged(ctx, clusterBinding)

			// Verify user has access to the specific resource in any namespace
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/test-configmap", "get",
				"rbac/principal", "kubernetes/test-user")
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/another-namespace/test-configmap", "update",
				"rbac/principal", "kubernetes/test-user")

			// Verify user doesn't have access to the namespace itself
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/test-user")
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/another-namespace", "configmaps_update",
				"rbac/principal", "kubernetes/test-user")

			// Verify user doesn't have access to other configmaps
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/other-configmap", "get",
				"rbac/principal", "kubernetes/test-user")
		})

		// Given a cluster role binding, ensure new namespaces added after the binding are also accessible
		t.Run("new namespaces added after cluster binding are accessible", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			// Create the original namespace and map it
			origNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
				},
			}
			kube.AddOrReplace(origNamespace)
			k2k.ObjectAddedOrChanged(ctx, origNamespace)

			clusterRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get", "list"},
					},
				},
			}
			clusterBinding := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-binding",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     clusterRole.Name,
				},
			}

			kube.AddOrReplace(clusterRole)
			kube.AddOrReplace(clusterBinding)
			k2k.ObjectAddedOrChanged(ctx, clusterRole)
			k2k.ObjectAddedOrChanged(ctx, clusterBinding)

			// Verify user has access to existing namespace
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_get",
				"rbac/principal", "kubernetes/test-user")

			// Simulate adding a new namespace after the cluster binding
			newNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "new-namespace",
				},
			}

			kube.AddOrReplace(newNamespace)
			k2k.ObjectAddedOrChanged(ctx, newNamespace)

			// Verify user has access to the new namespace
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/new-namespace", "pods_get",
				"rbac/principal", "kubernetes/test-user")
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/new-namespace", "pods_list",
				"rbac/principal", "kubernetes/test-user")
		})

		// Test clusterrole with resource names - new namespace should have access to matching resources
		t.Run("clusterrole with resource names - new namespace access", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			// Create initial namespace
			testNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
				},
			}
			kube.AddOrReplace(testNamespace)
			k2k.ObjectAddedOrChanged(ctx, testNamespace)

			// Create clusterrole with specific resource names
			clusterRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups:     []string{""},
						Resources:     []string{"configmaps"},
						Verbs:         []string{"get", "update"},
						ResourceNames: []string{"specific-configmap"},
					},
				},
			}
			clusterBinding := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-binding",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     clusterRole.Name,
				},
			}

			kube.AddOrReplace(clusterRole)
			kube.AddOrReplace(clusterBinding)
			k2k.ObjectAddedOrChanged(ctx, clusterRole)
			k2k.ObjectAddedOrChanged(ctx, clusterBinding)

			// Verify user has access to specific resource in existing namespace
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/specific-configmap", "get",
				"rbac/principal", "kubernetes/test-user")

			// Verify user does NOT have namespace-level access
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/test-user")

			// Simulate adding a new namespace after the cluster binding
			newNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "new-namespace",
				},
			}

			kube.AddOrReplace(newNamespace)
			k2k.ObjectAddedOrChanged(ctx, newNamespace)

			// Verify user has access to the specific resource in the new namespace
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/new-namespace/specific-configmap", "get",
				"rbac/principal", "kubernetes/test-user")

			// Verify user does NOT have namespace-level access in the new namespace
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/new-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/test-user")

			// Verify user does NOT have access to other configmaps in the new namespace
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/new-namespace/other-configmap", "get",
				"rbac/principal", "kubernetes/test-user")
		})

		// Test to demonstrate the prefix collision bug
		t.Run("clusterrole deletion should not affect namespaced role with same name", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			// Create namespace for the role
			testNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
				},
			}
			kube.AddOrReplace(testNamespace)
			k2k.ObjectAddedOrChanged(ctx, testNamespace)

			// 1. Add a role in namespace "test-namespace" with name "some-role"
			role := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-role",
					Namespace: "test-namespace",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get"},
					},
				},
			}
			binding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-binding",
					Namespace: "test-namespace",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "Role",
					Name:     role.Name,
				},
			}

			kube.AddOrReplace(role)
			kube.AddOrReplace(binding)
			k2k.ObjectAddedOrChanged(ctx, role)
			k2k.ObjectAddedOrChanged(ctx, binding)

			// 2. Verify the user has access from the namespaced role
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_get",
				"rbac/principal", "kubernetes/test-user")

			// 3. Add a clusterrole with name "test-namespace" (same as the namespace name)
			// This should NOT affect the namespaced role above
			clusterRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace", // Same name as the namespace
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"configmaps"},
						Verbs:     []string{"get"},
					},
				},
			}
			clusterBinding := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-binding",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "cluster-user",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     clusterRole.Name,
				},
			}

			kube.AddOrReplace(clusterRole)
			kube.AddOrReplace(clusterBinding)
			k2k.ObjectAddedOrChanged(ctx, clusterRole)
			k2k.ObjectAddedOrChanged(ctx, clusterBinding)

			// 4. Assert that the access from the first role is still granted
			// This should still work - the clusterrole should not have affected the namespaced role
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_get",
				"rbac/principal", "kubernetes/test-user")

			// 5. Also verify the clusterrole works for the cluster user
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/cluster-user")
		})

		// Test clusterrole transition from no resource names to resource names
		t.Run("clusterrole transition from no resource names to resource names", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			// Create namespaces
			testNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
				},
			}
			anotherNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "another-namespace",
				},
			}
			kube.AddOrReplace(testNamespace)
			kube.AddOrReplace(anotherNamespace)
			k2k.ObjectAddedOrChanged(ctx, testNamespace)
			k2k.ObjectAddedOrChanged(ctx, anotherNamespace)

			// 1. Create clusterrole with NO resource names (namespace-level access)
			clusterRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"configmaps"},
						Verbs:     []string{"get", "update"},
					},
				},
			}
			clusterBinding := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-binding",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     clusterRole.Name,
				},
			}

			kube.AddOrReplace(clusterRole)
			kube.AddOrReplace(clusterBinding)
			k2k.ObjectAddedOrChanged(ctx, clusterRole)
			k2k.ObjectAddedOrChanged(ctx, clusterBinding)

			// Verify user has namespace-level access to all configmaps
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/test-user")
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/another-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/test-user")
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_update",
				"rbac/principal", "kubernetes/test-user")

			// 2. Update clusterrole to ADD resource names
			clusterRole.Rules[0].ResourceNames = []string{"specific-configmap"}
			k2k.ObjectAddedOrChanged(ctx, clusterRole)

			// Verify user now has access to the specific resource only
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/specific-configmap", "get",
				"rbac/principal", "kubernetes/test-user")
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/another-namespace/specific-configmap", "get",
				"rbac/principal", "kubernetes/test-user")

			// Verify user NO LONGER has namespace-level access
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/test-user")
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/another-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/test-user")

			// Verify user doesn't have access to other configmaps
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/other-configmap", "get",
				"rbac/principal", "kubernetes/test-user")
		})

		// Test clusterrole transition from resource names to no resource names
		t.Run("clusterrole transition from resource names to no resource names", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			// Create namespaces
			testNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
				},
			}
			anotherNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "another-namespace",
				},
			}
			kube.AddOrReplace(testNamespace)
			kube.AddOrReplace(anotherNamespace)
			k2k.ObjectAddedOrChanged(ctx, testNamespace)
			k2k.ObjectAddedOrChanged(ctx, anotherNamespace)

			// 1. Create clusterrole WITH resource names (resource-level access)
			clusterRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups:     []string{""},
						Resources:     []string{"configmaps"},
						Verbs:         []string{"get", "update"},
						ResourceNames: []string{"specific-configmap"},
					},
				},
			}
			clusterBinding := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-binding",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     clusterRole.Name,
				},
			}

			kube.AddOrReplace(clusterRole)
			kube.AddOrReplace(clusterBinding)
			k2k.ObjectAddedOrChanged(ctx, clusterRole)
			k2k.ObjectAddedOrChanged(ctx, clusterBinding)

			// Verify user has resource-level access to specific configmap only
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/specific-configmap", "get",
				"rbac/principal", "kubernetes/test-user")
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/another-namespace/specific-configmap", "get",
				"rbac/principal", "kubernetes/test-user")

			// Verify user doesn't have namespace-level access
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/test-user")

			// 2. Update clusterrole to REMOVE resource names
			clusterRole.Rules[0].ResourceNames = nil
			k2k.ObjectAddedOrChanged(ctx, clusterRole)

			// Verify user now has namespace-level access to all configmaps
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/test-user")
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/another-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/test-user")
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_update",
				"rbac/principal", "kubernetes/test-user")

			// User does not have access to the specific resource anymore when checked directly,
			// clients must check through the namespace for this POC.
			// TODO: we could add an implicit relation to the namespace for the resource,
			//       and this would work
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/specific-configmap", "get",
				"rbac/principal", "kubernetes/test-user")
		})

		// Test that clusterrole changes only affect the changed clusterrole
		t.Run("clusterrole changes only affect the changed clusterrole", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			// Create namespace
			testNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
				},
			}
			kube.AddOrReplace(testNamespace)
			k2k.ObjectAddedOrChanged(ctx, testNamespace)

			// 1. Create first clusterrole with resource names
			clusterRole1 := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster-role-1",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups:     []string{""},
						Resources:     []string{"configmaps"},
						Verbs:         []string{"get"},
						ResourceNames: []string{"config-1"},
					},
				},
			}
			clusterBinding1 := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster-binding-1",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "user-1",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     clusterRole1.Name,
				},
			}

			// 2. Create second clusterrole with different resource names
			clusterRole2 := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster-role-2",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups:     []string{""},
						Resources:     []string{"configmaps"},
						Verbs:         []string{"get"},
						ResourceNames: []string{"config-2"},
					},
				},
			}
			clusterBinding2 := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster-binding-2",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "user-2",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     clusterRole2.Name,
				},
			}

			// Create both cluster roles and bindings
			kube.AddOrReplace(clusterRole1)
			kube.AddOrReplace(clusterBinding1)
			kube.AddOrReplace(clusterRole2)
			kube.AddOrReplace(clusterBinding2)
			k2k.ObjectAddedOrChanged(ctx, clusterRole1)
			k2k.ObjectAddedOrChanged(ctx, clusterBinding1)
			k2k.ObjectAddedOrChanged(ctx, clusterRole2)
			k2k.ObjectAddedOrChanged(ctx, clusterBinding2)

			// Verify both users have access to their respective resources
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/config-1", "get",
				"rbac/principal", "kubernetes/user-1")
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/config-2", "get",
				"rbac/principal", "kubernetes/user-2")

			// 3. Update only the first clusterrole to change its resource names
			clusterRole1.Rules[0].ResourceNames = []string{"config-1-updated"}
			k2k.ObjectAddedOrChanged(ctx, clusterRole1)

			// Verify user-1 now has access to the updated resource
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/config-1-updated", "get",
				"rbac/principal", "kubernetes/user-1")

			// Verify user-1 no longer has access to the old resource
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/config-1", "get",
				"rbac/principal", "kubernetes/user-1")

			// Verify user-2 still has access to their resource (unchanged)
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/config-2", "get",
				"rbac/principal", "kubernetes/user-2")

			// Verify users don't have access to each other's resources
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/config-1-updated", "get",
				"rbac/principal", "kubernetes/user-2")
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/config-2", "get",
				"rbac/principal", "kubernetes/user-1")
		})

		// Test clusterrole resource names change
		t.Run("clusterrole resource names change", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			// Create namespaces
			testNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
				},
			}
			anotherNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "another-namespace",
				},
			}
			kube.AddOrReplace(testNamespace)
			kube.AddOrReplace(anotherNamespace)
			k2k.ObjectAddedOrChanged(ctx, testNamespace)
			k2k.ObjectAddedOrChanged(ctx, anotherNamespace)

			// 1. Create clusterrole with initial resource names
			clusterRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups:     []string{""},
						Resources:     []string{"configmaps"},
						Verbs:         []string{"get", "update"},
						ResourceNames: []string{"old-configmap"},
					},
				},
			}
			clusterBinding := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-binding",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     clusterRole.Name,
				},
			}

			kube.AddOrReplace(clusterRole)
			kube.AddOrReplace(clusterBinding)
			k2k.ObjectAddedOrChanged(ctx, clusterRole)
			k2k.ObjectAddedOrChanged(ctx, clusterBinding)

			// Verify user has access to the old resource
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/old-configmap", "get",
				"rbac/principal", "kubernetes/test-user")
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/another-namespace/old-configmap", "get",
				"rbac/principal", "kubernetes/test-user")

			// Verify user doesn't have access to the new resource yet
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/new-configmap", "get",
				"rbac/principal", "kubernetes/test-user")

			// 2. Update clusterrole to change resource names
			clusterRole.Rules[0].ResourceNames = []string{"new-configmap"}
			k2k.ObjectAddedOrChanged(ctx, clusterRole)

			// Verify user now has access to the new resource
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/new-configmap", "get",
				"rbac/principal", "kubernetes/test-user")
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/another-namespace/new-configmap", "get",
				"rbac/principal", "kubernetes/test-user")

			// Verify user NO LONGER has access to the old resource
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/old-configmap", "get",
				"rbac/principal", "kubernetes/test-user")
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/another-namespace/old-configmap", "get",
				"rbac/principal", "kubernetes/test-user")

			// Verify user doesn't have namespace-level access
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/test-user")
		})

		// Deleting a ClusterRole with multiple bindings cleans up all access
		t.Run("cluster role deletion revokes access for multiple bindings", func(t *testing.T) {
			spicedb, kube, k2k := setupTest(ctx, t, port)

			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}}
			kube.AddOrReplace(ns)
			k2k.ObjectAddedOrChanged(ctx, ns)

			clusterRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cluster-role"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
			}
			binding1 := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "binding-1"},
				Subjects:   []rbacv1.Subject{{Kind: "User", Name: "user-1"}},
				RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: clusterRole.Name},
			}
			binding2 := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "binding-2"},
				Subjects:   []rbacv1.Subject{{Kind: "User", Name: "user-2"}},
				RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: clusterRole.Name},
			}

			kube.AddOrReplace(clusterRole)
			kube.AddOrReplace(binding1)
			kube.AddOrReplace(binding2)
			k2k.ObjectAddedOrChanged(ctx, clusterRole)
			k2k.ObjectAddedOrChanged(ctx, binding1)
			k2k.ObjectAddedOrChanged(ctx, binding2)

			// Verify access for both users
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_get",
				"rbac/principal", "kubernetes/user-1")
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_get",
				"rbac/principal", "kubernetes/user-2")

			k2k.ObjectDeleted(ctx, clusterRole)

			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_get",
				"rbac/principal", "kubernetes/user-1")
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_get",
				"rbac/principal", "kubernetes/user-2")

			for _, rt := range []string{"kubernetes/role", "kubernetes/role_binding", "rbac/role", "rbac/role_binding"} {
				if c := countTotalRelationships(t, ctx, spicedb, rt); c != 0 {
					t.Errorf("Expected 0 relationships for %s after deletion, got %d", rt, c)
				}
			}
		})

		// Test ClusterRole transition from no resource names to resource names with RoleBinding
		t.Run("cluster role transition from no resource names to resource names with role binding", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			// Create namespace
			testNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"},
			}
			kube.AddOrReplace(testNamespace)
			k2k.ObjectAddedOrChanged(ctx, testNamespace)

			// 1. Create ClusterRole with NO resource names (namespace-level access)
			clusterRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cluster-role"},
				Rules: []rbacv1.PolicyRule{{
					APIGroups: []string{""},
					Resources: []string{"configmaps"},
					Verbs:     []string{"get", "update"},
				}},
			}
			// Use a RoleBinding (not ClusterRoleBinding) that references the ClusterRole
			roleBinding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role-binding",
					Namespace: "test-namespace",
				},
				Subjects: []rbacv1.Subject{{Kind: "User", Name: "test-user"}},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     clusterRole.Name,
				},
			}

			kube.AddOrReplace(clusterRole)
			kube.AddOrReplace(roleBinding)
			k2k.ObjectAddedOrChanged(ctx, clusterRole)
			k2k.ObjectAddedOrChanged(ctx, roleBinding)

			// Verify user has namespace-level access to configmaps in the binding's namespace only
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/test-user")
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_update",
				"rbac/principal", "kubernetes/test-user")

			// 2. Update ClusterRole to ADD resource names
			clusterRole.Rules[0].ResourceNames = []string{"specific-configmap"}
			k2k.ObjectAddedOrChanged(ctx, clusterRole)

			// Verify user now has access to the specific resource only in the binding's namespace
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/specific-configmap", "get",
				"rbac/principal", "kubernetes/test-user")
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/specific-configmap", "update",
				"rbac/principal", "kubernetes/test-user")

			// Verify user NO LONGER has namespace-level access
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/test-user")
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_update",
				"rbac/principal", "kubernetes/test-user")

			// Verify user doesn't have access to other configmaps
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/other-configmap", "get",
				"rbac/principal", "kubernetes/test-user")
		})

		// Test ClusterRole transition from resource names to no resource names with RoleBinding
		t.Run("cluster role transition from resource names to no resource names with role binding", func(t *testing.T) {
			t.Parallel()

			spicedb, kube, k2k := setupTest(ctx, t, port)

			// Create namespace
			testNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"},
			}
			kube.AddOrReplace(testNamespace)
			k2k.ObjectAddedOrChanged(ctx, testNamespace)

			// 1. Create ClusterRole with resource names (resource-level access)
			clusterRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cluster-role"},
				Rules: []rbacv1.PolicyRule{{
					APIGroups:     []string{""},
					Resources:     []string{"configmaps"},
					Verbs:         []string{"get", "update"},
					ResourceNames: []string{"specific-configmap"},
				}},
			}
			// Use a RoleBinding (not ClusterRoleBinding) that references the ClusterRole
			roleBinding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role-binding",
					Namespace: "test-namespace",
				},
				Subjects: []rbacv1.Subject{{Kind: "User", Name: "test-user"}},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     clusterRole.Name,
				},
			}

			kube.AddOrReplace(clusterRole)
			kube.AddOrReplace(roleBinding)
			k2k.ObjectAddedOrChanged(ctx, clusterRole)
			k2k.ObjectAddedOrChanged(ctx, roleBinding)

			// Verify user has access to the specific resource only in the binding's namespace
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/specific-configmap", "get",
				"rbac/principal", "kubernetes/test-user")
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/specific-configmap", "update",
				"rbac/principal", "kubernetes/test-user")

			// Verify user does not have namespace-level access
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/test-user")

			// 2. Update ClusterRole to REMOVE resource names
			clusterRole.Rules[0].ResourceNames = nil
			k2k.ObjectAddedOrChanged(ctx, clusterRole)

			// Verify user now has namespace-level access to configmaps in the binding's namespace
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_get",
				"rbac/principal", "kubernetes/test-user")
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "configmaps_update",
				"rbac/principal", "kubernetes/test-user")

			// Verify user no longer has direct access to the specific resource
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/specific-configmap", "get",
				"rbac/principal", "kubernetes/test-user")
		})

		t.Run("clusterrole deletion with resource names cleans up all relationships", func(t *testing.T) {
			spicedb, kube, k2k := setupTest(ctx, t, port)

			// Create namespace so that namespace-specific resource bindings are generated
			namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}}
			kube.AddOrReplace(namespace)
			k2k.ObjectAddedOrChanged(ctx, namespace)

			// 1. Create ClusterRole with resource names (resource-level access)
			clusterRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cluster-role"},
				Rules: []rbacv1.PolicyRule{{
					APIGroups:     []string{""},
					Resources:     []string{"configmaps"},
					Verbs:         []string{"get"},
					ResourceNames: []string{"specific-configmap"},
				}},
			}
			// ClusterRoleBinding referencing the ClusterRole
			clusterBinding := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cluster-binding"},
				Subjects:   []rbacv1.Subject{{Kind: "User", Name: "test-user"}},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     clusterRole.Name,
				},
			}

			kube.AddOrReplace(clusterRole)
			kube.AddOrReplace(clusterBinding)
			k2k.ObjectAddedOrChanged(ctx, clusterRole)
			k2k.ObjectAddedOrChanged(ctx, clusterBinding)

			// Sanity check: user has access to the specific configmap
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/specific-configmap", "get",
				"rbac/principal", "kubernetes/test-user")

			// 2. Delete the ClusterRole
			k2k.ObjectDeleted(ctx, clusterRole)

			// Verify access is revoked
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/specific-configmap", "get",
				"rbac/principal", "kubernetes/test-user")

			// 3. Ensure no relationships remain for the relevant resource types
			resourceTypes := []string{"kubernetes/role", "kubernetes/role_binding", "rbac/role", "rbac/role_binding", "kubernetes/configmap"}
			for _, rt := range resourceTypes {
				if c := countTotalRelationships(t, ctx, spicedb, rt); c != 0 {
					t.Errorf("Expected 0 relationships for %s after clusterrole deletion, got %d", rt, c)
				}
			}
		})

		// Ensure deleting one ClusterRole does not delete another whose name shares a prefix.
		// Regression test for overly broad prefix matching in DeleteClusterRole.
		t.Run("clusterrole deletion does not affect role with overlapping prefix", func(t *testing.T) {
			spicedb, kube, k2k := setupTest(ctx, t, port)

			// Add a namespace so namespace-level permissions can be verified
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns"}}
			kube.AddOrReplace(ns)
			k2k.ObjectAddedOrChanged(ctx, ns)

			// ClusterRole "foo"
			fooRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
			}
			fooBinding := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "foo-binding"},
				Subjects:   []rbacv1.Subject{{Kind: "User", Name: "user-foo"}},
				RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: fooRole.Name},
			}

			// ClusterRole "foobar"
			foobarRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "foobar"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
			}
			foobarBinding := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "foobar-binding"},
				Subjects:   []rbacv1.Subject{{Kind: "User", Name: "user-foobar"}},
				RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: foobarRole.Name},
			}

			// Add to fake kube and mapper
			for _, obj := range []client.Object{fooRole, fooBinding, foobarRole, foobarBinding} {
				kube.AddOrReplace(obj)
				k2k.ObjectAddedOrChanged(ctx, obj)
			}

			// Sanity: both users have access
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-ns", "pods_get",
				"rbac/principal", "kubernetes/user-foo")
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-ns", "pods_get",
				"rbac/principal", "kubernetes/user-foobar")

			// Delete ClusterRole "foo"
			k2k.ObjectDeleted(ctx, fooRole)

			// user-foo should lose access
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-ns", "pods_get",
				"rbac/principal", "kubernetes/user-foo")

			// user-foobar should still have access
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-ns", "pods_get",
				"rbac/principal", "kubernetes/user-foobar")

			// Ensure relationships for foobar remain
			if c := countTotalRelationships(t, ctx, spicedb, "rbac/role"); c == 0 {
				t.Errorf("Expected rbac/role relationships for foobar to remain, got 0")
			}
		})

		// Failing test stub: clusterrolebinding deletion should revoke access and clean tuples.
		// Currently expected to FAIL until DeleteClusterRoleBinding is implemented.
		t.Run("clusterrolebinding deletion revokes cluster-level access", func(t *testing.T) {
			spicedb, kube, k2k := setupTest(ctx, t, port)

			// Pre-create a namespace so access can be checked.
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "del-ns"}}
			kube.AddOrReplace(ns)
			k2k.ObjectAddedOrChanged(ctx, ns)

			clusterRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "del-cr"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
			}
			clusterBinding := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "del-binding"},
				Subjects:   []rbacv1.Subject{{Kind: "User", Name: "target-user"}},
				RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: clusterRole.Name},
			}

			for _, obj := range []client.Object{clusterRole, clusterBinding} {
				kube.AddOrReplace(obj)
				k2k.ObjectAddedOrChanged(ctx, obj)
			}

			// Sanity: user has access
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/del-ns", "pods_get",
				"rbac/principal", "kubernetes/target-user")

			// Delete the binding
			k2k.ObjectDeleted(ctx, clusterBinding)

			// Expect access revoked
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/del-ns", "pods_get",
				"rbac/principal", "kubernetes/target-user")

			// Expect zero tuples for these resource types
			for _, rt := range []string{"kubernetes/role_binding", "rbac/role_binding"} {
				if c := countTotalRelationships(t, ctx, spicedb, rt); c != 0 {
					t.Errorf("expected 0 relationships for %s after clusterrolebinding deletion, got %d", rt, c)
				}
			}
		})

		// Failing test: deleting a clusterrolebinding should not delete the underlying ClusterRole.
		// After deleting first binding, creating a second binding should succeed and grant access.
		t.Run("clusterrolebinding deletion allows new binding to same role", func(t *testing.T) {
			spicedb, kube, k2k := setupTest(ctx, t, port)

			// Namespace for checks
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prefix-ns"}}
			kube.AddOrReplace(ns)
			k2k.ObjectAddedOrChanged(ctx, ns)

			clusterRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "keep-role"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
			}
			binding1 := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "bind-1"},
				Subjects:   []rbacv1.Subject{{Kind: "User", Name: "user1"}},
				RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: clusterRole.Name},
			}

			kube.AddOrReplace(clusterRole)
			kube.AddOrReplace(binding1)
			k2k.ObjectAddedOrChanged(ctx, clusterRole)
			k2k.ObjectAddedOrChanged(ctx, binding1)

			// user1 has access
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/prefix-ns", "pods_get",
				"rbac/principal", "kubernetes/user1")

			// Delete first binding
			k2k.ObjectDeleted(ctx, binding1)

			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/prefix-ns", "pods_get",
				"rbac/principal", "kubernetes/user1")

			// Create second binding referencing same role
			binding2 := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "bind-2"},
				Subjects:   []rbacv1.Subject{{Kind: "User", Name: "user2"}},
				RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: clusterRole.Name},
			}
			kube.AddOrReplace(binding2)
			k2k.ObjectAddedOrChanged(ctx, binding2)

			// user2 should now have access, proving clusterRole still exists
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/prefix-ns", "pods_get",
				"rbac/principal", "kubernetes/user2")
		})
	})
	t.Run("roles", func(t *testing.T) {
		t.Run("role deletion revokes namespace-level access", func(t *testing.T) {
			spicedb, kube, k2k := setupTest(ctx, t, port)

			role := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "test-namespace",
				},
				Rules: []rbacv1.PolicyRule{{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get"},
				}},
			}
			binding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "test-namespace",
				},
				Subjects: []rbacv1.Subject{{Kind: "User", Name: "test-user"}},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "Role",
					Name:     role.Name,
				},
			}
			kube.AddOrReplace(role)
			kube.AddOrReplace(binding)
			k2k.ObjectAddedOrChanged(ctx, role)
			k2k.ObjectAddedOrChanged(ctx, binding)
			// Verify access
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_get",
				"rbac/principal", "kubernetes/test-user")
			// Delete role
			k2k.ObjectDeleted(ctx, role)
			// Verify access revoked
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_get",
				"rbac/principal", "kubernetes/test-user")
			// Verify no relationships remain
			resourceTypes := []string{"kubernetes/role", "kubernetes/role_binding", "rbac/role", "rbac/role_binding"}
			for _, rt := range resourceTypes {
				relationshipCount := countTotalRelationships(t, ctx, spicedb, rt)
				if relationshipCount != 0 {
					t.Errorf("Expected 0 relationships for resource type %s after role deletion, got %d", rt, relationshipCount)
				}
			}
		})

		t.Run("role deletion revokes resource-level access", func(t *testing.T) {
			spicedb, kube, k2k := setupTest(ctx, t, port)
			role := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "test-namespace",
				},
				Rules: []rbacv1.PolicyRule{{
					APIGroups:     []string{""},
					Resources:     []string{"configmaps"},
					Verbs:         []string{"get"},
					ResourceNames: []string{"test-configmap"},
				}},
			}
			binding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "test-namespace",
				},
				Subjects: []rbacv1.Subject{{Kind: "User", Name: "test-user"}},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "Role",
					Name:     role.Name,
				},
			}
			kube.AddOrReplace(role)
			kube.AddOrReplace(binding)
			k2k.ObjectAddedOrChanged(ctx, role)
			k2k.ObjectAddedOrChanged(ctx, binding)
			// Verify access
			assertAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/test-configmap", "get",
				"rbac/principal", "kubernetes/test-user")
			// Delete role
			k2k.ObjectDeleted(ctx, role)
			// Verify access revoked
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/configmap", "test-cluster/test-namespace/test-configmap", "get",
				"rbac/principal", "kubernetes/test-user")
			// Verify no relationships remain
			resourceTypes := []string{"kubernetes/role", "kubernetes/role_binding", "rbac/role", "rbac/role_binding"}
			for _, rt := range resourceTypes {
				relationshipCount := countTotalRelationships(t, ctx, spicedb, rt)
				if relationshipCount != 0 {
					t.Errorf("Expected 0 relationships for resource type %s after role deletion, got %d", rt, relationshipCount)
				}
			}
		})

		t.Run("role deletion revokes access for multiple bindings", func(t *testing.T) {
			spicedb, kube, k2k := setupTest(ctx, t, port)
			role := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "test-namespace",
				},
				Rules: []rbacv1.PolicyRule{{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get"},
				}},
			}
			binding1 := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "binding-1",
					Namespace: "test-namespace",
				},
				Subjects: []rbacv1.Subject{{Kind: "User", Name: "user-1"}},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "Role",
					Name:     role.Name,
				},
			}
			binding2 := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "binding-2",
					Namespace: "test-namespace",
				},
				Subjects: []rbacv1.Subject{{Kind: "User", Name: "user-2"}},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "Role",
					Name:     role.Name,
				},
			}
			kube.AddOrReplace(role)
			kube.AddOrReplace(binding1)
			kube.AddOrReplace(binding2)
			k2k.ObjectAddedOrChanged(ctx, role)
			k2k.ObjectAddedOrChanged(ctx, binding1)
			k2k.ObjectAddedOrChanged(ctx, binding2)
			// Verify access for both users
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_get",
				"rbac/principal", "kubernetes/user-1")
			assertAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_get",
				"rbac/principal", "kubernetes/user-2")
			// Delete role
			k2k.ObjectDeleted(ctx, role)
			// Verify access revoked for both users
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_get",
				"rbac/principal", "kubernetes/user-1")
			assertNoAccess(t, ctx, spicedb,
				"kubernetes/knamespace", "test-cluster/test-namespace", "pods_get",
				"rbac/principal", "kubernetes/user-2")
			// Verify no relationships remain
			resourceTypes := []string{"kubernetes/role", "kubernetes/role_binding", "rbac/role", "rbac/role_binding"}
			for _, rt := range resourceTypes {
				relationshipCount := countTotalRelationships(t, ctx, spicedb, rt)
				if relationshipCount != 0 {
					t.Errorf("Expected 0 relationships for resource type %s after role deletion, got %d", rt, relationshipCount)
				}
			}
		})
	})
}

func setupTest(ctx context.Context, t *testing.T, port string) (*authzed.Client, *testutil.FakeKube, *mapper.KubeRbacToKessel) {
	// Set up controller-runtime logger
	log.SetLogger(zap.New(zap.UseDevMode(true)))

	spicedb, err := spicedbTestClient(port)
	if err != nil {
		t.Fatal(err)
	}

	kube := testutil.NewFakeKube()

	k2k, err := setupMapper(ctx, kube, spicedb)
	if err != nil {
		t.Fatal(err)
	}
	return spicedb, kube, k2k
}

// checkPermission checks if a subject has a specific permission on a resource in SpiceDB
// Returns true if the subject has permission, false otherwise
func checkPermission(t *testing.T, ctx context.Context, spicedb *authzed.Client,
	resourceType, resourceId, permission, subjectType, subjectId string) (bool, *v1.CheckPermissionResponse) {
	t.Helper()

	response, err := spicedb.CheckPermission(ctx, &v1.CheckPermissionRequest{
		Consistency: &v1.Consistency{
			Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true},
		},
		WithTracing: true,
		Resource: &v1.ObjectReference{
			ObjectType: resourceType,
			ObjectId:   resourceId,
		},
		Permission: permission,
		Subject: &v1.SubjectReference{
			Object: &v1.ObjectReference{
				ObjectType: subjectType,
				ObjectId:   subjectId,
			},
		}})

	if err != nil {
		t.Fatal(err)
	}

	hasPermission := response.Permissionship == v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION
	return hasPermission, response
}

// assertAccess checks that a subject has a specific permission on a resource in SpiceDB
func assertAccess(t *testing.T, ctx context.Context, spicedb *authzed.Client,
	resourceType, resourceId, permission, subjectType, subjectId string) {
	t.Helper()

	hasPermission, response := checkPermission(t, ctx, spicedb, resourceType, resourceId, permission, subjectType, subjectId)

	if !hasPermission {
		jsonTrace, _ := json.MarshalIndent(response.DebugTrace, "", "  ")
		t.Logf("Debug trace: %s", jsonTrace)
		t.Errorf("expected subject %s:%s to have permission %s on resource %s:%s, got %s",
			subjectType, subjectId, permission, resourceType, resourceId, response.Permissionship)
	}
}

// assertNoAccess checks that a subject does NOT have a specific permission on a resource in SpiceDB
func assertNoAccess(t *testing.T, ctx context.Context, spicedb *authzed.Client,
	resourceType, resourceId, permission, subjectType, subjectId string) {
	t.Helper()

	hasPermission, response := checkPermission(t, ctx, spicedb, resourceType, resourceId, permission, subjectType, subjectId)

	if hasPermission {
		jsonTrace, _ := json.MarshalIndent(response.DebugTrace, "", "  ")
		t.Logf("Debug trace: %s", jsonTrace)
		t.Errorf("expected subject %s:%s to NOT have permission %s on resource %s:%s, but it does",
			subjectType, subjectId, permission, resourceType, resourceId)
	}
}

func setupMapper(ctx context.Context, kube *testutil.FakeKube, spiceDb *authzed.Client) (*mapper.KubeRbacToKessel, error) {
	mapper := &mapper.KubeRbacToKessel{
		ClusterId:    "test-cluster",
		Kube:         kube,
		SpiceDb:      spiceDb,
		SchemaSource: &mapper.FileSchemaSource{FilePath: "../../config/ksl/schema.zed"},
	}
	return mapper, mapper.SetUpSchema(ctx)
}

// runSpiceDBTestServer spins up a SpiceDB container running the integration
// test server.
func runSpiceDBTestServer(t *testing.T) (port string, err error) {
	pool, err := dockertest.NewPool("") // Empty string uses default docker env
	if err != nil {
		return
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "authzed/spicedb",
		Tag:          "latest", // Replace this with an actual version
		Cmd:          []string{"serve-testing"},
		ExposedPorts: []string{"50051/tcp", "50052/tcp"},
	})
	if err != nil {
		return
	}

	// When you're done, kill and remove the container
	t.Cleanup(func() {
		_ = pool.Purge(resource)
	})

	return resource.GetPort("50051/tcp"), nil
	// return "50051", nil // For simplicity, return a fixed port. Replace with actual Docker setup if needed.
}

// spicedbTestClient creates a new SpiceDB client with random credentials.
//
// The test server gives each set of a credentials its own isolated datastore
// so that tests can be ran in parallel.
func spicedbTestClient(port string) (*authzed.Client, error) {
	// Generate a random credential to isolate this client from any others.
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	randomKey := base64.StdEncoding.EncodeToString(buf)

	return authzed.NewClient(
		"localhost:"+port,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// grpcutil.WithInsecureBearerToken("mykey"),
		grpcutil.WithInsecureBearerToken(randomKey),
		grpc.WithBlock(),
	)
}

// countTotalRelationships counts the total number of relationships in SpiceDB for a given resource type
func countTotalRelationships(t *testing.T, ctx context.Context, spicedb *authzed.Client, resourceType string) int {
	t.Helper()

	count := 0
	err := streamutil.ForEach(
		func() (v1.PermissionsService_ReadRelationshipsClient, error) {
			return spicedb.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{
				Consistency: &v1.Consistency{
					Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true},
				},
				RelationshipFilter: &v1.RelationshipFilter{
					ResourceType: resourceType,
				},
			})
		},
		func(response *v1.ReadRelationshipsResponse) error {
			count++
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return count
}
