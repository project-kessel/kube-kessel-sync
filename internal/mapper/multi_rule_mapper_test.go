package mapper_test

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestMultiRuleBindings verifies that a Role/ClusterRole with multiple PolicyRules still grants access
// for *all* rules after being processed by the mapper.
func TestMultiRuleBindings(t *testing.T) {
	ctx := context.Background()

	port, err := runSpiceDBTestServer(t)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("role with multiple rules", func(t *testing.T) {
		t.Parallel()

		spicedb, kube, k2k := setupTest(ctx, t, port)

		role := &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "multi-rule-role",
				Namespace: "demo-ns",
			},
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}},
			},
		}

		binding := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "multi-rule-binding",
				Namespace: "demo-ns",
			},
			Subjects: []rbacv1.Subject{{Kind: "User", Name: "alice"}},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "Role",
				Name:     role.Name,
			},
		}

		// Inject into fake kube so mapper can fetch them.
		kube.AddOrReplace(role)
		kube.AddOrReplace(binding)

		// Map objects.
		if err := k2k.ObjectAddedOrChanged(ctx, role); err != nil {
			t.Fatalf("mapping role: %v", err)
		}
		if err := k2k.ObjectAddedOrChanged(ctx, binding); err != nil {
			t.Fatalf("mapping rolebinding: %v", err)
		}

		// Assert access for each rule.
		assertAccess(t, ctx, spicedb,
			"kubernetes/knamespace", "test-cluster/demo-ns", "pods_get",
			"rbac/principal", "kubernetes/alice")
		assertAccess(t, ctx, spicedb,
			"kubernetes/knamespace", "test-cluster/demo-ns", "configmaps_get",
			"rbac/principal", "kubernetes/alice")
	})

	t.Run("clusterrole with multiple rules", func(t *testing.T) {
		t.Parallel()

		spicedb, kube, k2k := setupTest(ctx, t, port)

		clusterRole := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: "multi-rule-clusterrole",
			},
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}},
			},
		}

		clusterBinding := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "multi-rule-clusterbinding",
			},
			Subjects: []rbacv1.Subject{{Kind: "User", Name: "bob"}},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole",
				Name:     clusterRole.Name,
			},
		}

		kube.AddOrReplace(clusterRole)
		kube.AddOrReplace(clusterBinding)

		if err := k2k.ObjectAddedOrChanged(ctx, clusterRole); err != nil {
			t.Fatalf("mapping cluster role: %v", err)
		}
		if err := k2k.ObjectAddedOrChanged(ctx, clusterBinding); err != nil {
			t.Fatalf("mapping cluster role binding: %v", err)
		}

		// Cluster-level permissions are asserted against the cluster object.
		assertAccess(t, ctx, spicedb,
			"kubernetes/cluster", "test-cluster", "pods_get",
			"rbac/principal", "kubernetes/bob")
		assertAccess(t, ctx, spicedb,
			"kubernetes/cluster", "test-cluster", "configmaps_get",
			"rbac/principal", "kubernetes/bob")
	})
}
