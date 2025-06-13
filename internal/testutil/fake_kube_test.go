package testutil_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/project-kessel/kube-kessel-sync/internal/testutil"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("FakeKube", func() {
	var (
		fakeKube *testutil.FakeKube
		ctx      context.Context
	)

	BeforeEach(func() {
		fakeKube = testutil.NewFakeKube()
		ctx = context.Background()
	})

	Describe("Get operations", func() {
		Context("when object exists", func() {
			It("should retrieve the stored object successfully", func() {
				originalRole := &rbacv1.Role{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-role",
						Namespace: "default",
					},
					Rules: []rbacv1.PolicyRule{
						{
							APIGroups: []string{""},
							Resources: []string{"pods"},
							Verbs:     []string{"get", "list"},
						},
					},
				}

				fakeKube.AddOrReplace(originalRole)

				var retrievedRole rbacv1.Role
				key := client.ObjectKey{Name: "test-role", Namespace: "default"}
				err := fakeKube.Get(ctx, key, &retrievedRole)

				Expect(err).ToNot(HaveOccurred())
				Expect(retrievedRole.Name).To(Equal("test-role"))
				Expect(retrievedRole.Namespace).To(Equal("default"))
				Expect(retrievedRole.Rules).To(HaveLen(1))
				Expect(retrievedRole.Rules[0].Resources).To(ContainElement("pods"))
				Expect(retrievedRole.Rules[0].Verbs).To(ContainElements("get", "list"))
			})

			It("should handle cluster-scoped objects (no namespace)", func() {
				originalClusterRole := &rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-cluster-role",
					},
					Rules: []rbacv1.PolicyRule{
						{
							APIGroups: []string{"apps"},
							Resources: []string{"deployments"},
							Verbs:     []string{"create", "update"},
						},
					},
				}

				fakeKube.AddOrReplace(originalClusterRole)

				var retrievedClusterRole rbacv1.ClusterRole
				key := client.ObjectKey{Name: "test-cluster-role"}
				err := fakeKube.Get(ctx, key, &retrievedClusterRole)

				Expect(err).ToNot(HaveOccurred())
				Expect(retrievedClusterRole.Name).To(Equal("test-cluster-role"))
				Expect(retrievedClusterRole.Namespace).To(BeEmpty())
				Expect(retrievedClusterRole.Rules).To(HaveLen(1))
				Expect(retrievedClusterRole.Rules[0].Resources).To(ContainElement("deployments"))
			})
		})

		Context("when object does not exist", func() {
			It("should return NotFound error", func() {
				var role rbacv1.Role
				key := client.ObjectKey{Name: "nonexistent-role", Namespace: "default"}
				err := fakeKube.Get(ctx, key, &role)

				Expect(err).To(HaveOccurred())
				Expect(errors.IsNotFound(err)).To(BeTrue())

				statusErr := err.(*errors.StatusError)
				Expect(statusErr.Status().Details.Name).To(Equal("nonexistent-role"))
			})
		})
	})

	Describe("AddOrReplace operations", func() {
		It("should store new objects", func() {
			role := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "new-role",
					Namespace: "test-namespace",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"configmaps"},
						Verbs:     []string{"get"},
					},
				},
			}

			fakeKube.AddOrReplace(role)

			var retrievedRole rbacv1.Role
			key := client.ObjectKey{Name: "new-role", Namespace: "test-namespace"}
			err := fakeKube.Get(ctx, key, &retrievedRole)

			Expect(err).ToNot(HaveOccurred())
			Expect(retrievedRole.Name).To(Equal("new-role"))
			Expect(retrievedRole.Namespace).To(Equal("test-namespace"))
		})

		It("should replace existing objects with updated values", func() {
			originalRole := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "role-to-update",
					Namespace: "default",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get"},
					},
				},
			}

			fakeKube.AddOrReplace(originalRole)

			updatedRole := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "role-to-update",
					Namespace: "default",
					Labels:    map[string]string{"updated": "true"},
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods", "services"},
						Verbs:     []string{"get", "list", "create"},
					},
				},
			}

			fakeKube.AddOrReplace(updatedRole)

			var retrievedRole rbacv1.Role
			key := client.ObjectKey{Name: "role-to-update", Namespace: "default"}
			err := fakeKube.Get(ctx, key, &retrievedRole)

			Expect(err).ToNot(HaveOccurred())
			Expect(retrievedRole.Name).To(Equal("role-to-update"))
			Expect(retrievedRole.Labels).To(HaveKeyWithValue("updated", "true"))
			Expect(retrievedRole.Rules).To(HaveLen(1))
			Expect(retrievedRole.Rules[0].Resources).To(ContainElements("pods", "services"))
			Expect(retrievedRole.Rules[0].Verbs).To(ContainElements("get", "list", "create"))
		})

		It("should handle objects with different types independently", func() {
			role := &rbacv1.Role{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Role",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "same-name",
					Namespace: "default",
				},
				Rules: []rbacv1.PolicyRule{
					{Resources: []string{"pods"}, Verbs: []string{"get"}},
				},
			}

			roleBinding := &rbacv1.RoleBinding{
				TypeMeta: metav1.TypeMeta{
					Kind:       "RoleBinding",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "same-name",
					Namespace: "default",
				},
				Subjects: []rbacv1.Subject{
					{Kind: "User", Name: "test-user"},
				},
				RoleRef: rbacv1.RoleRef{
					Kind: "Role",
					Name: "test-role",
				},
			}

			fakeKube.AddOrReplace(role)
			fakeKube.AddOrReplace(roleBinding)

			var retrievedRole rbacv1.Role
			var retrievedRoleBinding rbacv1.RoleBinding
			key := client.ObjectKey{Name: "same-name", Namespace: "default"}

			err1 := fakeKube.Get(ctx, key, &retrievedRole)
			err2 := fakeKube.Get(ctx, key, &retrievedRoleBinding)

			Expect(err1).ToNot(HaveOccurred())
			Expect(err2).ToNot(HaveOccurred())
			Expect(retrievedRole.Rules).To(HaveLen(1))
			Expect(retrievedRole.Rules[0].Resources).To(ContainElement("pods"))
			Expect(retrievedRoleBinding.Subjects).To(HaveLen(1))
			Expect(retrievedRoleBinding.Subjects[0].Name).To(Equal("test-user"))
		})
	})

	Describe("Remove operations", func() {
		It("should remove existing objects", func() {
			role := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "role-to-remove",
					Namespace: "default",
				},
				Rules: []rbacv1.PolicyRule{
					{Resources: []string{"secrets"}, Verbs: []string{"get"}},
				},
			}

			fakeKube.AddOrReplace(role)

			var retrievedRole rbacv1.Role
			key := client.ObjectKey{Name: "role-to-remove", Namespace: "default"}
			err := fakeKube.Get(ctx, key, &retrievedRole)
			Expect(err).ToNot(HaveOccurred())

			fakeKube.Remove(key, role)

			err = fakeKube.Get(ctx, key, &retrievedRole)
			Expect(err).To(HaveOccurred())
			Expect(errors.IsNotFound(err)).To(BeTrue())
		})

		It("should handle removal of non-existent objects gracefully", func() {
			role := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "never-existed",
					Namespace: "default",
				},
			}

			key := client.ObjectKey{Name: "never-existed", Namespace: "default"}

			Expect(func() {
				fakeKube.Remove(key, role)
			}).ToNot(Panic())

			var retrievedRole rbacv1.Role
			err := fakeKube.Get(ctx, key, &retrievedRole)
			Expect(err).To(HaveOccurred())
			Expect(errors.IsNotFound(err)).To(BeTrue())
		})

		It("should only remove the specified object type", func() {
			role := &rbacv1.Role{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Role",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "shared-name",
					Namespace: "default",
				},
				Rules: []rbacv1.PolicyRule{{Resources: []string{"pods"}, Verbs: []string{"get"}}},
			}

			roleBinding := &rbacv1.RoleBinding{
				TypeMeta: metav1.TypeMeta{
					Kind:       "RoleBinding",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "shared-name",
					Namespace: "default",
				},
				Subjects: []rbacv1.Subject{{Kind: "User", Name: "test"}},
				RoleRef:  rbacv1.RoleRef{Kind: "Role", Name: "test"},
			}

			fakeKube.AddOrReplace(role)
			fakeKube.AddOrReplace(roleBinding)

			key := client.ObjectKey{Name: "shared-name", Namespace: "default"}
			fakeKube.Remove(key, role)

			var retrievedRole rbacv1.Role
			var retrievedRoleBinding rbacv1.RoleBinding

			err1 := fakeKube.Get(ctx, key, &retrievedRole)
			err2 := fakeKube.Get(ctx, key, &retrievedRoleBinding)

			Expect(err1).To(HaveOccurred())
			Expect(errors.IsNotFound(err1)).To(BeTrue())
			Expect(err2).ToNot(HaveOccurred())
			Expect(retrievedRoleBinding.Subjects).To(HaveLen(1))
		})
	})

	Describe("Object key generation", func() {
		It("should distinguish between namespaced and cluster-scoped objects", func() {
			role := &rbacv1.Role{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Role",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-name",
					Namespace: "kube-system",
				},
			}

			clusterRole := &rbacv1.ClusterRole{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ClusterRole",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-name", // Same name, no namespace
				},
			}

			fakeKube.AddOrReplace(role)
			fakeKube.AddOrReplace(clusterRole)

			var retrievedRole rbacv1.Role
			var retrievedClusterRole rbacv1.ClusterRole

			namespacedKey := client.ObjectKey{Name: "test-name", Namespace: "kube-system"}
			clusterKey := client.ObjectKey{Name: "test-name"}

			err1 := fakeKube.Get(ctx, namespacedKey, &retrievedRole)
			err2 := fakeKube.Get(ctx, clusterKey, &retrievedClusterRole)

			Expect(err1).ToNot(HaveOccurred())
			Expect(err2).ToNot(HaveOccurred())
			Expect(retrievedRole.Namespace).To(Equal("kube-system"))
			Expect(retrievedClusterRole.Namespace).To(BeEmpty())
		})

		It("should distinguish between objects in different namespaces", func() {
			role1 := &rbacv1.Role{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Role",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "namespace-1",
				},
				Rules: []rbacv1.PolicyRule{{Resources: []string{"pods"}, Verbs: []string{"get"}}},
			}

			role2 := &rbacv1.Role{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Role",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "namespace-2",
				},
				Rules: []rbacv1.PolicyRule{{Resources: []string{"services"}, Verbs: []string{"list"}}},
			}

			fakeKube.AddOrReplace(role1)
			fakeKube.AddOrReplace(role2)

			var retrievedRole1, retrievedRole2 rbacv1.Role

			key1 := client.ObjectKey{Name: "test-role", Namespace: "namespace-1"}
			key2 := client.ObjectKey{Name: "test-role", Namespace: "namespace-2"}

			err1 := fakeKube.Get(ctx, key1, &retrievedRole1)
			err2 := fakeKube.Get(ctx, key2, &retrievedRole2)

			Expect(err1).ToNot(HaveOccurred())
			Expect(err2).ToNot(HaveOccurred())
			Expect(retrievedRole1.Namespace).To(Equal("namespace-1"))
			Expect(retrievedRole2.Namespace).To(Equal("namespace-2"))
			Expect(retrievedRole1.Rules[0].Resources).To(ContainElement("pods"))
			Expect(retrievedRole2.Rules[0].Resources).To(ContainElement("services"))
		})
	})
})
