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
	"github.com/project-kessel/kube-kessel-sync/internal/testutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMapper(t *testing.T) {
	var err error
	ctx := context.Background()
	// g := gomega.NewWithT(t)

	port, err := runSpiceDBTestServer(t)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("namespace bindings", func(t *testing.T) {
		t.Run("grant access", func(t *testing.T) {
			t.Parallel()

			spicedb, err := spicedbTestClient(port)
			if err != nil {
				t.Fatal(err)
			}

			kube := testutil.NewFakeKube()

			k2k, err := setupMapper(ctx, kube, spicedb)
			if err != nil {
				t.Fatal(err)
			}

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
			response, err := spicedb.CheckPermission(ctx, &v1.CheckPermissionRequest{
				Consistency: &v1.Consistency{
					Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true},
				},
				WithTracing: true,
				Resource: &v1.ObjectReference{
					ObjectType: "kubernetes/knamespace",
					ObjectId:   "test-cluster/test-namespace",
				},
				Permission: "pods_get",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "rbac/principal",
						ObjectId:   "kubernetes/test-user",
					},
				}})

			if err != nil {
				t.Fatal(err)
			}

			if response.Permissionship != v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION {
				jsonTrace, _ := json.MarshalIndent(response.DebugTrace, "", "  ")
				t.Logf("Debug trace: %s", jsonTrace)
				t.Errorf("expected user to have access to namespace, got %s", response.Permissionship)
			}

		})
	})

	// Given a new role and binding, ensure the user doesn't have access to things not granted

	// Given a new role and binding, ensure a different user doesn't have access

	// Given a new role with resource name and binding, ensure the user has access to that resource

	// Given a new role with resource name and binding, ensure the user has doesn't have access to the namespace
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
