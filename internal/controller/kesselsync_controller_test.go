package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// stubSink is a simple test double that records calls made by the reconciler.
// It implements the sink.KubeObjectSink interface.
// NOTE: we declare it in this package to avoid an import cycle.
type stubSink struct {
	addedOrChanged []client.Object
	deleted        []client.Object
}

func (s *stubSink) ObjectAddedOrChanged(_ context.Context, obj client.Object) error {
	s.addedOrChanged = append(s.addedOrChanged, obj)
	return nil
}

func (s *stubSink) ObjectDeleted(_ context.Context, obj client.Object) error {
	s.deleted = append(s.deleted, obj)
	return nil
}

func (s *stubSink) reset() {
	s.addedOrChanged = nil
	s.deleted = nil
}

// newTestReconciler creates a KesselSyncReconciler wired with a fake Kubernetes
// client seeded with the provided objects and a stub sink.
func newTestReconciler(objs ...client.Object) (*KesselSyncReconciler, *stubSink, error) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()

	sink := &stubSink{}

	r := &KesselSyncReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Sink:   sink,
	}

	return r, sink, nil
}

// TestKesselSyncReconciler verifies that the reconciler correctly calls the sink
// when objects are created, updated, or left unchanged.
func TestKesselSyncReconciler(t *testing.T) {
	ctx := context.TODO()

	// Seed object – a simple Role.
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-role",
			Namespace: "default",
			UID:       types.UID("role-uid"),
		},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get"},
		}},
	}

	reconciler, sink, err := newTestReconciler(role)
	if err != nil {
		t.Fatalf("failed to create test reconciler: %v", err)
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "dummy", Namespace: "dummy"}}

	// 1. First reconcile – the Role is new, so the sink must be called once.
	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("reconcile returned error: %v", err)
	}
	if got := len(sink.addedOrChanged); got != 1 {
		t.Fatalf("expected 1 ObjectAddedOrChanged call, got %d", got)
	}

	// 2. Second reconcile with no changes – sink should not be invoked again.
	sink.reset()
	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("reconcile returned error (unchanged case): %v", err)
	}
	if got := len(sink.addedOrChanged); got != 0 {
		t.Fatalf("expected 0 ObjectAddedOrChanged calls on unchanged reconcile, got %d", got)
	}

	// 3. Modify the role (add a verb) and update the fake client.
	updatedRole := role.DeepCopy()
	updatedRole.Rules[0].Verbs = append(updatedRole.Rules[0].Verbs, "list")
	if err := reconciler.Client.Update(ctx, updatedRole); err != nil {
		t.Fatalf("failed to update role in fake client: %v", err)
	}

	sink.reset()

	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("reconcile returned error (changed case): %v", err)
	}
	if got := len(sink.addedOrChanged); got != 1 {
		t.Fatalf("expected 1 ObjectAddedOrChanged call after role change, got %d", got)
	}
}
