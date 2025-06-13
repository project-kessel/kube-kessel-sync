package testutil

import (
	"context"
	"fmt"
	"reflect"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FakeKube is a very simple fake Kubernetes client with just the Getter implementation
// for testing.
type FakeKube struct {
	objects map[string]client.Object
	scheme  *runtime.Scheme
}

func NewFakeKube() *FakeKube {
	return &FakeKube{
		objects: make(map[string]client.Object),
		scheme:  scheme.Scheme, // Use the default Kubernetes scheme
	}
}

func (k *FakeKube) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	storageKey := k.keyFor(key, obj)

	stored, exists := k.objects[storageKey]
	if !exists {
		gvk, err := k.gvkForObject(obj)
		if err != nil {
			// Fall back to empty GVK if we can't determine it
			gvk = schema.GroupVersionKind{}
		}
		return errors.NewNotFound(schema.GroupResource{
			Group:    gvk.Group,
			Resource: gvk.Kind,
		}, key.Name)
	}

	reflect.ValueOf(obj).Elem().Set(reflect.ValueOf(stored).Elem())

	return nil
}

// AddOrReplace adds or replaces an object in the fake store
func (k *FakeKube) AddOrReplace(obj client.Object) {
	key := client.ObjectKey{
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
	}
	storageKey := k.keyFor(key, obj)
	k.objects[storageKey] = obj
}

// Remove removes an object from the fake store
func (k *FakeKube) Remove(key client.ObjectKey, obj client.Object) {
	storageKey := k.keyFor(key, obj)
	delete(k.objects, storageKey)
}

func (k *FakeKube) keyFor(key client.ObjectKey, obj client.Object) string {
	gvk, err := k.gvkForObject(obj)
	if err != nil {
		// Fall back to the object's own GVK if scheme lookup fails
		gvk = obj.GetObjectKind().GroupVersionKind()
	}

	if key.Namespace == "" {
		return fmt.Sprintf("%s/%s/%s", gvk.String(), key.Name, "")
	}
	return fmt.Sprintf("%s/%s/%s", gvk.String(), key.Namespace, key.Name)
}

// gvkForObject returns the GroupVersionKind for the given object using the scheme
func (k *FakeKube) gvkForObject(obj runtime.Object) (schema.GroupVersionKind, error) {
	gvks, _, err := k.scheme.ObjectKinds(obj)
	if err != nil {
		return schema.GroupVersionKind{}, err
	}
	if len(gvks) == 0 {
		return schema.GroupVersionKind{}, fmt.Errorf("no GroupVersionKind found for object type %T", obj)
	}
	return gvks[0], nil
}
