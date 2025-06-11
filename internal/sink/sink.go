package sink

import (
	"context"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type KubeObjectSink interface {
	ObjectAddedOrChanged(ctx context.Context, obj client.Object) error
	ObjectDeleted(ctx context.Context, obj client.Object) error
}

type LoggingKubeObjectSink struct {
}

func NewLoggingKubeObjectSink() *LoggingKubeObjectSink {
	return &LoggingKubeObjectSink{}
}

func (s *LoggingKubeObjectSink) ObjectAddedOrChanged(ctx context.Context, obj client.Object) error {
	log := logf.FromContext(ctx)

	name := obj.GetName()
	namespace := obj.GetNamespace()
	kind := obj.GetObjectKind().GroupVersionKind().Kind
	log.Info("POST", "objectKind", kind, "objectNamespace", namespace, "objectName", name)

	return nil
}

func (s *LoggingKubeObjectSink) ObjectDeleted(ctx context.Context, obj client.Object) error {
	log := logf.FromContext(ctx)

	name := obj.GetName()
	namespace := obj.GetNamespace()
	kind := obj.GetObjectKind().GroupVersionKind().Kind
	switch o := obj.(type) {
	case *rbacv1.Role:
		log.Info("DELETE Role", "namespace", namespace, "name", name, "rules", o.Rules)
	case *rbacv1.RoleBinding:
		log.Info("DELETE RoleBinding", "namespace", namespace, "name", name, "subjects", o.Subjects)
	case *rbacv1.ClusterRole:
		log.Info("DELETE ClusterRole", "name", name, "rules", o.Rules)
	case *rbacv1.ClusterRoleBinding:
		log.Info("DELETE ClusterRoleBinding", "name", name, "subjects", o.Subjects)
	default:
		log.Info("DELETE Unknown", "kind", kind, "namespace", namespace, "name", name)
	}
	log.Info("DELETE", "objectKind", kind, "objectNamespace", namespace, "objectName", name)
	return nil
}
