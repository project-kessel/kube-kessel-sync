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

package controller

import (
	"context"

	sink "github.com/project-kessel/kube-kessel-sync/internal/sink"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles;clusterrolebindings;roles;rolebindings,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch

// KesselSyncReconciler reconciles a FabricSyncConfig object
type KesselSyncReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	lastData map[types.UID]client.Object
	Sink     sink.KubeObjectSink
}

func (r *KesselSyncReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Initialize lastData if nil
	if r.lastData == nil {
		r.lastData = make(map[types.UID]client.Object)
	}

	// Store true if object is different from lastData, false if it is the same
	foundUids := make(map[types.UID]bool)

	// Fetch all roles
	allRoleExistingList := &rbacv1.RoleList{}
	if err := r.List(ctx, allRoleExistingList); err != nil {
		log.Error(err, "Failed to list Roles")
		return ctrl.Result{}, err
	}
	for _, role := range allRoleExistingList.Items {
		if data, ok := r.lastData[role.UID]; ok {
			// If the object is in lastData, check if it has changed
			// true if changed, false if not
			foundUids[role.UID] = !equality.Semantic.DeepEqual(&role, data)
		} else {
			// If the object is not in lastData, it is new
			foundUids[role.UID] = true
		}
		r.lastData[role.UID] = role.DeepCopy()
	}

	// Fetch all rolebindings
	allRoleBindingExistingList := &rbacv1.RoleBindingList{}
	if err := r.List(ctx, allRoleBindingExistingList); err != nil {
		log.Error(err, "Failed to list RoleBindings")
		return ctrl.Result{}, err
	}
	for _, roleBinding := range allRoleBindingExistingList.Items {
		if data, ok := r.lastData[roleBinding.UID]; ok {
			foundUids[roleBinding.UID] = !equality.Semantic.DeepEqual(&roleBinding, data)
		} else {
			foundUids[roleBinding.UID] = true
		}
		r.lastData[roleBinding.UID] = roleBinding.DeepCopy()
	}

	// Fetch all clusterroles
	allClusterRoleExistingList := &rbacv1.ClusterRoleList{}
	if err := r.List(ctx, allClusterRoleExistingList); err != nil {
		log.Error(err, "Failed to list ClusterRoles")
		return ctrl.Result{}, err
	}
	for _, clusterRole := range allClusterRoleExistingList.Items {
		if data, ok := r.lastData[clusterRole.UID]; ok {
			foundUids[clusterRole.UID] = !equality.Semantic.DeepEqual(&clusterRole, data)
		} else {
			foundUids[clusterRole.UID] = true
		}
		r.lastData[clusterRole.UID] = clusterRole.DeepCopy()
	}

	// Fetch all clusterrolebindings
	allClusterRoleBindingExistingList := &rbacv1.ClusterRoleBindingList{}
	if err := r.List(ctx, allClusterRoleBindingExistingList); err != nil {
		log.Error(err, "Failed to list RoleBindings")
		return ctrl.Result{}, err
	}
	for _, clusterRoleBinding := range allClusterRoleBindingExistingList.Items {
		if data, ok := r.lastData[clusterRoleBinding.UID]; ok {
			foundUids[clusterRoleBinding.UID] = !equality.Semantic.DeepEqual(&clusterRoleBinding, data)
		} else {
			foundUids[clusterRoleBinding.UID] = true
		}
		r.lastData[clusterRoleBinding.UID] = clusterRoleBinding.DeepCopy()
	}

	// Fetch all namespaces
	allNamespaceExistingList := &corev1.NamespaceList{}
	if err := r.List(ctx, allNamespaceExistingList); err != nil {
		log.Error(err, "Failed to list Namespaces")
		return ctrl.Result{}, err
	}
	for _, namespace := range allNamespaceExistingList.Items {
		if data, ok := r.lastData[namespace.UID]; ok {
			foundUids[namespace.UID] = !equality.Semantic.DeepEqual(&namespace, data)
		} else {
			foundUids[namespace.UID] = true
		}
		r.lastData[namespace.UID] = namespace.DeepCopy()
	}

	// Post all objects based on whether they've been updated or deleted
	for uid, obj := range r.lastData {
		if changed, ok := foundUids[uid]; ok {
			if changed {
				r.Sink.ObjectAddedOrChanged(ctx, obj)
			}
		} else {
			if err := r.Sink.ObjectDeleted(ctx, obj); err != nil {
				// Log the error but keep trying
				log.Error(err, "Failed to post delete object")
			} else {
				// Only delete from lastData if the post was successful
				delete(r.lastData, uid)
			}
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *KesselSyncReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Watches(&rbacv1.ClusterRole{}, myHandler).
		Watches(&rbacv1.ClusterRoleBinding{}, myHandler).
		Watches(&rbacv1.Role{}, myHandler).
		Watches(&rbacv1.RoleBinding{}, myHandler).
		Watches(&corev1.Namespace{}, myHandler).
		Named("sync").
		Complete(r)
}

var dummyKey = types.NamespacedName{
	Name:      "dummy",
	Namespace: "dummy",
}

var myHandler = handler.Funcs{
	CreateFunc: func(ctx context.Context, tce event.TypedCreateEvent[client.Object], trli workqueue.TypedRateLimitingInterface[reconcile.Request]) {
		trli.Add(reconcile.Request{
			NamespacedName: dummyKey,
		})
	},
	UpdateFunc: func(ctx context.Context, tue event.TypedUpdateEvent[client.Object], trli workqueue.TypedRateLimitingInterface[reconcile.Request]) {
		trli.Add(reconcile.Request{
			NamespacedName: dummyKey,
		})
	},
	DeleteFunc: func(ctx context.Context, tde event.TypedDeleteEvent[client.Object], trli workqueue.TypedRateLimitingInterface[reconcile.Request]) {
		trli.Add(reconcile.Request{
			NamespacedName: dummyKey,
		})
	},
	GenericFunc: func(ctx context.Context, tge event.TypedGenericEvent[client.Object], trli workqueue.TypedRateLimitingInterface[reconcile.Request]) {
		trli.Add(reconcile.Request{
			NamespacedName: dummyKey,
		})
	},
}
