// Copyright 2019-2021 The Liqo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storageprovisioner

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/sig-storage-lib-external-provisioner/v7/controller"
)

// +kubebuilder:rbac:groups=core,resources=persistentvolumeclaims;persistentvolumes,verbs=get;list;watch;create;delete;update
// +kubebuilder:rbac:groups=storage.k8s.io,resources=storageclasses,verbs=get;list;watch

type liqoLocalStorageProvisioner struct {
	client                  client.Client
	virtualStorageClassName string
	storageNamespace        string
	localRealStorageClass   string
}

// NewLiqoLocalStorageProvisioner creates a new liqoLocalStorageProvisioner provisioner.
func NewLiqoLocalStorageProvisioner(cl client.Client,
	virtualStorageClassName, storageNamespace, localRealStorageClass string) controller.Provisioner {
	return &liqoLocalStorageProvisioner{
		client:                  cl,
		virtualStorageClassName: virtualStorageClassName,
		storageNamespace:        storageNamespace,
		localRealStorageClass:   localRealStorageClass,
	}
}
