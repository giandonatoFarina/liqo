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
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"github.com/onsi/gomega/types"
	v1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/sig-storage-lib-external-provisioner/v7/controller"

	liqoconst "github.com/liqotech/liqo/pkg/consts"
)

var _ = Describe("Test Storage Provisioner", func() {

	var (
		k8sClient client.Client
	)

	BeforeEach(func() {
		k8sClient = ctrlfake.NewClientBuilder().WithScheme(scheme.Scheme).Build()
	})

	Context("Provision function", func() {

		const (
			virtualStorageClassName = "liqo"
			storageNamespace        = "liqo-storage"
		)

		var (
			forgeNode = func(name string, isVirtual bool) *v1.Node {
				node := &v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:   name,
						Labels: map[string]string{},
					},
				}

				if isVirtual {
					node.ObjectMeta.Labels[liqoconst.TypeLabel] = liqoconst.TypeNode
				}

				return node
			}

			forgePVC = func(name, namespace string) *v1.PersistentVolumeClaim {
				pvc := &v1.PersistentVolumeClaim{
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
					},
					Spec: v1.PersistentVolumeClaimSpec{
						Resources: v1.ResourceRequirements{
							Requests: v1.ResourceList{
								v1.ResourceStorage: *resource.NewQuantity(10, resource.BinarySI),
							},
						},
					},
				}

				return pvc
			}
		)

		type provisionTestcase struct {
			options                   controller.ProvisionOptions
			localRealStorageClassName string
			expectedState             types.GomegaMatcher
			expectedError             types.GomegaMatcher
		}

		DescribeTable("Provision table",
			func(c provisionTestcase) {
				ctx := context.TODO()

				Expect(k8sClient.Create(ctx, c.options.SelectedNode)).To(Succeed())
				defer Expect(k8sClient.Delete(ctx, c.options.SelectedNode)).To(Succeed())

				provisioner := NewLiqoLocalStorageProvisioner(k8sClient, virtualStorageClassName, storageNamespace, c.localRealStorageClassName)
				Expect(provisioner).NotTo(BeNil())

				_, state, err := provisioner.Provision(ctx, c.options)
				Expect(err).To(c.expectedError)
				Expect(state).To(c.expectedState)
			},

			Entry("virtual node", provisionTestcase{
				options: controller.ProvisionOptions{
					SelectedNode: forgeNode("test", true),
				},
				expectedError: MatchError(&controller.IgnoredError{
					Reason: "the local storage provider is not providing storage for remote nodes",
				}),
				expectedState: Equal(controller.ProvisioningFinished),
			}),

			Entry("local node", provisionTestcase{
				options: controller.ProvisionOptions{
					SelectedNode: forgeNode("test", false),
					PVC:          forgePVC("test", "default"),
				},
				expectedError: MatchError("provisioning real PVC"),
				expectedState: Equal(controller.ProvisioningInBackground),
			}),
		)

		type provisionRealTestcase struct {
			pvc                       *v1.PersistentVolumeClaim
			node                      *v1.Node
			localRealStorageClassName string
			pvName                    string
			realPvName                string
		}

		DescribeTable("provision a real PVC",
			func(c provisionRealTestcase) {
				ctx := context.TODO()

				forgeOpts := func() controller.ProvisionOptions {
					return controller.ProvisionOptions{
						SelectedNode: c.node,
						PVC:          c.pvc,
						PVName:       c.pvName,
						StorageClass: &storagev1.StorageClass{
							ObjectMeta: metav1.ObjectMeta{
								Name: virtualStorageClassName,
							},
							ReclaimPolicy: func() *v1.PersistentVolumeReclaimPolicy {
								policy := v1.PersistentVolumeReclaimDelete
								return &policy
							}(),
						},
					}
				}

				Expect(k8sClient.Create(ctx, c.node)).To(Succeed())

				provisioner := NewLiqoLocalStorageProvisioner(k8sClient,
					virtualStorageClassName, storageNamespace, c.localRealStorageClassName).(*liqoLocalStorageProvisioner)
				Expect(provisioner).ToNot(BeNil())

				By("first creation")
				pv, state, err := provisioner.provisionLocalPVC(ctx, forgeOpts())
				Expect(err).To(MatchError("provisioning real PVC"))
				Expect(state).To(Equal(controller.ProvisioningInBackground))
				Expect(pv).To(BeNil())

				var realPvc v1.PersistentVolumeClaim
				Expect(k8sClient.Get(ctx, apitypes.NamespacedName{
					Name:      c.pvc.GetName(),
					Namespace: storageNamespace,
				}, &realPvc)).To(Succeed())

				if c.localRealStorageClassName != "" {
					Expect(realPvc.Spec.StorageClassName).To(PointTo(Equal(c.localRealStorageClassName)))
				} else {
					Expect(realPvc.Spec.StorageClassName).To(BeNil())
				}

				By("second attempt with no real pvc provisioned")
				pv, state, err = provisioner.provisionLocalPVC(ctx, forgeOpts())
				Expect(err).To(MatchError("real PV not provided yet"))
				Expect(state).To(Equal(controller.ProvisioningInBackground))
				Expect(pv).To(BeNil())

				By("second attempt with real pvc provisioned")
				realPv := &v1.PersistentVolume{
					ObjectMeta: metav1.ObjectMeta{
						Name: c.realPvName,
					},
					Spec: v1.PersistentVolumeSpec{
						Capacity: v1.ResourceList{
							v1.ResourceStorage: *resource.NewQuantity(10, resource.BinarySI),
						},
						PersistentVolumeSource: v1.PersistentVolumeSource{
							HostPath: &v1.HostPathVolumeSource{
								Path: "/test",
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, realPv)).To(Succeed())

				realPvc.Spec.VolumeName = c.realPvName
				Expect(k8sClient.Update(ctx, &realPvc)).To(Succeed())
				pv, state, err = provisioner.provisionLocalPVC(ctx, forgeOpts())
				Expect(err).ToNot(HaveOccurred())
				Expect(state).To(Equal(controller.ProvisioningFinished))
				Expect(pv).ToNot(BeNil())
				Expect(pv.Spec.Capacity).To(Equal(realPv.Spec.Capacity))
				Expect(pv.Spec.PersistentVolumeSource).To(Equal(realPv.Spec.PersistentVolumeSource))
				Expect(pv.Spec.StorageClassName).To(Equal(virtualStorageClassName))
			},

			Entry("empty storage class", provisionRealTestcase{
				pvc:                       forgePVC("test-real", "default"),
				node:                      forgeNode("test", false),
				localRealStorageClassName: "",
				pvName:                    "pv-name",
				realPvName:                "real-pv-name",
			}),

			Entry("defined storage class", provisionRealTestcase{
				pvc:                       forgePVC("test-real-2", "default"),
				node:                      forgeNode("test-2", false),
				localRealStorageClassName: "other-class",
				pvName:                    "pv-name-2",
				realPvName:                "real-pv-name-2",
			}),
		)

	})

})
