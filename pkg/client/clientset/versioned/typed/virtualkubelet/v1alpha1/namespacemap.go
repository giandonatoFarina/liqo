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

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	"time"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"

	v1alpha1 "github.com/liqotech/liqo/apis/virtualkubelet/v1alpha1"
	scheme "github.com/liqotech/liqo/pkg/client/clientset/versioned/scheme"
)

// NamespaceMapsGetter has a method to return a NamespaceMapInterface.
// A group's client should implement this interface.
type NamespaceMapsGetter interface {
	NamespaceMaps(namespace string) NamespaceMapInterface
}

// NamespaceMapInterface has methods to work with NamespaceMap resources.
type NamespaceMapInterface interface {
	Create(ctx context.Context, namespaceMap *v1alpha1.NamespaceMap, opts v1.CreateOptions) (*v1alpha1.NamespaceMap, error)
	Update(ctx context.Context, namespaceMap *v1alpha1.NamespaceMap, opts v1.UpdateOptions) (*v1alpha1.NamespaceMap, error)
	UpdateStatus(ctx context.Context, namespaceMap *v1alpha1.NamespaceMap, opts v1.UpdateOptions) (*v1alpha1.NamespaceMap, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.NamespaceMap, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.NamespaceMapList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.NamespaceMap, err error)
	NamespaceMapExpansion
}

// namespaceMaps implements NamespaceMapInterface
type namespaceMaps struct {
	client rest.Interface
	ns     string
}

// newNamespaceMaps returns a NamespaceMaps
func newNamespaceMaps(c *VirtualkubeletV1alpha1Client, namespace string) *namespaceMaps {
	return &namespaceMaps{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the namespaceMap, and returns the corresponding namespaceMap object, and an error if there is any.
func (c *namespaceMaps) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.NamespaceMap, err error) {
	result = &v1alpha1.NamespaceMap{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("namespacemaps").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of NamespaceMaps that match those selectors.
func (c *namespaceMaps) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.NamespaceMapList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.NamespaceMapList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("namespacemaps").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested namespaceMaps.
func (c *namespaceMaps) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("namespacemaps").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a namespaceMap and creates it.  Returns the server's representation of the namespaceMap, and an error, if there is any.
func (c *namespaceMaps) Create(ctx context.Context, namespaceMap *v1alpha1.NamespaceMap, opts v1.CreateOptions) (result *v1alpha1.NamespaceMap, err error) {
	result = &v1alpha1.NamespaceMap{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("namespacemaps").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(namespaceMap).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a namespaceMap and updates it. Returns the server's representation of the namespaceMap, and an error, if there is any.
func (c *namespaceMaps) Update(ctx context.Context, namespaceMap *v1alpha1.NamespaceMap, opts v1.UpdateOptions) (result *v1alpha1.NamespaceMap, err error) {
	result = &v1alpha1.NamespaceMap{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("namespacemaps").
		Name(namespaceMap.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(namespaceMap).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *namespaceMaps) UpdateStatus(ctx context.Context, namespaceMap *v1alpha1.NamespaceMap, opts v1.UpdateOptions) (result *v1alpha1.NamespaceMap, err error) {
	result = &v1alpha1.NamespaceMap{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("namespacemaps").
		Name(namespaceMap.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(namespaceMap).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the namespaceMap and deletes it. Returns an error if one occurs.
func (c *namespaceMaps) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("namespacemaps").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *namespaceMaps) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("namespacemaps").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched namespaceMap.
func (c *namespaceMaps) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.NamespaceMap, err error) {
	result = &v1alpha1.NamespaceMap{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("namespacemaps").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
