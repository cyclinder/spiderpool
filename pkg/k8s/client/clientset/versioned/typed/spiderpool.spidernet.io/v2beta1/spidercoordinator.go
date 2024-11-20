// Copyright 2022 Authors of spidernet-io
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package v2beta1

import (
	"context"
	"time"

	v2beta1 "github.com/spidernet-io/spiderpool/pkg/k8s/apis/spiderpool.spidernet.io/v2beta2"
	scheme "github.com/spidernet-io/spiderpool/pkg/k8s/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// SpiderCoordinatorsGetter has a method to return a SpiderCoordinatorInterface.
// A group's client should implement this interface.
type SpiderCoordinatorsGetter interface {
	SpiderCoordinators() SpiderCoordinatorInterface
}

// SpiderCoordinatorInterface has methods to work with SpiderCoordinator resources.
type SpiderCoordinatorInterface interface {
	Create(ctx context.Context, spiderCoordinator *v2beta1.SpiderCoordinator, opts v1.CreateOptions) (*v2beta1.SpiderCoordinator, error)
	Update(ctx context.Context, spiderCoordinator *v2beta1.SpiderCoordinator, opts v1.UpdateOptions) (*v2beta1.SpiderCoordinator, error)
	UpdateStatus(ctx context.Context, spiderCoordinator *v2beta1.SpiderCoordinator, opts v1.UpdateOptions) (*v2beta1.SpiderCoordinator, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v2beta1.SpiderCoordinator, error)
	List(ctx context.Context, opts v1.ListOptions) (*v2beta1.SpiderCoordinatorList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2beta1.SpiderCoordinator, err error)
	SpiderCoordinatorExpansion
}

// spiderCoordinators implements SpiderCoordinatorInterface
type spiderCoordinators struct {
	client rest.Interface
}

// newSpiderCoordinators returns a SpiderCoordinators
func newSpiderCoordinators(c *SpiderpoolV2beta1Client) *spiderCoordinators {
	return &spiderCoordinators{
		client: c.RESTClient(),
	}
}

// Get takes name of the spiderCoordinator, and returns the corresponding spiderCoordinator object, and an error if there is any.
func (c *spiderCoordinators) Get(ctx context.Context, name string, options v1.GetOptions) (result *v2beta1.SpiderCoordinator, err error) {
	result = &v2beta1.SpiderCoordinator{}
	err = c.client.Get().
		Resource("spidercoordinators").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of SpiderCoordinators that match those selectors.
func (c *spiderCoordinators) List(ctx context.Context, opts v1.ListOptions) (result *v2beta1.SpiderCoordinatorList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v2beta1.SpiderCoordinatorList{}
	err = c.client.Get().
		Resource("spidercoordinators").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested spiderCoordinators.
func (c *spiderCoordinators) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("spidercoordinators").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a spiderCoordinator and creates it.  Returns the server's representation of the spiderCoordinator, and an error, if there is any.
func (c *spiderCoordinators) Create(ctx context.Context, spiderCoordinator *v2beta1.SpiderCoordinator, opts v1.CreateOptions) (result *v2beta1.SpiderCoordinator, err error) {
	result = &v2beta1.SpiderCoordinator{}
	err = c.client.Post().
		Resource("spidercoordinators").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(spiderCoordinator).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a spiderCoordinator and updates it. Returns the server's representation of the spiderCoordinator, and an error, if there is any.
func (c *spiderCoordinators) Update(ctx context.Context, spiderCoordinator *v2beta1.SpiderCoordinator, opts v1.UpdateOptions) (result *v2beta1.SpiderCoordinator, err error) {
	result = &v2beta1.SpiderCoordinator{}
	err = c.client.Put().
		Resource("spidercoordinators").
		Name(spiderCoordinator.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(spiderCoordinator).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *spiderCoordinators) UpdateStatus(ctx context.Context, spiderCoordinator *v2beta1.SpiderCoordinator, opts v1.UpdateOptions) (result *v2beta1.SpiderCoordinator, err error) {
	result = &v2beta1.SpiderCoordinator{}
	err = c.client.Put().
		Resource("spidercoordinators").
		Name(spiderCoordinator.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(spiderCoordinator).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the spiderCoordinator and deletes it. Returns an error if one occurs.
func (c *spiderCoordinators) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("spidercoordinators").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *spiderCoordinators) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("spidercoordinators").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched spiderCoordinator.
func (c *spiderCoordinators) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2beta1.SpiderCoordinator, err error) {
	result = &v2beta1.SpiderCoordinator{}
	err = c.client.Patch(pt).
		Resource("spidercoordinators").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
