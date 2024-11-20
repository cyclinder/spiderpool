// Copyright 2022 Authors of spidernet-io
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package v2beta2

import (
	"context"
	"time"

	v2beta2 "github.com/spidernet-io/spiderpool/pkg/k8s/apis/spiderpool.spidernet.io/v2beta2"
	scheme "github.com/spidernet-io/spiderpool/pkg/k8s/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// SpiderSubnetsGetter has a method to return a SpiderSubnetInterface.
// A group's client should implement this interface.
type SpiderSubnetsGetter interface {
	SpiderSubnets() SpiderSubnetInterface
}

// SpiderSubnetInterface has methods to work with SpiderSubnet resources.
type SpiderSubnetInterface interface {
	Create(ctx context.Context, spiderSubnet *v2beta2.SpiderSubnet, opts v1.CreateOptions) (*v2beta2.SpiderSubnet, error)
	Update(ctx context.Context, spiderSubnet *v2beta2.SpiderSubnet, opts v1.UpdateOptions) (*v2beta2.SpiderSubnet, error)
	UpdateStatus(ctx context.Context, spiderSubnet *v2beta2.SpiderSubnet, opts v1.UpdateOptions) (*v2beta2.SpiderSubnet, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v2beta2.SpiderSubnet, error)
	List(ctx context.Context, opts v1.ListOptions) (*v2beta2.SpiderSubnetList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2beta2.SpiderSubnet, err error)
	SpiderSubnetExpansion
}

// spiderSubnets implements SpiderSubnetInterface
type spiderSubnets struct {
	client rest.Interface
}

// newSpiderSubnets returns a SpiderSubnets
func newSpiderSubnets(c *SpiderpoolV2beta2Client) *spiderSubnets {
	return &spiderSubnets{
		client: c.RESTClient(),
	}
}

// Get takes name of the spiderSubnet, and returns the corresponding spiderSubnet object, and an error if there is any.
func (c *spiderSubnets) Get(ctx context.Context, name string, options v1.GetOptions) (result *v2beta2.SpiderSubnet, err error) {
	result = &v2beta2.SpiderSubnet{}
	err = c.client.Get().
		Resource("spidersubnets").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of SpiderSubnets that match those selectors.
func (c *spiderSubnets) List(ctx context.Context, opts v1.ListOptions) (result *v2beta2.SpiderSubnetList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v2beta2.SpiderSubnetList{}
	err = c.client.Get().
		Resource("spidersubnets").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested spiderSubnets.
func (c *spiderSubnets) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("spidersubnets").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a spiderSubnet and creates it.  Returns the server's representation of the spiderSubnet, and an error, if there is any.
func (c *spiderSubnets) Create(ctx context.Context, spiderSubnet *v2beta2.SpiderSubnet, opts v1.CreateOptions) (result *v2beta2.SpiderSubnet, err error) {
	result = &v2beta2.SpiderSubnet{}
	err = c.client.Post().
		Resource("spidersubnets").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(spiderSubnet).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a spiderSubnet and updates it. Returns the server's representation of the spiderSubnet, and an error, if there is any.
func (c *spiderSubnets) Update(ctx context.Context, spiderSubnet *v2beta2.SpiderSubnet, opts v1.UpdateOptions) (result *v2beta2.SpiderSubnet, err error) {
	result = &v2beta2.SpiderSubnet{}
	err = c.client.Put().
		Resource("spidersubnets").
		Name(spiderSubnet.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(spiderSubnet).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *spiderSubnets) UpdateStatus(ctx context.Context, spiderSubnet *v2beta2.SpiderSubnet, opts v1.UpdateOptions) (result *v2beta2.SpiderSubnet, err error) {
	result = &v2beta2.SpiderSubnet{}
	err = c.client.Put().
		Resource("spidersubnets").
		Name(spiderSubnet.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(spiderSubnet).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the spiderSubnet and deletes it. Returns an error if one occurs.
func (c *spiderSubnets) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("spidersubnets").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *spiderSubnets) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("spidersubnets").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched spiderSubnet.
func (c *spiderSubnets) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2beta2.SpiderSubnet, err error) {
	result = &v2beta2.SpiderSubnet{}
	err = c.client.Patch(pt).
		Resource("spidersubnets").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
