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

// SpiderClaimParametersGetter has a method to return a SpiderClaimParameterInterface.
// A group's client should implement this interface.
type SpiderClaimParametersGetter interface {
	SpiderClaimParameters(namespace string) SpiderClaimParameterInterface
}

// SpiderClaimParameterInterface has methods to work with SpiderClaimParameter resources.
type SpiderClaimParameterInterface interface {
	Create(ctx context.Context, spiderClaimParameter *v2beta2.SpiderClaimParameter, opts v1.CreateOptions) (*v2beta2.SpiderClaimParameter, error)
	Update(ctx context.Context, spiderClaimParameter *v2beta2.SpiderClaimParameter, opts v1.UpdateOptions) (*v2beta2.SpiderClaimParameter, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v2beta2.SpiderClaimParameter, error)
	List(ctx context.Context, opts v1.ListOptions) (*v2beta2.SpiderClaimParameterList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2beta2.SpiderClaimParameter, err error)
	SpiderClaimParameterExpansion
}

// spiderClaimParameters implements SpiderClaimParameterInterface
type spiderClaimParameters struct {
	client rest.Interface
	ns     string
}

// newSpiderClaimParameters returns a SpiderClaimParameters
func newSpiderClaimParameters(c *SpiderpoolV2beta2Client, namespace string) *spiderClaimParameters {
	return &spiderClaimParameters{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the spiderClaimParameter, and returns the corresponding spiderClaimParameter object, and an error if there is any.
func (c *spiderClaimParameters) Get(ctx context.Context, name string, options v1.GetOptions) (result *v2beta2.SpiderClaimParameter, err error) {
	result = &v2beta2.SpiderClaimParameter{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("spiderclaimparameters").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of SpiderClaimParameters that match those selectors.
func (c *spiderClaimParameters) List(ctx context.Context, opts v1.ListOptions) (result *v2beta2.SpiderClaimParameterList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v2beta2.SpiderClaimParameterList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("spiderclaimparameters").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested spiderClaimParameters.
func (c *spiderClaimParameters) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("spiderclaimparameters").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a spiderClaimParameter and creates it.  Returns the server's representation of the spiderClaimParameter, and an error, if there is any.
func (c *spiderClaimParameters) Create(ctx context.Context, spiderClaimParameter *v2beta2.SpiderClaimParameter, opts v1.CreateOptions) (result *v2beta2.SpiderClaimParameter, err error) {
	result = &v2beta2.SpiderClaimParameter{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("spiderclaimparameters").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(spiderClaimParameter).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a spiderClaimParameter and updates it. Returns the server's representation of the spiderClaimParameter, and an error, if there is any.
func (c *spiderClaimParameters) Update(ctx context.Context, spiderClaimParameter *v2beta2.SpiderClaimParameter, opts v1.UpdateOptions) (result *v2beta2.SpiderClaimParameter, err error) {
	result = &v2beta2.SpiderClaimParameter{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("spiderclaimparameters").
		Name(spiderClaimParameter.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(spiderClaimParameter).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the spiderClaimParameter and deletes it. Returns an error if one occurs.
func (c *spiderClaimParameters) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("spiderclaimparameters").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *spiderClaimParameters) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("spiderclaimparameters").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched spiderClaimParameter.
func (c *spiderClaimParameters) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2beta2.SpiderClaimParameter, err error) {
	result = &v2beta2.SpiderClaimParameter{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("spiderclaimparameters").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
