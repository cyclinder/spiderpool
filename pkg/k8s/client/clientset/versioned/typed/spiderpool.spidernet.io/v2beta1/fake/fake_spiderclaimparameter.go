// Copyright 2022 Authors of spidernet-io
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v2beta1 "github.com/spidernet-io/spiderpool/pkg/k8s/apis/spiderpool.spidernet.io/v2beta2"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeSpiderClaimParameters implements SpiderClaimParameterInterface
type FakeSpiderClaimParameters struct {
	Fake *FakeSpiderpoolV2beta1
	ns   string
}

var spiderclaimparametersResource = v2beta1.SchemeGroupVersion.WithResource("spiderclaimparameters")

var spiderclaimparametersKind = v2beta1.SchemeGroupVersion.WithKind("SpiderClaimParameter")

// Get takes name of the spiderClaimParameter, and returns the corresponding spiderClaimParameter object, and an error if there is any.
func (c *FakeSpiderClaimParameters) Get(ctx context.Context, name string, options v1.GetOptions) (result *v2beta1.SpiderClaimParameter, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(spiderclaimparametersResource, c.ns, name), &v2beta1.SpiderClaimParameter{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v2beta1.SpiderClaimParameter), err
}

// List takes label and field selectors, and returns the list of SpiderClaimParameters that match those selectors.
func (c *FakeSpiderClaimParameters) List(ctx context.Context, opts v1.ListOptions) (result *v2beta1.SpiderClaimParameterList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(spiderclaimparametersResource, spiderclaimparametersKind, c.ns, opts), &v2beta1.SpiderClaimParameterList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v2beta1.SpiderClaimParameterList{ListMeta: obj.(*v2beta1.SpiderClaimParameterList).ListMeta}
	for _, item := range obj.(*v2beta1.SpiderClaimParameterList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested spiderClaimParameters.
func (c *FakeSpiderClaimParameters) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(spiderclaimparametersResource, c.ns, opts))

}

// Create takes the representation of a spiderClaimParameter and creates it.  Returns the server's representation of the spiderClaimParameter, and an error, if there is any.
func (c *FakeSpiderClaimParameters) Create(ctx context.Context, spiderClaimParameter *v2beta1.SpiderClaimParameter, opts v1.CreateOptions) (result *v2beta1.SpiderClaimParameter, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(spiderclaimparametersResource, c.ns, spiderClaimParameter), &v2beta1.SpiderClaimParameter{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v2beta1.SpiderClaimParameter), err
}

// Update takes the representation of a spiderClaimParameter and updates it. Returns the server's representation of the spiderClaimParameter, and an error, if there is any.
func (c *FakeSpiderClaimParameters) Update(ctx context.Context, spiderClaimParameter *v2beta1.SpiderClaimParameter, opts v1.UpdateOptions) (result *v2beta1.SpiderClaimParameter, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(spiderclaimparametersResource, c.ns, spiderClaimParameter), &v2beta1.SpiderClaimParameter{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v2beta1.SpiderClaimParameter), err
}

// Delete takes name of the spiderClaimParameter and deletes it. Returns an error if one occurs.
func (c *FakeSpiderClaimParameters) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(spiderclaimparametersResource, c.ns, name, opts), &v2beta1.SpiderClaimParameter{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeSpiderClaimParameters) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(spiderclaimparametersResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v2beta1.SpiderClaimParameterList{})
	return err
}

// Patch applies the patch and returns the patched spiderClaimParameter.
func (c *FakeSpiderClaimParameters) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2beta1.SpiderClaimParameter, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(spiderclaimparametersResource, c.ns, name, pt, data, subresources...), &v2beta1.SpiderClaimParameter{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v2beta1.SpiderClaimParameter), err
}
