// Copyright 2022 Authors of spidernet-io
// SPDX-License-Identifier: Apache-2.0

// Code generated by lister-gen. DO NOT EDIT.

package v2beta2

import (
	v2beta2 "github.com/spidernet-io/spiderpool/pkg/k8s/apis/spiderpool.spidernet.io/v2beta2"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// SpiderClaimParameterLister helps list SpiderClaimParameters.
// All objects returned here must be treated as read-only.
type SpiderClaimParameterLister interface {
	// List lists all SpiderClaimParameters in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v2beta2.SpiderClaimParameter, err error)
	// SpiderClaimParameters returns an object that can list and get SpiderClaimParameters.
	SpiderClaimParameters(namespace string) SpiderClaimParameterNamespaceLister
	SpiderClaimParameterListerExpansion
}

// spiderClaimParameterLister implements the SpiderClaimParameterLister interface.
type spiderClaimParameterLister struct {
	indexer cache.Indexer
}

// NewSpiderClaimParameterLister returns a new SpiderClaimParameterLister.
func NewSpiderClaimParameterLister(indexer cache.Indexer) SpiderClaimParameterLister {
	return &spiderClaimParameterLister{indexer: indexer}
}

// List lists all SpiderClaimParameters in the indexer.
func (s *spiderClaimParameterLister) List(selector labels.Selector) (ret []*v2beta2.SpiderClaimParameter, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v2beta2.SpiderClaimParameter))
	})
	return ret, err
}

// SpiderClaimParameters returns an object that can list and get SpiderClaimParameters.
func (s *spiderClaimParameterLister) SpiderClaimParameters(namespace string) SpiderClaimParameterNamespaceLister {
	return spiderClaimParameterNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// SpiderClaimParameterNamespaceLister helps list and get SpiderClaimParameters.
// All objects returned here must be treated as read-only.
type SpiderClaimParameterNamespaceLister interface {
	// List lists all SpiderClaimParameters in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v2beta2.SpiderClaimParameter, err error)
	// Get retrieves the SpiderClaimParameter from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v2beta2.SpiderClaimParameter, error)
	SpiderClaimParameterNamespaceListerExpansion
}

// spiderClaimParameterNamespaceLister implements the SpiderClaimParameterNamespaceLister
// interface.
type spiderClaimParameterNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all SpiderClaimParameters in the indexer for a given namespace.
func (s spiderClaimParameterNamespaceLister) List(selector labels.Selector) (ret []*v2beta2.SpiderClaimParameter, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v2beta2.SpiderClaimParameter))
	})
	return ret, err
}

// Get retrieves the SpiderClaimParameter from the indexer for a given namespace and name.
func (s spiderClaimParameterNamespaceLister) Get(name string) (*v2beta2.SpiderClaimParameter, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v2beta2.Resource("spiderclaimparameter"), name)
	}
	return obj.(*v2beta2.SpiderClaimParameter), nil
}
