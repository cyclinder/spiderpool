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

// SpiderIPPoolLister helps list SpiderIPPools.
// All objects returned here must be treated as read-only.
type SpiderIPPoolLister interface {
	// List lists all SpiderIPPools in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v2beta2.SpiderIPPool, err error)
	// Get retrieves the SpiderIPPool from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v2beta2.SpiderIPPool, error)
	SpiderIPPoolListerExpansion
}

// spiderIPPoolLister implements the SpiderIPPoolLister interface.
type spiderIPPoolLister struct {
	indexer cache.Indexer
}

// NewSpiderIPPoolLister returns a new SpiderIPPoolLister.
func NewSpiderIPPoolLister(indexer cache.Indexer) SpiderIPPoolLister {
	return &spiderIPPoolLister{indexer: indexer}
}

// List lists all SpiderIPPools in the indexer.
func (s *spiderIPPoolLister) List(selector labels.Selector) (ret []*v2beta2.SpiderIPPool, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v2beta2.SpiderIPPool))
	})
	return ret, err
}

// Get retrieves the SpiderIPPool from the index for a given name.
func (s *spiderIPPoolLister) Get(name string) (*v2beta2.SpiderIPPool, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v2beta2.Resource("spiderippool"), name)
	}
	return obj.(*v2beta2.SpiderIPPool), nil
}
