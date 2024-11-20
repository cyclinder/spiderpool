// Copyright 2022 Authors of spidernet-io
// SPDX-License-Identifier: Apache-2.0

// Code generated by informer-gen. DO NOT EDIT.

package v2beta2

import (
	"context"
	time "time"

	spiderpoolspidernetiov2beta2 "github.com/spidernet-io/spiderpool/pkg/k8s/apis/spiderpool.spidernet.io/v2beta2"
	versioned "github.com/spidernet-io/spiderpool/pkg/k8s/client/clientset/versioned"
	internalinterfaces "github.com/spidernet-io/spiderpool/pkg/k8s/client/informers/externalversions/internalinterfaces"
	v2beta2 "github.com/spidernet-io/spiderpool/pkg/k8s/client/listers/spiderpool.spidernet.io/v2beta2"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// SpiderIPPoolInformer provides access to a shared informer and lister for
// SpiderIPPools.
type SpiderIPPoolInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v2beta2.SpiderIPPoolLister
}

type spiderIPPoolInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewSpiderIPPoolInformer constructs a new informer for SpiderIPPool type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewSpiderIPPoolInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredSpiderIPPoolInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredSpiderIPPoolInformer constructs a new informer for SpiderIPPool type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredSpiderIPPoolInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.SpiderpoolV2beta2().SpiderIPPools().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.SpiderpoolV2beta2().SpiderIPPools().Watch(context.TODO(), options)
			},
		},
		&spiderpoolspidernetiov2beta2.SpiderIPPool{},
		resyncPeriod,
		indexers,
	)
}

func (f *spiderIPPoolInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredSpiderIPPoolInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *spiderIPPoolInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&spiderpoolspidernetiov2beta2.SpiderIPPool{}, f.defaultInformer)
}

func (f *spiderIPPoolInformer) Lister() v2beta2.SpiderIPPoolLister {
	return v2beta2.NewSpiderIPPoolLister(f.Informer().GetIndexer())
}
