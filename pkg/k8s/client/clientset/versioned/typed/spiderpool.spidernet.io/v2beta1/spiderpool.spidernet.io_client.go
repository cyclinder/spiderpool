// Copyright 2022 Authors of spidernet-io
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package v2beta1

import (
	"net/http"

	v2beta1 "github.com/spidernet-io/spiderpool/pkg/k8s/apis/spiderpool.spidernet.io/v2beta2"
	"github.com/spidernet-io/spiderpool/pkg/k8s/client/clientset/versioned/scheme"
	rest "k8s.io/client-go/rest"
)

type SpiderpoolV2beta1Interface interface {
	RESTClient() rest.Interface
	SpiderClaimParametersGetter
	SpiderCoordinatorsGetter
	SpiderIPPoolsGetter
	SpiderMultusConfigsGetter
	SpiderSubnetsGetter
}

// SpiderpoolV2beta1Client is used to interact with features provided by the spiderpool.spidernet.io group.
type SpiderpoolV2beta1Client struct {
	restClient rest.Interface
}

func (c *SpiderpoolV2beta1Client) SpiderClaimParameters(namespace string) SpiderClaimParameterInterface {
	return newSpiderClaimParameters(c, namespace)
}

func (c *SpiderpoolV2beta1Client) SpiderCoordinators() SpiderCoordinatorInterface {
	return newSpiderCoordinators(c)
}

func (c *SpiderpoolV2beta1Client) SpiderIPPools() SpiderIPPoolInterface {
	return newSpiderIPPools(c)
}

func (c *SpiderpoolV2beta1Client) SpiderMultusConfigs(namespace string) SpiderMultusConfigInterface {
	return newSpiderMultusConfigs(c, namespace)
}

func (c *SpiderpoolV2beta1Client) SpiderSubnets() SpiderSubnetInterface {
	return newSpiderSubnets(c)
}

// NewForConfig creates a new SpiderpoolV2beta1Client for the given config.
// NewForConfig is equivalent to NewForConfigAndClient(c, httpClient),
// where httpClient was generated with rest.HTTPClientFor(c).
func NewForConfig(c *rest.Config) (*SpiderpoolV2beta1Client, error) {
	config := *c
	if err := setConfigDefaults(&config); err != nil {
		return nil, err
	}
	httpClient, err := rest.HTTPClientFor(&config)
	if err != nil {
		return nil, err
	}
	return NewForConfigAndClient(&config, httpClient)
}

// NewForConfigAndClient creates a new SpiderpoolV2beta1Client for the given config and http client.
// Note the http client provided takes precedence over the configured transport values.
func NewForConfigAndClient(c *rest.Config, h *http.Client) (*SpiderpoolV2beta1Client, error) {
	config := *c
	if err := setConfigDefaults(&config); err != nil {
		return nil, err
	}
	client, err := rest.RESTClientForConfigAndClient(&config, h)
	if err != nil {
		return nil, err
	}
	return &SpiderpoolV2beta1Client{client}, nil
}

// NewForConfigOrDie creates a new SpiderpoolV2beta1Client for the given config and
// panics if there is an error in the config.
func NewForConfigOrDie(c *rest.Config) *SpiderpoolV2beta1Client {
	client, err := NewForConfig(c)
	if err != nil {
		panic(err)
	}
	return client
}

// New creates a new SpiderpoolV2beta1Client for the given RESTClient.
func New(c rest.Interface) *SpiderpoolV2beta1Client {
	return &SpiderpoolV2beta1Client{c}
}

func setConfigDefaults(config *rest.Config) error {
	gv := v2beta1.SchemeGroupVersion
	config.GroupVersion = &gv
	config.APIPath = "/apis"
	config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()

	if config.UserAgent == "" {
		config.UserAgent = rest.DefaultKubernetesUserAgent()
	}

	return nil
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *SpiderpoolV2beta1Client) RESTClient() rest.Interface {
	if c == nil {
		return nil
	}
	return c.restClient
}
