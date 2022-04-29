#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Spider

kind load docker-image $IMAGE_MULTUS --name $1
kind load docker-image $TEST_IMAGE --name $1
kubectl apply -f $(pwd)/yamls/multus-daemonset-thick-plugin.yml --kubeconfig $2