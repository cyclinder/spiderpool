// Copyright 2022 Authors of spidernet-io
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubevirtv1 "kubevirt.io/api/core/v1"

	"github.com/spidernet-io/spiderpool/api/v1/agent/models"
	"github.com/spidernet-io/spiderpool/api/v1/agent/server/restapi/daemonset"
	"github.com/spidernet-io/spiderpool/pkg/constant"
	"github.com/spidernet-io/spiderpool/pkg/logutils"
	"github.com/spidernet-io/spiderpool/pkg/metric"
)

// Singleton.
var (
	unixPostAgentIpamIp    = &_unixPostAgentIpamIp{}
	unixDeleteAgentIpamIp  = &_unixDeleteAgentIpamIp{}
	unixPostAgentIpamIps   = &_unixPostAgentIpamIps{}
	unixDeleteAgentIpamIps = &_unixDeleteAgentIpamIps{}
)

type _unixPostAgentIpamIp struct{}

// Handle handles POST requests for /ipam/ip.
func (g *_unixPostAgentIpamIp) Handle(params daemonset.PostIpamIPParams) middleware.Responder {
	if err := params.IpamAddArgs.Validate(strfmt.Default); err != nil {
		return daemonset.NewPostIpamIPFailure().WithPayload(models.Error(err.Error()))
	}

	logger := logutils.Logger.Named("IPAM").With(
		zap.String("CNICommand", "ADD"),
		zap.String("ContainerID", *params.IpamAddArgs.ContainerID),
		zap.String("IfName", *params.IpamAddArgs.IfName),
		zap.String("NetNamespace", *params.IpamAddArgs.NetNamespace),
		zap.String("PodNamespace", *params.IpamAddArgs.PodNamespace),
		zap.String("PodName", *params.IpamAddArgs.PodName),
		zap.String("PodUID", *params.IpamAddArgs.PodUID),
	)
	ctx := logutils.IntoContext(params.HTTPRequest.Context(), logger)

	// The total count of IP allocations.
	metric.IpamAllocationTotalCounts.Add(ctx, 1)

	timeRecorder := metric.NewTimeRecorder()
	defer func() {
		// Time taken for once IP allocation.
		allocationDuration := timeRecorder.SinceInSeconds()
		metric.IPAMDurationConstruct.RecordIPAMAllocationDuration(ctx, allocationDuration)
		logger.Sugar().Infof("IPAM allocation duration: %v", allocationDuration)
	}()

	resp, err := agentContext.IPAM.Allocate(ctx, params.IpamAddArgs)
	if err != nil {
		// The count of failures in IP allocations.
		metric.IpamAllocationFailureCounts.Add(ctx, 1)
		gatherIPAMAllocationErrMetric(ctx, err)
		logger.Error(err.Error())

		return daemonset.NewPostIpamIPFailure().WithPayload(models.Error(err.Error()))
	}

	return daemonset.NewPostIpamIPOK().WithPayload(resp)
}

type _unixDeleteAgentIpamIp struct{}

// Handle handles DELETE requests for /ipam/ip.
func (g *_unixDeleteAgentIpamIp) Handle(params daemonset.DeleteIpamIPParams) middleware.Responder {
	if err := params.IpamDelArgs.Validate(strfmt.Default); err != nil {
		return daemonset.NewDeleteIpamIPFailure().WithPayload(models.Error(err.Error()))
	}

	logger := logutils.Logger.Named("IPAM").With(
		zap.String("CNICommand", "DEL"),
		zap.String("ContainerID", *params.IpamDelArgs.ContainerID),
		zap.String("IfName", *params.IpamDelArgs.IfName),
		zap.String("NetNamespace", params.IpamDelArgs.NetNamespace),
		zap.String("PodNamespace", *params.IpamDelArgs.PodNamespace),
		zap.String("PodName", *params.IpamDelArgs.PodName),
		zap.String("PodUID", *params.IpamDelArgs.PodUID),
	)
	ctx := logutils.IntoContext(params.HTTPRequest.Context(), logger)

	// The total count of IP releasing.
	metric.IpamReleaseTotalCounts.Add(ctx, 1)

	timeRecorder := metric.NewTimeRecorder()
	defer func() {
		// Time taken for once IP releasing.
		releaseDuration := timeRecorder.SinceInSeconds()
		metric.IPAMDurationConstruct.RecordIPAMReleaseDuration(ctx, releaseDuration)
		logger.Sugar().Infof("IPAM releasing duration: %v", releaseDuration)
	}()

	if err := agentContext.IPAM.Release(ctx, params.IpamDelArgs); err != nil {
		// The count of failures in IP releasing.
		metric.IpamReleaseFailureCounts.Add(ctx, 1)
		gatherIPAMReleasingErrMetric(ctx, err)
		logger.Error(err.Error())

		return daemonset.NewDeleteIpamIPFailure().WithPayload(models.Error(err.Error()))
	}

	return daemonset.NewDeleteIpamIPOK()
}

type _unixPostAgentIpamIps struct{}

// Handle handles POST requests for /ipam/ips.
func (g *_unixPostAgentIpamIps) Handle(params daemonset.PostIpamIpsParams) middleware.Responder {
	return daemonset.NewPostIpamIpsOK()
}

type _unixDeleteAgentIpamIps struct{}

// Handle handles DELETE requests for /ipam/ips.
func (g *_unixDeleteAgentIpamIps) Handle(params daemonset.DeleteIpamIpsParams) middleware.Responder {
	err := params.IpamBatchDelArgs.Validate(strfmt.Default)
	if err != nil {
		return daemonset.NewDeleteIpamIpsFailure().WithPayload(models.Error(err.Error()))
	}

	log := logutils.Logger.Named("IPAM").With(
		zap.String("Operation", "Release IPs"),
		zap.String("ContainerID", *params.IpamBatchDelArgs.ContainerID),
		zap.String("NetNamespace", params.IpamBatchDelArgs.NetNamespace),
		zap.String("PodNamespace", *params.IpamBatchDelArgs.PodNamespace),
		zap.String("PodName", *params.IpamBatchDelArgs.PodName),
		zap.String("PodUID", *params.IpamBatchDelArgs.PodUID),
	)
	ctx := logutils.IntoContext(params.HTTPRequest.Context(), log)

	// The total count of IP releasing.
	metric.IpamReleaseTotalCounts.Add(ctx, 1)

	timeRecorder := metric.NewTimeRecorder()
	defer func() {
		// Time taken for once IP releasing.
		releaseDuration := timeRecorder.SinceInSeconds()
		metric.IPAMDurationConstruct.RecordIPAMReleaseDuration(ctx, releaseDuration)
		logger.Sugar().Infof("IPAM releasing duration: %v", releaseDuration)
	}()

	err = agentContext.IPAM.ReleaseIPs(ctx, params.IpamBatchDelArgs)
	if nil != err {
		// The count of failures in IP releasing.
		metric.IpamReleaseFailureCounts.Add(ctx, 1)
		gatherIPAMReleasingErrMetric(ctx, err)
		logger.Error(err.Error())
		return filteredErrResponder(err)
	}

	return daemonset.NewDeleteIpamIpsOK()
}

type _unixGetIpamIPDetectionConfigs struct{}

// Handle handles GET requests for /ipam/ip-detection-configs.
func (g *_unixGetIpamIPDetectionConfigs) Handle(params daemonset.GetIpamIPDetectionConfigsParams) middleware.Responder {
	err := params.GetIPDetectionConfig.Validate(strfmt.Default)
	if err != nil {
		return daemonset.NewGetCoordinatorConfigFailure().WithPayload(models.Error(err.Error()))
	}

	log := logutils.Logger.Named("IPAM").With(
		zap.String("Operation", "Get IPGateway detection configs"),
		zap.String("PodNamespace", *&params.GetIPDetectionConfig.PodNamespace),
		zap.String("PodName", *&params.GetIPDetectionConfig.PodName),
	)
	ctx := logutils.IntoContext(params.HTTPRequest.Context(), log)

	config := agentContext.IPAM.GetIPGatewayDetectionConfigs(ctx)

	podClient := agentContext.PodManager
	kubevirtMgr := agentContext.KubevirtManager
	pod, err := podClient.GetPodByName(ctx, params.GetIPDetectionConfig.PodNamespace, params.GetIPDetectionConfig.PodName, constant.UseCache)
	if err != nil {
		return daemonset.NewGetCoordinatorConfigFailure().WithPayload(models.Error(fmt.Sprintf("failed to get pod %s/%s", params.GetIPDetectionConfig.PodNamespace, params.GetIPDetectionConfig.PodName)))
	}

	isVMPod := false
	// kubevirt vm pod corresponding SpiderEndpoint uses kubevirt VM/VMI name
	ownerReference := metav1.GetControllerOf(pod)
	if ownerReference != nil && agentContext.Cfg.EnableKubevirtStaticIP && ownerReference.APIVersion == kubevirtv1.SchemeGroupVersion.String() && ownerReference.Kind == constant.KindKubevirtVMI {
		isVMPod = true
	}

	// cancel IP conflict detection for the kubevirt vm live migration new pod
	if config.EnableIPConflictDetection && isVMPod {
		// the live migration new pod has the annotation "kubevirt.io/migrationJobName"
		// we just only cancel IP conflict detection for the live migration new pod.
		podAnnos := pod.GetAnnotations()
		vmimName, ok := podAnnos[kubevirtv1.MigrationJobNameAnnotation]
		if ok {
			_, err := kubevirtMgr.GetVMIMByName(ctx, pod.Namespace, vmimName, false)
			if nil != err {
				if apierrors.IsNotFound(err) {
					logger.Sugar().Warnf("no kubevirt vm pod '%s/%s' corresponding VirtualMachineInstanceMigration '%s/%s' found, still execute IP conflict detection",
						pod.Namespace, pod.Name, pod.Namespace, vmimName)
				} else {
					return daemonset.NewGetCoordinatorConfigFailure().WithPayload(models.Error(fmt.Sprintf("failed to get kubevirt vm pod '%s/%s' corresponding VirtualMachineInstanceMigration '%s/%s', error: %v",
						pod.Namespace, pod.Name, pod.Namespace, vmimName, err)))
				}
			} else {
				// cancel IP conflict detection because there's a moment the old vm pod still running during the vm live migration phase
				logger.Sugar().Infof("cancel IP conflict detection for live migration new pod '%s/%s'", pod.Namespace, pod.Name)
				config.EnableIPConflictDetection = false
			}
		}
	}

	return daemonset.NewGetIpamIPDetectionConfigsOK().WithPayload(config)
}

func gatherIPAMAllocationErrMetric(ctx context.Context, err error) {
	internal := true
	if errors.Is(err, constant.ErrWrongInput) {
		metric.IpamAllocationErrRetriesExhaustedCounts.Add(ctx, 1)
		internal = false
	}
	if errors.Is(err, constant.ErrNoAvailablePool) {
		metric.IpamAllocationErrNoAvailablePoolCounts.Add(ctx, 1)
		internal = false
	}
	if errors.Is(err, constant.ErrRetriesExhausted) {
		metric.IpamAllocationErrRetriesExhaustedCounts.Add(ctx, 1)
		internal = false
	}
	if errors.Is(err, constant.ErrIPUsedOut) {
		metric.IpamAllocationErrIPUsedOutCounts.Add(ctx, 1)
		internal = false
	}

	if internal {
		metric.IpamAllocationErrInternalCounts.Add(ctx, 1)
	}
}

func gatherIPAMReleasingErrMetric(ctx context.Context, err error) {
	internal := true
	if errors.Is(err, constant.ErrRetriesExhausted) {
		metric.IpamReleaseErrRetriesExhaustedCounts.Add(ctx, 1)
		internal = false
	}

	if internal {
		metric.IpamReleaseErrInternalCounts.Add(ctx, 1)
	}
}

func filteredErrResponder(err error) middleware.Responder {
	switch {
	case errors.Is(err, constant.ErrForbidReleasingStatelessWorkload):
		return daemonset.NewDeleteIpamIpsStatus521().WithPayload(models.Error(err.Error()))
	case errors.Is(err, constant.ErrForbidReleasingStatefulWorkload):
		return daemonset.NewDeleteIpamIpsStatus522().WithPayload(models.Error(err.Error()))
	default:
		return daemonset.NewDeleteIpamIpsFailure().WithPayload(models.Error(err.Error()))
	}
}
