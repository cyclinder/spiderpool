// Copyright 2025 Authors of spidernet-io
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/pkg/ns"
	"go.uber.org/zap"

	agentOpenAPIClient "github.com/spidernet-io/spiderpool/api/v1/agent/client"
	"github.com/spidernet-io/spiderpool/api/v1/agent/client/daemonset"
	"github.com/spidernet-io/spiderpool/api/v1/agent/models"
	"github.com/spidernet-io/spiderpool/pkg/logutils"
	"github.com/spidernet-io/spiderpool/pkg/networking/detection"
)

// Set up file logging for spiderpool bin.
func setupFileLogging(conf *NetConf) (*zap.Logger, error) {
	v := logutils.ConvertLogLevel(conf.IPAM.LogLevel)
	if v == nil {
		return nil, fmt.Errorf("unsupported log level %s", conf.IPAM.LogLevel)
	}

	return logutils.InitFileLogger(
		*v,
		conf.IPAM.LogFilePath,
		conf.IPAM.LogFileMaxSize,
		conf.IPAM.LogFileMaxAge,
		conf.IPAM.LogFileMaxCount,
	)
}

func DetectIPGateway(iface string, hostNs, podNetns ns.NetNS, ips []*models.IPConfig, detectionConfigs models.IPDetectionConfigs) error {
	if len(ips) == 0 {
		logger.Warn("No any ipAddress configured in pod, skip IPAM Detection")
		return nil
	}

	// IP conflict detection must precede gateway detection, which avoids the
	// possibility that gateway detection may update arp table entries first and cause
	// communication problems when IP conflict detection fails
	// see https://github.com/spidernet-io/spiderpool/issues/4475
	if detectionConfigs.EnableIPConflictDetection {
		logger.Debug("Start IP conflict detection")
		// call ip conflict detection
		if err := runIPConflictDetection(iface, hostNs, podNetns, ips); err != nil {
			return err
		}
	} else {
		logger.Debug("IP conflict detection is disabled")
	}

	//  we do detect gateway connection lastly
	// Finally, there is gateway detection, which updates the correct arp table entries
	// once there are no IP address conflicts and fixed Mac addresses
	if detectionConfigs.EnableGatewayDetection {
		logger.Debug("Start gateway detection")
		// call gateway detection
		if err := runGatewayDetection(iface, hostNs, podNetns, ips); err != nil {
			return err
		}
	} else {
		logger.Debug("Gateway detection is disabled")
	}

	return nil
}

func runIPConflictDetection(iface string, hostNs, podNetns ns.NetNS, ips []*models.IPConfig) error {
	return detection.RunIPConflictDetection(logger, iface, hostNs, podNetns, ips)
}

func runGatewayDetection(iface string, hostNs, podNetns ns.NetNS, ips []*models.IPConfig) error {
	return detection.RunGatewayDetection(logger, iface, hostNs, podNetns, ips)
}

func deleteIpamIps(spiderpoolAgentAPI *agentOpenAPIClient.SpiderpoolAgentAPI, args *skel.CmdArgs, k8sArgs K8sArgs) error {
	_, err := spiderpoolAgentAPI.Daemonset.DeleteIpamIps(daemonset.NewDeleteIpamIpsParams().WithContext(context.TODO()).WithIpamBatchDelArgs(
		&models.IpamBatchDelArgs{
			ContainerID:  &args.ContainerID,
			NetNamespace: args.Netns,
			PodName:      (*string)(&k8sArgs.K8S_POD_NAME),
			PodNamespace: (*string)(&k8sArgs.K8S_POD_NAMESPACE),
			PodUID:       (*string)(&k8sArgs.K8S_POD_UID),
		},
	))
	if err != nil {
		return fmt.Errorf("failed to clean up conflict IPs: %v", err)
	}
	return err
}
