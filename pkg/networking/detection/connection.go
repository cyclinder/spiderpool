// Copyright 2023 Authors of spidernet-io
// SPDX-License-Identifier: Apache-2.0

package detection

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"go.uber.org/zap"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/mdlayher/arp"
	"github.com/mdlayher/ndp"
	"github.com/spidernet-io/spiderpool/api/v1/agent/models"
	"github.com/spidernet-io/spiderpool/pkg/constant"
	"github.com/spidernet-io/spiderpool/pkg/errgroup"
)

type DetectGateway struct {
	retries    int
	iface      string
	timeout    time.Duration
	V4Gw, V6Gw netip.Addr
	logger     *zap.Logger
}

func RunGatewayDetection(logger *zap.Logger, iface string, hostNetns, podNetns ns.NetNS, ips []*models.IPConfig) error {
	dg := &DetectGateway{
		retries: retryNum,
		timeout: timeOut,
		iface:   iface,
		logger:  logger,
	}

	errg := errgroup.Group{}
	for _, i := range ips {
		if i.Gateway == "" {
			continue
		}

		g := netip.MustParseAddr(i.Gateway)
		if g.Is4() {
			dg.V4Gw = g
			errg.Go(hostNetns, podNetns, dg.ArpingOverIface)
		}

		if g.Is6() {
			dg.V6Gw = g
			errg.Go(hostNetns, podNetns, dg.NDPingOverIface)
		}
	}

	return errg.Wait()
}

// PingOverIface sends an arp ping over interface 'iface' to 'dstIP'
func (dg *DetectGateway) ArpingOverIface() error {
	ifi, err := net.InterfaceByName(dg.iface)
	if err != nil {
		return err
	}

	client, err := arp.Dial(ifi)
	if err != nil {
		return err
	}
	defer client.Close()

	gwNetIP := netip.MustParseAddr(dg.V4Gw.String())
	if err = client.SetDeadline(time.Now().Add(dg.timeout)); err != nil {
		dg.logger.Sugar().Errorf("failed to set deadline: %v", err)
		return err
	}

	for i := 0; i < dg.retries; i++ {
		dg.logger.Sugar().Debugf("[Retry: %v]try to send the arp request", i+1)
		err := client.Request(gwNetIP)
		if err != nil {
			dg.logger.Sugar().Errorf("[Retry: %v]failed to send the arp request: %v", i+1, err)
			continue
		}

	}

	// Loop and wait for replies
	for {
		res, _, err := client.Read()
		if err != nil {
			dg.logger.Sugar().Errorf("gateway %s is %v, reason: %v", dg.V4Gw.String(), constant.ErrGatewayUnreachable, err)
			return fmt.Errorf("gateway %s is %v", dg.V4Gw.String(), constant.ErrGatewayUnreachable)
		}

		if res.Operation != arp.OperationReply || res.SenderIP != gwNetIP {
			continue
		}

		dg.logger.Sugar().Infof("Gateway %s is reachable, gateway is located at %v", gwNetIP, res.SenderHardwareAddr.String())
		return nil
	}
}

func (dg *DetectGateway) NDPingOverIface() error {
	ifi, err := net.InterfaceByName(dg.iface)
	if err != nil {
		return err
	}

	client, _, err := ndp.Listen(ifi, ndp.LinkLocal)
	if err != nil {
		return err
	}
	defer client.Close()

	msg := &ndp.NeighborSolicitation{
		TargetAddress: netip.MustParseAddr(dg.V6Gw.String()),
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Source,
				Addr:      ifi.HardwareAddr,
			},
		},
	}

	var gwHwAddr string
	for i := 0; i < dg.retries && gwHwAddr == ""; i++ {
		gwHwAddr, err = dg.sendReceive(client, msg)
		if err != nil {
			dg.logger.Sugar().Errorf("[retry number: %v]error detect if gateway is reachable: %v", i+1, err)
		} else if gwHwAddr != "" {
			dg.logger.Sugar().Infof("gateway %s is reachable, it is located at %s", dg.V6Gw.String(), gwHwAddr)
			return nil
		}
	}

	dg.logger.Sugar().Errorf("gateway %s is %s, reason: %v", dg.V6Gw.String(), constant.ErrGatewayUnreachable, err)
	return fmt.Errorf("gateway %s is %w", dg.V6Gw.String(), constant.ErrGatewayUnreachable)
}

func (dg *DetectGateway) sendReceive(client *ndp.Conn, m ndp.Message) (string, error) {
	gwNetIP := netip.MustParseAddr(dg.V6Gw.String())
	// Always multicast the message to the target's solicited-node multicast
	// group as if we have no knowledge of its MAC address.
	snm, err := ndp.SolicitedNodeMulticast(gwNetIP)
	if err != nil {
		dg.logger.Error("[NDP]failed to determine solicited-node multicast address", zap.Error(err))
		return "", fmt.Errorf("failed to determine solicited-node multicast address: %v", err)
	}

	if err := client.SetDeadline(time.Now().Add(dg.timeout)); err != nil {
		dg.logger.Error("[NDP]failed to set deadline", zap.Error(err))
		return "", fmt.Errorf("failed to set deadline: %v", err)
	}

	// we send a gratuitous neighbor solicitation to checking if ip is conflict
	err = client.WriteTo(m, nil, snm)
	if err != nil {
		dg.logger.Error("[NDP]failed to send message", zap.Error(err))
		return "", fmt.Errorf("failed to send message: %v", err)
	}

	msg, _, _, err := client.ReadFrom()
	if err != nil {
		return "", err
	}

	gwAddr := netip.MustParseAddr(dg.V6Gw.String())
	na, ok := msg.(*ndp.NeighborAdvertisement)
	if ok && na.TargetAddress.Compare(gwAddr) == 0 && len(na.Options) == 1 {
		dg.logger.Debug("Detect gateway: found the response", zap.String("TargetAddress", na.TargetAddress.String()))
		// found ndp reply what we want
		option, ok := na.Options[0].(*ndp.LinkLayerAddress)
		if ok {
			return option.Addr.String(), nil
		}
	}
	return "", nil
}
