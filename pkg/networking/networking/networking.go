// Copyright 2025 Authors of spidernet-io
// SPDX-License-Identifier: Apache-2.0

// these source file is come from:
// https://github.com/k8snetworkplumbingwg/sriov-cni/blob/master/pkg/utils/packet.go
// All copyrights belong to its authors.
package networking

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

func SendGratuitousARP(iface string, srcIP net.IP) error {
	return nil
}

func SendUnsolicitedNeighborAdvertisement(srcIP net.IP) error {
	return nil
}
