# Configure Lossless Network For RoCE

## Introduction

In various HPC high-performance computing scenarios, the main requirements for networks are high throughput and low latency. To achieve high throughput and low latency, the industry generally uses RDMA (Remote Direct Memory Access) to replace the TCP protocol. However, RDMA networks are very sensitive to packet loss. Once packet retransmission occurs, performance will drop sharply. Therefore, to ensure that RDMA throughput is not affected, the packet loss rate must be kept below 1e-05 (one in 100,000), ideally zero.

RoCE (RDMA over Converged Ethernet) networks use PFC+ECN features to ensure no packet loss during network transmission.

- PFC: Priority Flow Control, IEEE 802.1Qbb, flow control based on priority.
- ECN: Explicit Congestion Notification, implemented by setting flags in specific bits of the IP header to indicate network congestion without dropping packets.

This document will introduce how to configure a lossless network on the host side for RoCE. Note: This does not involve switch configuration.

## How to Configure

This document provides a script to help configure a lossless network on the host side using Systemd.

1. Download the script, then add script permissions and execute

    ```shell
    cd /usr/local/bin
    curl -O https://raw.githubusercontent.com/spidernet-io/spiderpool/master/docs/usage/rdma-qos.sh
    chmod +x rdma-qos.sh
    ```

    Configure the priority queues for All RDMA traffic and CNP packets:

    ```shell
    chmod +x rdma-qos.sh 
    GPU_RDMA_PRIORITY=5 GPU_CNP_PRIORITY=6 bash rdma-qos.sh
    ```

2. Check the execution result and view the status of the Systemd service.

    After execution, you can query the configuration results using `rdma-qos.sh q` to see if they meet expectations.

    ```shell
    ./set-rdma-qos.sh q
    ======== show configuration for device eth0 / mlx5_0========
    Priority trust state: dscp
    PFC configuration:
            priority    0   1   2   3   4   5   6   7
            enabled     0   0   0   0   0   1   0   0   
            buffer      0   0   0   0   0   1   0   0   
    ECN Enabled for priority 0: /sys/class/net/eth0/ecn/roce_np/enable/0 = 1
    ECN Enabled for priority 0: /sys/class/net/eth0/ecn/roce_rp/enable/0 = 1
    ECN Enabled for priority 1: /sys/class/net/eth0/ecn/roce_np/enable/1 = 1
    ECN Enabled for priority 1: /sys/class/net/eth0/ecn/roce_rp/enable/1 = 1
    ECN Enabled for priority 2: /sys/class/net/eth0/ecn/roce_np/enable/2 = 1
    ECN Enabled for priority 2: /sys/class/net/eth0/ecn/roce_rp/enable/2 = 1
    ECN Enabled for priority 3: /sys/class/net/eth0/ecn/roce_np/enable/3 = 1
    ECN Enabled for priority 3: /sys/class/net/eth0/ecn/roce_rp/enable/3 = 1
    ECN Enabled for priority 4: /sys/class/net/eth0/ecn/roce_np/enable/4 = 1
    ECN Enabled for priority 4: /sys/class/net/eth0/ecn/roce_rp/enable/4 = 1
    ECN Enabled for priority 5: /sys/class/net/eth0/ecn/roce_np/enable/5 = 1
    ECN Enabled for priority 5: /sys/class/net/eth0/ecn/roce_rp/enable/5 = 1
    ECN Enabled for priority 6: /sys/class/net/eth0/ecn/roce_np/enable/6 = 1
    ECN Enabled for priority 6: /sys/class/net/eth0/ecn/roce_rp/enable/6 = 1
    ECN Enabled for priority 7: /sys/class/net/eth0/ecn/roce_np/enable/7 = 1
    ECN Enabled for priority 7: /sys/class/net/eth0/ecn/roce_rp/enable/7 = 1
    QOS for CNP: /sys/class/net/eth0/ecn/roce_np/cnp_dscp = 48
    cma_roce_tos: 160
    QOS for rdma: /sys/class/infiniband/mlx5_0/tc/1/traffic_class = Global tclass=160
    ```

    Check the Systemd service status:

    ```shell
    systemctl status rdma-qos.service
    journalctl -u rdma-qos.service
    ```
