# 一键简化 AI 应用的

## 背景

大多数 AI 集群（比如 Nvidia DGX A100）每一个节点的 GPU 和 网卡都是一一对应的，且数量都为 8 个 。一个典型的 AI 集群网络拓扑如下：

集群的网络规划如下：

1. 在节点的 eth0 网卡上运行 calico CNI，来承载 kubernetes 流量。AI workload 将会被分配一个 calico 的缺省网卡，进行控制面通信。

2. 节点上使用具备 RDMA 功能的 Mellanox 网卡来承载 AI 计算的 RDMA 流量，网卡接入到 rail optimized 网络中。AI workload 将会被额外分配所有 RDMA 网卡的 Macvlan 虚拟化接口，确保 GPU 的高速网络通信。

3. 节点内 GPU 通信通过 NVLink 高速链路直接通信，节点之间 GPU 进行跨轨通信时，需要借助 RDMA 网卡进行传输数据。

![AI Cluster](../../../images/ai-cluster.png)

> 图 1. AI 集群拓扑

当 GPU 跨节点通信时，期望使用的 RDMA 网卡与 GPU 位于同一个 PCI Switch 下，这样能开启如 GPU Direct RDMA 的特性，最大程度提高 GPU 的高速网络通信。所以在实际生产环境中，通常将主机的 8 张网卡都插入到 Pod 中，这样如 NCCL 等通信库能够自动选择最佳的 RDMA 网卡通信，但插入 8 张网卡会带来如下问题：

1. 网络配置复杂且容易出错，需要手动配置 8 张 RDMA 网卡，即需要手动为 Pod 注入 8 个 Multus 的 Annotations。

2. 需要单独为 Pod 声明 8 个 RDMA 网卡对应的网络硬件资源，因为与配置网卡的配置是独立的，极易出错。

为了简化 AI 应用的网络配置，Spiderpool 支持通过 webhook 自动为应用注入 RDMA 网卡和资源的配置，无需用户繁琐操作。

## 预先准备

> 本文基于 Macvlan 技术给 AI 应用提供 RDMA 通信能力，适用在 RoCE 网络场景。

1. 确保主机已经安装 RDMA 网卡驱动

    对于 Mellanox 网卡，可下载 [NVIDIA OFED 官方驱动](https://network.nvidia.com/products/infiniband-drivers/linux/mlnx_ofed/)进行主机安装，执行如下安装命令：

    ```shell
    mount /root/MLNX_OFED_LINUX-24.01-0.3.3.1-ubuntu22.04-x86_64.iso   /mnt
    /mnt/mlnxofedinstall --all
    ```

    对于 Mellanox 网卡，也可基于容器化安装驱动，实现对集群主机上所有 Mellanox 网卡批量安装驱动，运行如下命令，注意的是，该运行过程中需要访问因特网获取一些安装包。当所有的 ofed pod 进入 ready 状态，表示主机上已经完成了 OFED driver 安装。

    ```shell
    $ helm repo add spiderchart https://spidernet-io.github.io/charts
    $ helm repo update
    $ helm search repo ofed

    # pelase replace the following values with your actual environment
    # for china user, it could set `--set image.registry=nvcr.m.daocloud.io` to use a domestic registry
    $ helm install ofed-driver spiderchart/ofed-driver -n kube-system \
            --set image.OSName="ubuntu" \
            --set image.OSVer="22.04" \
            --set image.Arch="amd64"
    ```

2. 确认网卡支持 Ethernet 工作模式

    本示例环境中，宿主机上接入了 mellanox ConnectX 5 VPI 网卡，查询 RDMA 设备，确认网卡驱动安装完成

    ```
    $ rdma link
      link mlx5_0/1 state ACTIVE physical_state LINK_UP netdev ens6f0np0
      link mlx5_1/1 state ACTIVE physical_state LINK_UP netdev ens6f1np1
      ....... 
    ```

    确认网卡的工作模式，如下输出表示网卡工作在 Ethernet 模式下，可实现 RoCE 通信

    ```
    $ ibstat mlx5_0 | grep "Link layer"
       Link layer: Ethernet
    ```

    如下输出表示网卡工作在 Infiniband 模式下，可实现 Infiniband 通信

    ```
    $ ibstat mlx5_0 | grep "Link layer"
       Link layer: InfiniBand
    ```

    如果网卡没有工作在预期的模式下，请输入如下命令，确认网卡支持配置 LINK_TYPE 参数，如果没有该参数，请更换支持的网卡型号

    ```
    $ mst start

    # check the card's PCIE 
    $ lspci -nn | grep Mellanox
          86:00.0 Infiniband controller [0207]: Mellanox Technologies MT27800 Family [ConnectX-5] [15b3:1017]
          86:00.1 Infiniband controller [0207]: Mellanox Technologies MT27800 Family [ConnectX-5] [15b3:1017]
          ....... 

    # check whether the network card supports parameters LINK_TYPE 
    $ mlxconfig -d 86:00.0  q | grep LINK_TYPE
          LINK_TYPE_P1                                IB(1)
    ```

3. 确认主机上的 RDMA 子系统为 shared 模式，这是 macvlan 场景下提供 RDMA 设备给容器的要求。

    ```
    # Check the current operating mode (the Linux RDMA subsystem operates in shared mode by default):
    $ rdma system
       netns shared copy-on-fork on
    ```

## 安装配置 Spiderpool

## 安装 Spiderpool

1. 使用 helm 安装 Spiderpool，并启用 rdmaSharedDevicePlugin 组件

    ```shell
    helm repo add spiderpool https://spidernet-io.github.io/spiderpool
    helm repo update spiderpool
    helm install spiderpool spiderpool/spiderpool -n spiderpool --set spiderpoolController.podResourceInject.enabled=true --set rdma.rdmaSharedDevicePlugin.install=true --create-namespace
    ```

    > - 如果您是中国用户，可以指定参数 `--set global.imageRegistryOverride=ghcr.m.daocloud.io` 来使用国内的镜像源。
    > - 默认关闭 webhook 自动注入网络资源功能，需要用户手动开启。
    > - 您可以通过 `spiderpoolController.podResourceInject.namespacesExclude` 指定哪些 namespaces 不需要自动注入 RDMA 网络资源。通过 `spiderpoolController.podResourceInject.namespacesInclude` 指定需要自动注入 RDMA 网络资源的命名空间。
    > - 安装 Spiderpool 后，您可以通过更新 spiderpool-config configMap 中 podResourceInject 字段更新配置。
    > - 设置 `--set spiderpoolAgent.prometheus.enabled --set spiderpoolAgent.prometheus.enabledRdmaMetric=true` 和 `--set grafanaDashboard.install=true` 命令行参数可以开启 RDMA metrics exporter 和 Grafana dashboard，更多可以查看 [RDMA metrics](../../rdma-metrics.md).


   完成后，安装的组件如下

    ```shell
    $ kubectl get pod -n spiderpool
        spiderpool-agent-9sllh                         1/1     Running     0          1m
        spiderpool-agent-h92bv                         1/1     Running     0          1m
        spiderpool-controller-7df784cdb7-bsfwv         1/1     Running     0          1m
        spiderpool-init                                0/1     Completed   0          1m
        spiderpool-rdma-shared-device-plugin-9xsm9     1/1     Running     0          1m
        spiderpool-rdma-shared-device-plugin-nxvlx     1/1     Running     0          1m
    ```

2. 配置 k8s-rdma-shared-dev-plugin, 识别出每个主机上的 RDMA 共享设备资源

    修改如下 configmap，创建出 8 种 RDMA 共享设备，它们分别亲和每一个 GPU 设备。configmap 的详细配置可参考[官方文档](https://github.com/Mellanox/k8s-rdma-shared-dev-plugin?tab=readme-ov-file#rdma-shared-device-plugin-configurations)。

    ```shell
    $ kubectl edit configmap -n spiderpool spiderpool-rdma-shared-device-plugi
      ....
      config.json: |
        {
         "periodicUpdateInterval": 300,
         "configList": [
            {
             "resourcePrefix": "spidernet.io",
             "resourceName": "shared_cx5_gpu1",
             "rdmaHcaMax": 100,
             "selectors": { "ifNames": ["enp11s0f0np0"] }
           },
           ....
           {
             "resourcePrefix": "spidernet.io",
             "resourceName": "shared_cx5_gpu8",
             "rdmaHcaMax": 100,
             "selectors": { "ifNames": ["enp18s0f0np0"] }
           }
         ]
    ```

    完成如上配置后，可查看 node 的可用资源，确认每个节点都正确识别并上报了 8 种 RDMA 设备资源。

    ```shell
    $ kubectl get no -o json | jq -r '[.items[] | {name:.metadata.name, allocable:.status.allocatable}]'
        [
          {
            "name": "ai-10-1-16-1",
            "allocable": {
              "cpu": "40",
              "pods": "110",
              "spidernet.io/shared_cx5_gpu1": "100",
              "spidernet.io/shared_cx5_gpu2": "100",
              ...
              "spidernet.io/shared_cx5_gpu8": "100",
              ...
            }
          },
          ...
        ]
    ```

3. 创建 CNI 配置和对应的 ippool 资源

    对于 Ethernet 网络，请为所有的 GPU 亲和的 macvlan 网卡配置，并创建对应的 IP 地址池。如下例子，配置了 GPU1 亲和的网卡和 IP 地址池。

    ```shell
    $ cat <<EOF | kubectl apply -f -
    apiVersion: spiderpool.spidernet.io/v2beta1
    kind: SpiderIPPool
    metadata:
      name: gpu1-net11
    spec:
      gateway: 172.16.11.254
      subnet: 172.16.11.0/16
      ips:
        - 172.16.11.1-172.16.11.200
    ---
    apiVersion: spiderpool.spidernet.io/v2beta1
    kind: SpiderMultusConfig
    metadata:
      name: gpu1-macvlan
      namespace: spiderpool
    spec:
      cniType: macvlan
      macvlan:
        master: ["enp11s0f0np0"]
        enableRdma: true
        rdmaResourceName: spidernet.io/shared_cx5_gpu1
        ippools:
          ipv4: ["gpu1-net11"]
    EOF
    ```

    > - `cni.spidernet.io/rdma-resource-inject: gpu-macvlan` 固定的 key，value 为用户自定义。
    > - `enableRdma`, `rdmaResourceName` 和 `ippools` 必须配置，否则 Pod 无法自动注入网络资源。

4. 在指定节点上创建一组 DaemonSet 应用
   如下例子，通过 annotations `v1.multus-cni.io/default-network` 指定使用 calico 的缺省网卡，用于进行控制面通信，annotation: `cni.spidernet.io/rdma-resource-inject: gpu-macvlan`，这样 Spiderpool 自动为 Pod 添加  8 个 GPU 亲和网卡的网卡，用于 RDMA 通信，并配置 8 种 RDMA resources 资源:

    > 注意：使用 webhook 自动注入网络资源功能时，不能为应用添加其他网络配置注解(如 `k8s.v1.cni.cncf.io/networks` 和 `ipam.spidernet.io/ippools`等)，否则可能会影响资源自动注入功能。

    ```shell
    $ helm repo add spiderchart https://spidernet-io.github.io/charts
    $ helm repo update
    $ helm search repo rdma-tools
   
    # run daemonset on worker1 and worker2
    $ cat <<EOF > values.yaml
    # for china user , it could add these to use a domestic registry
    #image:
    #  registry: ghcr.m.daocloud.io

    # just run daemonset in nodes 'worker1' and 'worker2'
    affinity:
      nodeAffinity:
        requiredDuringSchedulingIgnoredDuringExecution:
          nodeSelectorTerms:
          - matchExpressions:
            - key: kubernetes.io/hostname
              operator: In
              values:
              - worker1
              - worker2

    # macvlan interfaces
    extraAnnotations:
      cni.spidernet.io/rdma-resource-inject: gpu-macvlan
    EOF

    $ helm install rdma-tools spiderchart/rdma-tools -f ./values.yaml
    ```

    当 Pod 成功 Running，检查 Pod 是否成功注入 8 个 RDMA 网卡的 annotations 和 8 种 RDMA 资源。

    ```shell
    # Pod multus annotations
    k8s.v1.cni.cncf.io/networks: |-
      [{"name":"gpu1-macvlan","namespace":"spiderpool"},
      {"name":"gpu2-macvlan","namespace":"spiderpool"},
      {"name":"gpu3-macvlan","namespace":"spiderpool"},
      {"name":"gpu4-macvlan","namespace":"spiderpool"},
      {"name":"gpu5-macvlan","namespace":"spiderpool"},
      {"name":"gpu6-macvlan","namespace":"spiderpool"},
      {"name":"gpu7-macvlan","namespace":"spiderpool"},
      {"name":"gpu8-macvlan","namespace":"spiderpool"}]
    # macvlan resource
    resources:
      requests:
        spidernet.io/shared_cx5_gpu1: 1
        spidernet.io/shared_cx5_gpu2: 1
        spidernet.io/shared_cx5_gpu3: 1
        spidernet.io/shared_cx5_gpu4: 1
        spidernet.io/shared_cx5_gpu5: 1
        spidernet.io/shared_cx5_gpu6: 1
        spidernet.io/shared_cx5_gpu7: 1
        spidernet.io/shared_cx5_gpu8: 1
    ```

5. 查看容器的网络命名空间状态

    可进入任一一个 POD 的网络命名空间中，确认具备 9 个网卡：

    ```shell
    $ kubectl exec -it rdma-tools-4v8t8  bash
    kubectl exec [POD] [COMMAND] is DEPRECATED and will be removed in a future version. Use kubectl exec [POD] -- [COMMAND] instead.
    root@rdma-tools-4v8t8:/# ip a
       1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
           link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
           inet 127.0.0.1/8 scope host lo
              valid_lft forever preferred_lft forever
           inet6 ::1/128 scope host
              valid_lft forever preferred_lft forever
       2: tunl0@NONE: <NOARP> mtu 1480 qdisc noop state DOWN group default qlen 1000
           link/ipip 0.0.0.0 brd 0.0.0.0
       3: eth0@if356: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1480 qdisc noqueue state UP group default qlen 1000
           link/ether ca:39:52:fc:61:cd brd ff:ff:ff:ff:ff:ff link-netnsid 0
           inet 10.233.119.164/32 scope global eth0
              valid_lft forever preferred_lft forever
           inet6 fe80::c839:52ff:fefc:61cd/64 scope link
              valid_lft forever preferred_lft forever
       269: net1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
           link/ether 3a:97:49:35:79:95 brd ff:ff:ff:ff:ff:ff
           inet 172.16.11.10/24 brd 10.1.19.255 scope global net1
              valid_lft forever preferred_lft forever
           inet6 fe80::3897:49ff:fe35:7995/64 scope link
              valid_lft forever preferred_lft forever
       239: net2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
           link/ether 1e:b6:13:0e:2a:d5 brd ff:ff:ff:ff:ff:ff
           inet 172.16.12.10/24 brd 10.1.19.255 scope global net1
              valid_lft forever preferred_lft forever
           inet6 fe80::1cb6:13ff:fe0e:2ad5/64 scope link
              valid_lft forever preferred_lft forever
       .....
    ```

    查看路由配置，Spiderpool 会自动为每个网卡调谐策略路由，确保每个网卡上收到的外部请求都会从该网卡上返回回复流量：

    ```shell
    root@rdma-tools-4v8t8:/# ip rule
    0:  from all lookup local
    32762:  from 172.16.11.10 lookup 107
    32763:  from 172.16.12.10 lookup 106
    32764:  from 172.16.13.10 lookup 105
    32765:  from 172.16.14.10 lookup 104
    32765:  from 172.16.15.10 lookup 103
    32765:  from 172.16.16.10 lookup 102
    32765:  from 172.16.17.10 lookup 101
    32765:  from 172.16.18.10 lookup 100
    32766:  from all lookup main
    32767:  from all lookup default

    root@rdma-tools-4v8t8:/# ip route show table 100
        default via 172.16.11.254 dev net1
    ```

    main 路由中，确保了 calico 网络流量、ClusterIP 流量、本地宿主机通信等流量都会从 calico 网卡转发

    ```
    root@rdma-tools-4v8t8:/# ip r show table main
        default via 169.254.1.1 dev eth0
        172.16.11.0/24 dev net1 proto kernel scope link src 172.16.11.10
        172.16.12.0/24 dev net2 proto kernel scope link src 172.16.12.10
        172.16.13.0/24 dev net3 proto kernel scope link src 172.16.13.10
        172.16.14.0/24 dev net4 proto kernel scope link src 172.16.14.10
        172.16.15.0/24 dev net5 proto kernel scope link src 172.16.15.10
        172.16.16.0/24 dev net6 proto kernel scope link src 172.16.16.10
        172.16.17.0/24 dev net7 proto kernel scope link src 172.16.17.10
        172.16.18.0/24 dev net8 proto kernel scope link src 172.16.18.10
        10.233.0.0/18 via 10.1.20.4 dev eth0 src 10.233.119.164
        10.233.64.0/18 via 10.1.20.4 dev eth0 src 10.233.119.164
        10.233.119.128 dev eth0 scope link src 10.233.119.164
        169.254.0.0/16 via 10.1.20.4 dev eth0 src 10.233.119.164
        169.254.1.1 dev eth0 scope link
    ```

    确认具备 8 个 RDMA 设备

    ```
    root@rdma-tools-4v8t8:/# rdma link
        link mlx5_27/1 state ACTIVE physical_state LINK_UP netdev net2
        link mlx5_54/1 state ACTIVE physical_state LINK_UP netdev net1
        link mlx5_67/1 state ACTIVE physical_state LINK_UP netdev net4
        link mlx5_98/1 state ACTIVE physical_state LINK_UP netdev net3
        .....
    ```

6. 在跨节点的 Pod 之间，确认 RDMA 收发数据正常

    开启一个终端，进入一个 Pod 启动服务：

    ```shell
    # see 8 RDMA devices assigned to the Pod
    $ rdma link

    # Start an RDMA service
    $ ib_read_lat
    ```

   开启一个终端，进入另一个 Pod 访问服务：

    ```shell
    # You should be able to see all RDMA network cards on the host
    $ rdma link
        
    # Successfully access the RDMA service of the other Pod
    $ ib_read_lat 172.91.0.115
    ```
