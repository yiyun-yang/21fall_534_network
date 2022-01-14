# -*- coding:utf-8 -*-

"""
@author: Yiyun Yang
"""
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI


class LinuxRouter(Node):
    "A Node with IP forwarding enabled."

    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        # Enable forwarding on the router
        self.cmd('sysctl net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()


class NetworkTopo(Topo):
    def build(self, **_opts):
        # Add routers
        r1 = self.addHost('r1', cls=LinuxRouter)
        r2 = self.addHost('r2', cls=LinuxRouter)
        r3 = self.addHost('r3', cls=LinuxRouter)
        r4 = self.addHost('r4', cls=LinuxRouter)
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        # Adding host-router connection
        self.addLink(h1, r1, inftname1='h1-eth0', inftname2='r1-eth0')
        self.addLink(h2, r4, intfName1='h2-eth0', intfName2='r4-eth0')

        # Add router-router connection
        self.addLink(r4, r2, intfName1='r4-eth1', intfName2='r2-eth0')
        self.addLink(r4, r3, intfName1='r4-eth2', intfName2='r3-eth0')
        self.addLink(r2, r1, intfName1='r2-eth1', intfName2='r1-eth1')
        self.addLink(r3, r1, intfName1='r3-eth1', intfName2='r1-eth2')


def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo, autoStaticArp=True)
    net.start()
    h1, h2, r4, r2, r3, r1 = [net[x] for x in ['h1', 'h2', 'r4', 'r2', 'r3', 'r1']]

    h1.cmd('ip address add 192.168.10.10/24 dev h1-eth0')
    r1.cmd('ip address add 192.168.10.12/24 dev r1-eth0')
    h1.cmd('ip route add default via 192.168.10.12 dev h1-eth0')

    h2.cmd('ip address add 192.168.20.10/24 dev h2-eth0')
    r4.cmd('ip address add 192.168.20.12/24 dev r4-eth0')
    h2.cmd('ip route add default via 192.168.20.12 dev h2-eth0')

    r1.cmd('ip address add 192.168.12.12/24 dev r1-eth1')
    r2.cmd('ip address add 192.168.12.21/24 dev r2-eth1')
    r1.cmd('ip route add default via 192.168.12.21 dev r1-eth1')
    r2.cmd('route add -net 192.168.10.0/24 gw 192.168.12.12')

    r1.cmd('ip address add 192.168.13.13/24 dev r1-eth2')
    r3.cmd('ip address add 192.168.13.31/24 dev r3-eth1')
    r3.cmd('ip route add default via 192.168.13.13 dev r3-eth1')

    r2.cmd('ip address add 192.168.24.24/24 dev r2-eth0')
    r4.cmd('ip address add 192.168.24.42/24 dev r4-eth1')
    r2.cmd('ip route add default via 192.168.24.42 dev r2-eth0')

    r3.cmd('ip address add 192.168.34.34/24 dev r3-eth0')
    r4.cmd('ip address add 192.168.34.43/24 dev r4-eth2')
    r4.cmd('ip route add default via 192.168.34.34 dev r4-eth2')
    r3.cmd('route add -net 192.168.20.0/24 gw 192.168.34.43')

    for i in ['h1', 'h2', 'r1', 'r2', 'r3', 'r4']:
        # delete default IP that mininet assigned to the interface xx-eth0
        for ip in net[f'{i}'].cmd("hostname -I").split(" "):
            if ip.startswith("10.0.0"):
                net[f'{i}'].cmd(f"ip addr del {ip}/8 dev {i}-eth0")
                break
        # print ip config
        info(f'*** IP config on node {i}:\n')
        info(net[f'{i}'].cmd('ip a') + '\n')

    for i in ['r1', 'r2', 'r3', 'r4']:
        info(f'*** Routing Table on Router {i}:\n')
        info(net[f'{i}'].cmd('route -n') + '\n')

    # print ping output
    info("*** ping output from h1 to h2\n")
    info(h1.cmd(f"ping -c2 {h2.cmd('hostname -I')}") + "\n")
    info("*** ping output from h2 to h1\n")
    info(h2.cmd(f"ping -c2 {h1.cmd('hostname -I')}") + "\n")

    # print traceroute output
    info("*** trace route output from h1 to h2\n")
    info(h1.cmd("traceroute -I 192.168.20.10") + "\n")
    info("*** trace route output from h2 to h1\n")
    info(h2.cmd("traceroute -I 192.168.10.10") + "\n")

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
