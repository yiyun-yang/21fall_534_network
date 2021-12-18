# -*- coding:utf-8 -*-

"""
@author: Yiyun Yang
"""
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info, debug
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
        self.addLink(h1, r1, intfName1='h1-eth0', intfName2='r1-eth0')
        self.addLink(h2, r4, inftname1='h2-eth0', inftname2='r4-eth0')

        # Add router-router connection
        self.addLink(r1, r2, intfName1='r1-eth1', intfName2='r2-eth0')
        self.addLink(r1, r3, intfName1='r1-eth2', intfName2='r3-eth0')
        self.addLink(r2, r4, intfName1='r2-eth1', intfName2='r4-eth1')
        self.addLink(r3, r4, intfName1='r3-eth1', intfName2='r4-eth2')


def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo, autoStaticArp=True)
    net.start()
    h1, h2, r1, r2, r3, r4 = [net[x] for x in ['h1', 'h2', 'r1', 'r2', 'r3', 'r4']]

    h1.cmd('ifconfig h1-eth0 192.168.10.1/24')
    h1.cmd('route add default gw 192.168.10.2')
    r1.cmd('ifconfig r1-eth0 192.168.10.2/24')

    h2.cmd('ifconfig h2-eth0 192.168.20.1/24')
    h2.cmd('route add default gw 192.168.20.2')
    r4.cmd('ifconfig r4-eth0 192.168.20.2/24')

    r1.cmd('ifconfig r1-eth1 192.168.12.1/24')
    r2.cmd('ifconfig r2-eth0 192.168.12.2/24')

    r1.cmd('ifconfig r1-eth2 192.168.13.1/24')
    r3.cmd('ifconfig r3-eth0 192.168.13.3/24')
    r3.cmd('route add default gw 192.168.13.1')

    r2.cmd('ifconfig r2-eth1 192.168.24.2/24')
    r2.cmd('route add default gw 192.168.24.4')
    r4.cmd('ifconfig r4-eth1 192.168.24.4/24')

    r3.cmd('ifconfig r3-eth1 192.168.34.3/24')
    r4.cmd('ifconfig r4-eth2 192.168.34.4/24')
    r4.cmd('route add default gw 192.168.34.3')

    # Add routes
    r1.cmd("ip route add to 192.168.20.0/24 via 192.168.12.2")
    r2.cmd("ip route add to 192.168.20.0/24 via 192.168.24.4")
    r4.cmd("ip route add to 192.168.10.0/24 via 192.168.34.3")
    r3.cmd("ip route add to 192.168.10.0/24 via 192.168.13.1")

    for i in [1, 2, 3, 4]:
        info(f'*** Routing Table on Router r{i}:\n')
        info(net[f'r{i}'].cmd('route') + '\n')

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
