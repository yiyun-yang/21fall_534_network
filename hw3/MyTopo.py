# -*- coding:utf-8 -*-

"""
@author: Yiyun Yang
"""
"""Custom topology example
Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

import pdb
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
        r1 = self.addHost('r1', cls=LinuxRouter, ip='10.0.0.1/24')
        r2 = self.addHost('r2', cls=LinuxRouter)
        r3 = self.addHost('r3', cls=LinuxRouter)
        r4 = self.addHost('r4', cls=LinuxRouter, ip='10.0.1.1/24')

        # Adding hosts specifying the default route
        # subnet: 10.0.0.0/24
        h1 = self.addHost(name='h1', ip='10.0.0.2/24', defaultRoute='via 10.0.0.1')
        self.addLink(h1, r1, intfName1='h1-eth0', intfName2='r1-eth0')
        # subnet: 10.0.1.0/24
        h2 = self.addHost(name='h2', ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
        self.addLink(h2, r4, inftname1='h2-eth0', inftname2='r4-eth0')

        # Add router-router connection
        self.addLink(r1, r2, intfName1='r1-eth1', intfName2='r2-eth1')
        self.addLink(r3, r1, intfName1='r3-eth1', intfName2='r1-eth2')
        self.addLink(r2, r4, intfName1='r2-eth2', intfName2='r4-eth1')
        self.addLink(r4, r3, intfName1='r4-eth2', intfName2='r3-eth2')


def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo)

    r1 = net['r1']
    r2 = net['r2']
    r3 = net['r3']
    r4 = net['r4']

    # subnet: 192.168.10.128/25
    r1.cmd('ifconfig r1-eth1 192.168.10.176/25')
    r2.cmd('ifconfig r2-eth1 192.168.10.177/25')
    # subnet: 192.168.11.128/25
    r3.cmd('ifconfig r3-eth1 192.168.11.177/25')
    r1.cmd('ifconfig r1-eth2 192.168.11.176/25')
    # subnet: 192.168.12.128/25
    r2.cmd('ifconfig r2-eth2 192.168.12.177/25')
    r4.cmd('ifconfig r4-eth1 192.168.12.176/25')
    # subnet: 192.168.13.128/25
    r4.cmd('ifconfig r4-eth2 192.168.13.176/25')
    r3.cmd('ifconfig r3-eth2 192.168.13.177/25')

    # Add routing for reaching networks that aren't directly connected
    # H1 to H2
    info(r1.cmd("route add -net 10.0.1.0/24 gw 192.168.10.177"))
    info(r2.cmd("route add -net 10.0.1.0/24 gw 192.168.12.176"))
    # # H2 to H1
    info(r4.cmd("ip route add to 10.0.0.0/24 via 192.168.13.177"))
    info(r3.cmd("ip route add to 10.0.0.0/24 via 192.168.11.176"))

    net.start()
    info('*** Routing Table on Router:\n')
    for i in [1, 2, 3, 4]:
        info(net[f'r{i}'].cmd('route'))

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
