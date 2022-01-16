# -*- coding:utf-8 -*-

"""
@author: Yiyun Yang
"""
from mininet.link import TCLink
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI
import os
from contextlib import contextmanager
import time
from functools import partial
import sys

user_dir = "/home/mininet"
exec_dir = "exec_bird_conf"
working_dir = os.getcwd()


class LinuxRouter(Node):
    "A Node with IP forwarding enabled."

    @contextmanager
    def in_router_dir(self):
        info(self.cmd(f'cd {user_dir}/{exec_dir}/{self.name}'))
        yield
        info(self.cmd(f'cd {working_dir}'))

    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        # Enable forwarding on the router
        self.cmd('sysctl net.ipv4.ip_forward=1')
        # Startup BIRD
        with self.in_router_dir():
            info(self.cmd('sudo bird -u mininet -l'))

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        # Shutdown BIRD
        with self.in_router_dir():
            info(self.cmd('sudo birdc -l down'))
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

        bs_option = 1  # buffer size option: 1: 10000, 2: 5Mb, 3: 25Mb
        if len(sys.argv) > 1:
            bs_option = int(sys.argv[1])
        if bs_option == 1:
            bs = 1000
        elif bs_option == 2:
            bs = 5 * 1024 * 1024
        else:
            bs = 25 * 1024 * 1024

        # Adding host-router connection
        self.addLink(h1, r1, inftname1='h1-eth0', inftname2='r1-eth0', cls=TCLink, bw=100, delay='30ms', max_queue_size=bs)
        self.addLink(h2, r4, intfName1='h2-eth0', intfName2='r4-eth0', cls=TCLink, bw=100, delay='30ms', max_queue_size=bs)

        # Add router-router connection
        self.addLink(r4, r2, intfName1='r4-eth1', intfName2='r2-eth0', cls=TCLink, bw=100, delay='30ms', max_queue_size=bs)
        self.addLink(r4, r3, intfName1='r4-eth2', intfName2='r3-eth0', cls=TCLink, bw=100, delay='30ms', max_queue_size=bs)
        self.addLink(r2, r1, intfName1='r2-eth1', intfName2='r1-eth1', cls=TCLink, bw=100, delay='30ms', max_queue_size=bs)
        self.addLink(r3, r1, intfName1='r3-eth1', intfName2='r1-eth2', cls=TCLink, bw=100, delay='30ms', max_queue_size=bs)


def run():
    # Note: execute the copy_file_scipt.sh first to avoid permission issues.
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

    r1.cmd('ip address add 192.168.13.13/24 dev r1-eth2')
    r3.cmd('ip address add 192.168.13.31/24 dev r3-eth1')

    r2.cmd('ip address add 192.168.24.24/24 dev r2-eth0')
    r4.cmd('ip address add 192.168.24.42/24 dev r4-eth1')

    r3.cmd('ip address add 192.168.34.34/24 dev r3-eth0')
    r4.cmd('ip address add 192.168.34.43/24 dev r4-eth2')

    # delete default IP that mininet assigned to the interface xx-eth0
    for i in ['h1', 'h2', 'r1', 'r2', 'r3', 'r4']:
        for ip in net[f'{i}'].cmd("hostname -I").split(" "):
            if ip.startswith("10.0.0"):
                net[f'{i}'].cmd(f"ip addr del {ip}/8 dev {i}-eth0")
                break

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
