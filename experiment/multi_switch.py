#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import OVSController
from mininet.node import RemoteController
from mininet.cli import CLI

class MultiSwitchTopo(Topo):
    "Tree net"
    def __init__(self, depth=2, fanout=4, **opts):
        Topo.__init__(self, **opts)
        self.createSubTree(depth, fanout, 1, '0')

    def createSubTree(self, depth_max, fanout, depth, prefix):
        switch = self.addSwitch('s%s' % prefix)
        if depth < depth_max:
            for i in range(fanout):
                child = self.createSubTree(depth_max, fanout, depth+1, prefix+str(i))
                self.addLink(child, switch)
        else:
            for i in range(fanout):
                host = self.addHost('h%s' % (prefix+str(i)))
                self.addLink(host, switch)
        return switch


def multiSwitchTest():
    topo = MultiSwitchTopo(depth=2, fanout=4)
    #net = Mininet(topo, controller=OVSController)
    net = Mininet(topo, controller=lambda name: RemoteController(name, ip='192.168.56.1'))
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print "Testing network connectivity"
    net.pingAll()
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    multiSwitchTest()
