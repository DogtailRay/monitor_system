#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import OVSController
from mininet.node import RemoteController
from mininet.cli import CLI

class SingleSwitchTopo(Topo):
    "Single switch connected to n hosts."
    def __init__(self, n=2, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
        switch = self.addSwitch('s1')
        # Python's range(N) generates 0..N-1
        for h in range(n):
            host = self.addHost('h%s' % (h + 1), mac='00:11:22:33:44:%02d' % h)
            self.addLink(host, switch, delay='5ms', loss=10)

def simpleTest():
    "Create and test a simple network"
    topo = SingleSwitchTopo(n=3)
    #net = Mininet(topo, controller=lambda name: RemoteController(name, ip='192.168.56.1'))
    net = Mininet(topo, controller=OVSController, link=TCLink)
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print "Testing network connectivity"
    #net.pingAll()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTest()
