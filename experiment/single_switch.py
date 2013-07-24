#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
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
            host = self.addHost('h%s' % (h + 1))
            self.addLink(host, switch)

def simpleTest():
    "Create and test a simple network"
    topo = SingleSwitchTopo(n=3)
    net = Mininet(topo, controller=lambda name: RemoteController(name, ip='192.168.56.1'))
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print "Testing network connectivity"
    net.pingAll()
    print "Testing log monitoring system"
    hosts = net.hosts
    hosts[0].cmdPrint("./log_sender h1-eth0 &")
    hosts[1].cmdPrint("./log_receiver h2-eth0 log2 &")
    hosts[2].cmdPrint("./log_receiver h3-eth0 log3 &")

    hosts[0].cmdPrint("./generator")

    hosts[0].cmdPrint("pkill log_sender")
    hosts[1].cmdPrint("pkill log_receiver")
    hosts[2].cmdPrint("pkill log_receiver")
    net.stop()

if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTest()
