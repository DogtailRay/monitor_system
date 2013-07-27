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
                hn = len(self.hosts())
                mac = "00:11:22:33:44:%02x" % hn
                host = self.addHost('h%s' % (prefix+str(i)), mac=mac)
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
    receivers = ["00:11:22:33:44:00",
                 "00:11:22:33:44:04",
                 "00:11:22:33:44:08",
                 "00:11:22:33:44:0c"]
    for host in net.hosts:
        if host.defaultIntf().MAC() in receivers:
            startLogReceiver(host)
        else:
            startLogSender(host)

    for host in net.hosts:
        if not (host.defaultIntf().MAC() in receivers):
            runGenerator(host)

    for host in net.hosts:
        if host.defaultIntf().MAC() in receivers:
            stopLogReceiver(host)
        else:
            stopLogSender(host)
    net.stop()

def startLogReceiver(host):
    host.cmd("./log_receiver {0} log_{1} &".format(host.defaultIntf(), host.name) )
def startLogSender(host):
    host.cmd("./log_sender {0} &".format(host.defaultIntf()) )
def stopLogReceiver(host):
    host.cmd("pkill log_receiver")
def stopLogSender(host):
    host.cmd("pkill log_sender")
def runGenerator(host):
    host.cmd("./generator {0}".format(host.name))

if __name__ == '__main__':
    setLogLevel('info')
    multiSwitchTest()
