#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import irange,dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import RemoteController

import argparse
import sys
import time


class ClosTopo(Topo):

    def __init__(self, fanout, cores, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
       
        
        aggreg= fanout * cores
        edges= fanout * aggreg
        hosts= edges * fanout
        core_switch=[]
        num=1

        for x in range(cores): # add cores 
            switch=self.addSwitch('c'+str(num))
            core_switch.append(switch)
            print("c"+str(num))
            num=num+1

        pass

	"Set up Core and Aggregate level, Connection Core - Aggregation level"
        #WRITE YOUR CODE HERE!
        aggregation_switch=[]
        #make four aggregation with links to each core 
        for x in range(aggreg):
            switch=self.addSwitch('a'+str(num))
            print("a"+str(num))
            for i in range(cores):
                self.addLink(switch,core_switch[i])				
                aggregation_switch.append(switch)	
            num=num+1
	
	pass

	"Set up Edge level, Connection Aggregation - Edge level "
        #WRITE YOUR CODE HERE!
        edge_switches=[]
        for x in range(edges):
            switch=self.addSwitch('e'+str(num))
            print("e"+str(num))
            for i in range(aggreg):
                self.addLink(switch,aggregation_switch[i])
            edge_switches.append(switch)
            num=num+1
        pass

        "Set up Host level, Connection Edge - Host level "
        #WRITE YOUR CODE HERE!
        final_hosts=[]
        num_hosts=1
        for x in range(edges):
            for i in range(2):
                host=self.addHost('h'+str(num_hosts))
                self.addLink(host,edge_switches[x])
                print("h"+str(num_hosts))
                num_hosts=num_hosts+1
            final_hosts.append(host)

        pass
	

def setup_clos_topo(fanout=2, cores=1):
    "Create and test a simple clos network"
    assert(fanout>0)
    assert(cores>0)
    topo = ClosTopo(fanout, cores)
    net = Mininet(topo=topo, controller=lambda name: RemoteController('c0', "127.0.0.1"), autoSetMacs=True, link=TCLink)
    net.start()
    time.sleep(20) #wait 20 sec for routing to converge
    net.pingAll()  #test all to all ping and learn the ARP info over this process
    CLI(net)       #invoke the mininet CLI to test your own commands
    net.stop()     #stop the emulation (in practice Ctrl-C from the CLI 
                   #and then sudo mn -c will be performed by programmer)

    
def main(argv):
    parser = argparse.ArgumentParser(description="Parse input information for mininet Clos network")
    parser.add_argument('--num_of_core_switches', '-c', dest='cores', type=int, help='number of core switches')
    parser.add_argument('--fanout', '-f', dest='fanout', type=int, help='network fanout')
    args = parser.parse_args(argv)
    setLogLevel('info')
    setup_clos_topo(args.fanout, args.cores)


if __name__ == '__main__':
    main(sys.argv[1:])
