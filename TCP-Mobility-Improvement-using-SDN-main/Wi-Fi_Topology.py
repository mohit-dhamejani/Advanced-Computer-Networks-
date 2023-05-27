#!/usr/bin/python

from mininet.node import RemoteController, OVSKernelSwitch, Host
from mininet.log import setLogLevel, info
from mn_wifi.net import Mininet_wifi
from mn_wifi.node import Station, OVSKernelAP
from mn_wifi.cli import CLI
from mn_wifi.link import wmediumd
from mn_wifi.wmediumdConnector import interference

def myNetwork():

    net = Mininet_wifi(controller=RemoteController,
                       link=wmediumd,
                       wmediumd_mode=interference,
                    #    ipBase='10.0.0.0/8'
                    )

    info( '*** Adding controller\n' )
    # controller_ = net.addHost('con', ip='10.0.0.100/8', inNamespace=False)
    c0 = net.addController(name='c0', controller=RemoteController, ip='127.0.0.1', mac='00:00:00:00:00:08', port=6653)

    info( '*** Adding switches/APs\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch)
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch)
    s5 = net.addSwitch('s5', cls=OVSKernelSwitch)
    ap1 = net.addAccessPoint('ap1', cls=OVSKernelAP, mac='00:00:00:00:00:01', ip='10.0.0.4', ssid='ap1-ssid', channel='1', mode='g', position='1500.0,2000.0,0', range=500)
    ap2 = net.addAccessPoint('ap2', cls=OVSKernelAP, mac='00:00:00:00:00:02', ip='10.0.0.5', ssid='ap2-ssid', channel='6', mode='g', position='3000.0,2000.0,0', range=500)
    ap3 = net.addAccessPoint('ap3', cls=OVSKernelAP, mac='00:00:00:00:00:03', ip='10.0.0.6', ssid='ap3-ssid', channel='11', mode='g', position='4200.0,2000.0,0', range=500)

    info( '*** Adding hosts/stations\n')
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', mac='00:00:00:00:00:04', defaultRoute=None)
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', mac='00:00:00:00:00:05', defaultRoute=None)
    h3 = net.addHost('h3', cls=Host, ip='10.0.0.3', mac='00:00:00:00:00:06', defaultRoute=None)
    sta1 = net.addStation('sta1', ip='10.0.0.7', mac='00:00:00:00:00:07', position='300.0,450.0,0.0', range=300)

    info("*** Configuring Propagation Model\n")
    net.setPropagationModel(model="logDistance", exp=4)

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    info( '*** Adding links\n')
    net.addLink(s3, s5)
    net.addLink(s3, s4)
    net.addLink(s3, s2)
    net.addLink(s2, s1)
    net.addLink(s1, h1)
    net.addLink(s1, h2)
    net.addLink(s2, h3)
    net.addLink(ap1, s4)
    net.addLink(ap2, s3)
    net.addLink(ap3, s5)
    # net.addLink(s1, controller_)

    info( '*** Plotting graph\n')
    net.plotGraph(max_x=5000, max_y=4000)

    info( '*** Starting mobility\n')
    net.startMobility(time=0, repetitions=1, ac_method='ssf')
    net.mobility(sta1, 'start', time=20, position='300.0,2050.0,0.0')
    net.mobility(sta1, 'stop', time=60, position='4700.0,2050.0,0.0')
    net.stopMobility(time=61)

    # info( '*** Starting controllers\n')
    # for controller in net.controllers:
    #     controller.start()

    info( '*** Starting network, controller and switches/APs\n')
    net.build()
    # net.addNAT().configDefault()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    s4.start([c0])
    s5.start([c0])
    ap1.start([c0])
    ap2.start([c0])
    ap3.start([c0])

    info( '*** Starting monitor interface and wireshark\n')
    # sta1.cmd('iw dev %s interface add mon0 type monitor' % sta1.params['wlan'][0])
    # sta1.cmd('ifconfig mon0 up')
    c0.cmd('ifconfig hwsim0 up')
    # sta1.cmd('wireshark -i mon0 -k &')
    # c0.cmd('wireshark -i hwsim0 -k &')
    c0.cmd('wireshark &')
    # sta1.cmd('xterm -hold -e python sta1.py')
    c0.cmd('xterm -hold -e python sta1.py &')

    info( '*** Running CLI\n')
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

