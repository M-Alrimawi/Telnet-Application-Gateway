from mininet.topo import Topo
from mininet.node import Node, OVSSwitch, RemoteController
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel


class LinuxRouter(Node):
    """A Node with IP forwarding enabled so that it acts as a router."""
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()


class TelnetNetworkTopo(Topo):
    "Simple topology with Telnet clients and servers."

    def build(self):
        "Create custom topo."

        # Add hosts, switches and routers
        client1 = self.addHost('cl1', ip='192.168.0.3')
        client2 = self.addHost('cl2', ip='192.168.0.4')

        server_in = self.addHost('srvin', ip='192.168.0.2')
        server_out = self.addHost('srvout', ip='172.16.0.2')

        switch = self.addSwitch(
            's',
            cls=OVSSwitch,
            protocols='OpenFlow13',
            dpid='1'
        )

        router = self.addNode('r', cls=LinuxRouter, ip='192.168.0.1')

        # Add links
        self.addLink(client1, switch)
        self.addLink(client2, switch)
        self.addLink(server_in, switch)

        self.addLink(
            router,
            switch,
            intfName1='r-eth1',
            params1={'ip': '192.168.0.1/24'}
        )

        self.addLink(
            router,
            server_out,
            intfName1='r-eth2',
            params1={'ip': '172.16.0.1/24'}
        )


def runTelnetNetworkTopo():
    "Bootstrap a Mininet network using the Minimal Topology"

    # Create an instance of our topology
    topo = TelnetNetworkTopo()
    CONTROLLER_PORT = 6633
    CONTROLLER_IP = '192.168.100.204'
    controller = RemoteController(
        'c',
        ip=CONTROLLER_IP,
        port=CONTROLLER_PORT,
        protocols="OpenFlow13"
    )

    # Create a network based on the topology using OVS and controlled by
    # a remote controller.
    net = Mininet(
        topo=topo,
        controller=controller,
        autoSetMacs=True
    )

    # Actually start the network
    net.start()

    # Get the hosts
    client1 = net.get('cl1')
    client2 = net.get('cl2')
    server_in = net.get('srvin')
    server_out = net.get('srvout')
    router = net.get('r')

    # Add IP addresses to the router interfaces
    router.cmd('ip addr add 192.168.0.1/24 dev r-eth1')

    # Run telnetd-mock.py on the servers
    server_in.cmd('sudo python telnetd-mock.py &')
    server_out.cmd('sudo python telnetd-mock.py &')

    # Add default route
    client1.cmd('ip route add default via 192.168.0.1')
    client2.cmd('ip route add default via 192.168.0.1')
    server_in.cmd('ip route add default via 192.168.0.1')
    server_out.cmd('ip route add default via 172.16.0.1')

    # Additional configurations for the router (static route)
    router.cmd('ip route add 192.168.0.0/24 dev r-eth1')

    # Drop the user in to a CLI so user can run commands.
    CLI(net)

    # After the user exits the CLI, shutdown the network.
    net.stop()


if __name__ == '__main__':
    # This runs if this file is executed directly
    setLogLevel('info')
    runTelnetNetworkTopo()
