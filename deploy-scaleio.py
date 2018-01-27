#!/usr/bin/env python

import argparse
from ssh_paramiko import RemoteServer
import time

class UnableToConnectException(Exception):
    message = "Unable to connect to Server"

    def __init__(self, server):
        self.details = {
            "server": server,
        }
        super(UnableToConnectException, self).__init__(self.message, self.details)


class ScaleIODeployer:
    def __init__(self):
        self.client = None

    def sles_only_command(self, command):
        platform_specific="if [ -f /etc/SuSE-release ]; then {}; fi".format(command)
        return platform_specific

    def ubuntu_only_command(self, command):
        platform_specific="if [ -f /etc/lsb-release ]; then {}; fi".format(command)
        return platform_specific

    def centos_or_redhat_only_command(self, command):
        platform_specific="if [ -f /etc/centos-release -o -f /etc/redhat-release ]; then {}; fi".format(command)
        return platform_specific

    def centos_only_command(self, command):
        platform_specific="if [ -f /etc/centos-release ]; then {}; fi".format(command)
        return platform_specific

    def redhat_only_command(self, command):
        platform_specific="if [ -f /etc/redhat-release ]; then {}; fi".format(command)
        return platform_specific

    def _get_first_token(self, text):
        if len(text.split()) > 0:
	    return(text.split()[0])
        return None

    def setup_arguments(self):
        parser = argparse.ArgumentParser(description='Clone and configure a VM')

        # node settings
        parser.add_argument('--ip', dest='IP', action='store', nargs='*',
                        help='Space seperated list of IP addresses of the nodes')
        parser.add_argument('--username', dest='USERNAME', action='store',
                        default='root', help='Node Username, default is \"root\"')
        parser.add_argument('--password', dest='PASSWORD', action='store',
                        default='password', help='Node password, default is \"password\"')

        # scaleio options
        parser.add_argument('--package_url', dest='PACKAGE_URL', action='store', required=True,
                        help='URL to install packages')
        parser.add_argument('--scaleio_device', action='store', default='/dev/sdb',
                        help='Device name to add to ScaleIO Storage Pool, default is /dev/sdb')
        parser.add_argument('--domain', action='store', default='domain1',
                        help='Protection Domain [name] to create, default is domain1')
        parser.add_argument('--pool', action='store', default='pool1',
                        help='Storage Pool [name] to create, default is pool1')
        parser.add_argument('--gateway_http_port', action='store', default='80',
                        help='Port for gateway http traffic')
        parser.add_argument('--gateway_ssl_port', action='store', default='443',
                        help='Port for gateway https/ssl traffic')

        # misc options
        parser.add_argument('--preponly', action='store_true',
                            help='Sets up the node to run ansible but does not invoke it')

        # return the parser object
        return parser

    def node_execute_command(self, ipaddr, username, password, command, numTries=5):
        """
        Execute a command via ssh
        """
        attempt=1
        connected = False

        while (attempt<=numTries and connected==False):
            ssh = RemoteServer(None,
                               username=username,
                               password=password,
                               log_folder='/tmp',
                               server_has_dns=False)
            print("Connecting to: %s" % (ipaddr))

            try:
                connected, err = ssh.connect_server(ipaddr, ping=False)
            except Exception as e:
                print("Unable to connect. Will try again.")
                connected = False

            if connected == False:
                time.sleep(5)
                attempt = attempt + 1

        if connected == False:
            raise UnableToConnectException(ipaddr)

        print("Executing Command: %s" % (command))
        rc, stdout, stderr = ssh.execute_cmd(command, timeout=None)
        ssh.close_connection()

        stdout.strip()
        stderr.strip()

        if rc is True:
            print("%s" % stdout)

        return rc, stdout, stderr

    def node_execute_multiple(self, ipaddr, username, password, commands):
        """
        execute a list of commands
        """
        for cmd in commands:
            rc, output, error = self.node_execute_command(ipaddr, username, password, cmd)
            if rc is False:
                print("error running: [%s] %s" % (ipaddr, cmd))

    def setup_all_nodes(self, args):
        """
        Prepare all the nodes

        Install pre-reqs
        """
        _commands = []
        _commands.append(self.ubuntu_only_command("echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections"))

        for ipaddr in args.IP:
            self.node_execute_multiple(ipaddr, args.USERNAME, args.PASSWORD, _commands)

    def setup_scaleio(self, ipaddr, args):
        """
        Prepare a host to setup scaleio

        This includes installing some pre-reqs as well as
        cloning a git repo that configures scaleio with ansible
        """

        # get the network interface name
        command = 'ip -o link show | grep -v "lo:" | grep "UP" | awk \'{print $2}\''
        rc, interface, error = self.node_execute_command(ipaddr, args.USERNAME, args.PASSWORD, command)
        interface = interface.split(':')[0]

        # get the device we will add to scaleio
        # this is the user specified value (on the command line)
        #    - if that device is specified in the /etc/raw-devices file
        #    or
        #    - if the /etc/raw-devices file does not exist
        # otherwise, it is the first device in /etc/raw-devices
        #
        # NOTE: another way to detect not partioned disks is to run
        #       partprobe -d -s <device>
        #       Unpartitioned devices will return NO output
        siodevice = ""
        command = 'grep {} /etc/raw-devices'.format(args.scaleio_device)
        rc, siodevice, error = self.node_execute_command(ipaddr, args.USERNAME, args.PASSWORD, command)
        siodevice=self._get_first_token(siodevice)
        if (siodevice is None or siodevice == ""):
            command = 'head -n 1 /etc/raw-devices 2>/dev/null || echo {}'.format(args.scaleio_device)
            rc, siodevice, error = self.node_execute_command(ipaddr, args.USERNAME, args.PASSWORD, command)
            siodevice=self._get_first_token(siodevice)
        if (siodevice is None or siodevice == ""):
            print("Unable to determine which device to add to scaleio")
            raise Exception()

	    print("Will add {} to ScaleIO".format(siodevice))

        _commands = []
        # install some pre-reqs
        _commands.append(self.ubuntu_only_command("apt-add-repository -y -u ppa:ansible/ansible"))
        _commands.append(self.ubuntu_only_command('apt-get install -y ansible git wget'))
        _commands.append(self.centos_only_command('yum install -y ansible git wget'))
        _commands.append(self.redhat_only_command('yum install -y git wget'))
        _commands.append(self.redhat_only_command('(curl https://bootstrap.pypa.io/get-pip.py | python) && pip install ansible'))
        _commands.append(self.sles_only_command("zypper install -y python-setuptools && easy_install pip && pip install paramiko ansible"))
        # clone the ansible-scaleio playbooks and customize them
        _commands.append('cd /; mkdir git; chmod -R 777 /git')
        _commands.append("cd /git && git clone https://github.com/eric-young/ansible-scaleio.git")
        _commands.append("mkdir -p /git/files && mkdir -p /git/temp")
        _commands.append("cd /git/temp && "
                         "wget -r --no-parent -A '*.tar' {} || true".format(args.PACKAGE_URL))
        _commands.append("cd /git/temp && "
                         "wget -r --no-parent -A '*.deb' {} || true".format(args.PACKAGE_URL))
        _commands.append("cd /git/temp && "
                         "wget -r --no-parent -A '*.rpm' {} || true".format(args.PACKAGE_URL))
        _commands.append("cd /git/temp && find . -type f -exec mv {} /git/files \;")
        _commands.append("rm -rf /git/temp")
        _commands.append("cd /git/ansible-scaleio && cp hosts-3_node hosts")
        _commands.append("cd /git/ansible-scaleio && sed -i 's|NODE0|{}|g' hosts".format(args.IP[0]))
        _commands.append("cd /git/ansible-scaleio && sed -i 's|NODE1|{}|g' hosts".format(args.IP[1]))
        _commands.append("cd /git/ansible-scaleio && sed -i 's|NODE2|{}|g' hosts".format(args.IP[2]))
        _commands.append("cd /git/ansible-scaleio && sed -i 's|PASSWORD|{}|g' hosts".format(args.PASSWORD))
        _commands.append("cd /git/ansible-scaleio/group_vars && sed -i 's|80|{}|g' all".format(args.gateway_http_port))
        _commands.append("cd /git/ansible-scaleio/group_vars && sed -i 's|443|{}|g' all".format(args.gateway_ssl_port))
        _commands.append("cd /git/ansible-scaleio/group_vars && sed -i 's|domain1|{}|g' all".format(args.domain))
        _commands.append("cd /git/ansible-scaleio/group_vars && sed -i 's|pool1|{}|g' all".format(args.pool))
        _commands.append("cd /git/ansible-scaleio/group_vars && sed -i 's|/dev/sdb|{}|g' all".format(siodevice))
        _commands.append("cd /git/ansible-scaleio/group_vars && sed -i 's|eth1|{}|g' all".format(interface))
        _commands.append("cd /git/ansible-scaleio/group_vars && sed -i 's|5_node|3_node|g' all")

        self.node_execute_multiple(ipaddr, args.USERNAME, args.PASSWORD, _commands)

        if not args.preponly:
            self.node_execute_command(ipaddr,
                                      args.USERNAME,
                                      args.PASSWORD,
                                      "cd /git/ansible-scaleio && ansible-playbook -f 1 -i hosts site-no-gui-no-sdc.yml")
        else:
            print("To setup ScaleIO, log onto {} as root and run:".format(args.IP[0]))
            print("  \"cd /git/ansible-scaleio && ansible-playbook -f 1 -i hosts site-no-gui-no-sdc.yml\"")

    def setup_gateway(self, args):
        """
        Setup the gateway

        The gateway is on the last IP address (args.IP[2])
        and the MDMs are on the first two
        """
        if args.preponly:
            return

        # edit the gateway properties file and restart the gateway
        # mdm.ip.addresses = <addresses of node0,node1>
        # security.bypass_certificate_check = true
        _config = '/opt/emc/scaleio/gateway/webapps/ROOT/WEB-INF/classes/gatewayUser.properties'
        _commands = []
        #_commands.append("sed -i 's|^mdm.ip.addresses.*|mdm.ip.addresses={},{}|' {}".format(args.IP[0], args.IP[1], _config))
        #_commands.append("sed -i 's|^security.bypass_certificate_check.*|security.bypass_certificate_check=true|' {}".format( _config))
        _commands.append("systemctl restart scaleio-gateway")
        self.node_execute_multiple(args.IP[2], args.USERNAME, args.PASSWORD, _commands)
        return

    def process(self):
        """
        Main logic
        """
        parser = self.setup_arguments()
        args = parser.parse_args()

        self.setup_all_nodes(args)
        self.setup_scaleio(args.IP[0], args)

        # setup the gateway node
        self.setup_gateway(args)


# Start program
if __name__ == "__main__":
    scaleio_deployer = ScaleIODeployer()
    scaleio_deployer.process()
