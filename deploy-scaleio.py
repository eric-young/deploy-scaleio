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

        # return the parser object
        return parser

    def node_execute_command(self, ipaddr, username, password, command, numTries=5):
        """
        Execute a command via ssh
        """
        attempt=1
        connected = False

        while (attempt<=numTries and connected==False):
            print("Connecting to: %s" % (ipaddr))
            ssh = RemoteServer(None,
                               username=username,
                               password=password,
                               log_folder_path='/tmp',
                               server_has_dns=False)
            connected, err = ssh.connect_server(ipaddr, False)
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
        _commands.append("(echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections) || true")
        _commands.append('apt-get install -y ansible '
                     ' || '
                     'yum install -y ansible')

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

        _commands = []
        _commands.append('uptime')

        _commands.append('cd /; mkdir git; chmod -R 777 /git')
        _commands.append("( apt-get update && apt-get install -y git wget ) || yum install -y git wget")
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
        _commands.append("cd /git/ansible-scaleio && cp hosts-5_node hosts")
        _commands.append("cd /git/ansible-scaleio && sed -i 's|node0|{}|g' hosts".format(args.IP[0]))
        _commands.append("cd /git/ansible-scaleio && sed -i 's|node1|{}|g' hosts".format(args.IP[1]))
        _commands.append("cd /git/ansible-scaleio && sed -i 's|node2|{}|g' hosts".format(args.IP[2]))
        _commands.append("cd /git/ansible-scaleio/group_vars && sed -i 's|eth1|{}|g' all".format(interface))
        _commands.append("cd /git/ansible-scaleio/group_vars && sed -i 's|5_node|3_node|g' all")
        _commands.append("cd /git/ansible-scaleio && ansible-playbook -i hosts site-no-gui-no-sdc.yml")
        _commands.append("cat /git/ansible-scaleio/hosts")
        self.node_execute_multiple(ipaddr, args.USERNAME, args.PASSWORD, _commands)

    def run_postinstall(self, ipaddr, args):
        """
        Perform any post-install functions

        This includes installing utilities
        """
        return

    def process(self):
        """
        Main logic
        """
        parser = self.setup_arguments()
        args = parser.parse_args()

        self.setup_all_nodes(args)
        self.setup_scaleio(args.IP[0], args)

        # run anything that needs to be run on all hosts
        for ipaddress in args.IP:
            self.run_postinstall(ipaddress, args)


# Start program
if __name__ == "__main__":
    scaleio_deployer = ScaleIODeployer()
    scaleio_deployer.process()
