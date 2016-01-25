#!/usr/bin/env python
'''
This script will install Squid Caching Proxy on the targeted server.

This script is dependent on the following config files for this script to work.
    var/squid/*

'''

__author__ = "David Skeppstedt"
__copyright__ = "Copyright 2014, Fareoffice CRS AB"
__maintainer__ = "Kristofer Borgstrom"
__email__ = "davske@fareoffice.com"
__credits__ = ["Daniel Lindh, Mattias Hemmingsson, Kristofer Borgstrom, David Skeppstedt"]
__license__ = "???"
__version__ = "1.5"
__status__ = "Production"

import os
from general import x
import config
import socket
import app
import version
import scopen
import fcntl
import struct
import net
from iptables import InboundFirewallRule, OutboundFirewallRule

script_version = 1

SQUID_CONF_DIR = "/etc/squid/"

def build_commands(commands):
    '''
    Defines the commands that can be executed through the syco.py shell script.
    '''
    commands.add("install-squid", install_squid, help="Install Squid Caching Proxy on the server.",
                 firewall_config=[InboundFirewallRule(service="squid", ports="3128", src="local-nets"),
                                  OutboundFirewallRule(service="squid", ports=["80", "443"])])
    commands.add("uninstall-squid", uninstall_squid, help="Uninstall Squid Caching Proxy from the server.")

def _service(service,command):
    x("/sbin/service {0} {1}".format(service, command))

def _chkconfig(service,command):
    x("/sbin/chkconfig {0} {1}".format(service, command))

def install_squid(args):
    global SYCO_PLUGIN_PATH, ACCEPTED_SQUID_ENV

    SYCO_PLUGIN_PATH = str(app.get_syco_plugin_paths("/var/squid/").next())

    app.print_verbose("Install Squid Caching Proxy version: %d" % script_version)
    version_obj = version.Version("InstallSquid", script_version)
    version_obj.check_executed()
    os.chdir("/")

    x("yum install -y squid")
    _configure_squid()

    version_obj.mark_executed()


def _configure_squid():
    x("rm -rf /etc/squid/*")
    x("cp %s/*.conf %s" % (SYCO_PLUGIN_PATH, SQUID_CONF_DIR))
    x("mkdir -p %s/acl" % (SQUID_CONF_DIR))
    x("mkdir -p %s/services" % (SQUID_CONF_DIR))
    x("cp %s/acl/* %sacl/" % (SYCO_PLUGIN_PATH, SQUID_CONF_DIR))
    x("cp %s/services/* %sservices/" % (SYCO_PLUGIN_PATH, SQUID_CONF_DIR))

    env_ip = config.host(net.get_hostname()).get_front_ip()
    if config.general.is_back_enabled():
        #prefer backnet if enabled
        env_ip = config.host(net.get_hostname()).get_back_ip()

    scopen.scOpen(SQUID_CONF_DIR + "squid.conf").replace("${ENV_IP}", env_ip)
    #Some setups require the front IP as well
    scopen.scOpen(SQUID_CONF_DIR + "squid.conf").replace("${FRONT_IP}", config.host(net.get_hostname()).get_front_ip())

    _chkconfig("squid", "on")
    _service("squid", "restart")


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def uninstall_squid(args=""):
    '''
    Remove Squid Caching Proxy from the server.
    '''
    app.print_verbose("Uninstall Squid Caching Proxy")
    os.chdir("/")

    _chkconfig("squid","off")
    _service("squid","stop")

    x("yum -y remove squid")
    x("rm -rf %s*" % (SQUID_CONF_DIR))

'''
End of Squid Caching Proxy installation script.
'''
