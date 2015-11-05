#!/usr/bin/env python
'''
Install and configure syco to be used on localhost.

'''

__author__ = "daniel.lindh@cybercow.se"
__copyright__ = "Copyright 2011, The System Console project"
__maintainer__ = "Daniel Lindh"
__email__ = "syco@cybercow.se"
__credits__ = ["???"]
__license__ = "???"
__version__ = "1.0.0"
__status__ = "Production"

import os, sys
import app
from app import SYCO_ETC_PATH, SYCO_USR_PATH, SYCO_VAR_PATH
from general import x


def build_commands(commands):
    commands.add("install-syco", install_syco, help="Install the syco script on the current server.")
    commands.add("passwords", passwords, help="Set all passwords used by syco.")
    commands.add("change-env", change_env, "[env]", help="Set syco environment.")


def install_syco(args):
    '''
    Install/configure this script on the current computer.

    '''
    app.print_verbose("Install syco")
    if (os.access('/sbin/syco', os.F_OK) == False):
        app.print_verbose("Create symlink /sbin/syco")
        os.symlink(sys.path[0] + '/syco.py', '/sbin/syco')
        x("chmod o+x {0}".format("/opt/syco"))
        x("cat %syum/CentOS-Base.repo > /etc/yum.repos.d/CentOS-Base.repo" % app.SYCO_VAR_PATH)
    else:
        app.print_verbose("   Already installed")


def passwords(args):
    app.print_verbose("Listing all passwords that are managed by syco")

    passwords = app.get_all_passwords()


def change_env(args):
    '''
    Change syco invironment files.

    passwordstore and install.cfg files are relinked.

    '''
    if (len(args) != 2):
        raise Exception("syco chagne-env [env]")

    env = args[1]

    app.print_verbose("Change to env " + env)
    x("rm %spasswordstore " % (SYCO_ETC_PATH))
    x("ln -s %spasswordstore.%s %spasswordstore" % (
        SYCO_ETC_PATH, env, SYCO_ETC_PATH)
      )

    if (os.access(app.SYCO_USR_PATH, os.F_OK)):
        for plugin in os.listdir(app.SYCO_USR_PATH):
            plugin_path = os.path.abspath(app.SYCO_USR_PATH + plugin + "/etc/")

            x("rm %s/install.cfg " % (plugin_path))
            x("ln -s %s/install-%s.cfg %s/install.cfg" % (plugin_path, env, plugin_path))
