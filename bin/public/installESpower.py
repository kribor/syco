#!/usr/bin/env python
"""
Install Elasticsearch power using RammitMQ and Logstash.

"""
import install

__author__ = "mattias.hemmingsson@fareoffice.com"
__copyright__ = "Copyright 2014, The System Console project"
__maintainer__ = "Mattias Hemmingsson"
__email__ = "syco@cybercow.se"
__credits__ = ["Daniel Lindh"]
__license__ = "???"
__version__ = "1.0.0"
__status__ = "Production"

from general import x,download_file
import app
import version
import os
import iptables
import install


# The version of this module, used to prevent the same script version to be
# executed more then once on the same host.
SCRIPT_VERSION = 1
CONF_SOURCE= str(app.get_syco_plugin_paths("/var").next())


def build_commands(commands):
    commands.add("install-espower", install_espower, help="Install power modules for elastcisearch install-espower logstash version")
    commands.add("uninstall-espower", uninstall_espower, help="Uninstall the power modules for elastic search")


def install_espower(args):
    """Installation of Elastic search passing rule"""
    if (len(args) != 2):
        raise Exception("syco install-espower Logstash Version [syco install-es 1.4.2]")
    install_rabbit()
    install_logstash(args[1])
    config_rabbitmq()
    config_logstash()
    # Adding iptables rules
    iptables.add_rabbitmq_chain()
    iptables.save()

    print("Go to http://ip-address:15672 for rabbit mq ")


def uninstall_espower(args):
    x('yum remove rabbitmq-server -y')
    x('yum remove erlang -y')
    x('rm -rf /opt/logstash')
    x('rm -rf /etc/logstash')
    x('rm -rf /etc/rabbitmq')
    x('rm -rf /etc/init.d/shipper')
    x('rm -rf /etc/init.d/index')


def install_rabbit():
    """Install and setup the rabbit mq server."""
    install.epel_repo()
    x('yum install erlang -y')
    x('rpm --import http://www.rabbitmq.com/rabbitmq-signing-key-public.asc')
    x('yum install rabbitmq-server -y')


def install_logstash(version):
    """
    Download and install logstash
    """
    download_file("https://download.elasticsearch.org/logstash/logstash/logstash-{0}.tar.gz".format(version))
    x('mv /opt/syco/installtemp/logstash-{0}.tar.gz /opt/logstash.tar.gz'.format(version))
    x('tar -zxvf /opt/logstash.tar.gz -C /opt/')
    x('rm /opt/logstash.tar.gz')
    x('rm -rf /opt/logstash')
    x('ln -s /opt/logstash-1* /opt/logstash')


def config_logstash():
    """
    There are no default config for logstash
    Copy config from
    1. First from syco-private
    2. syco var/default config
    """
    x('cp -r {0}/logstash /etc/'.format(CONF_SOURCE))

    x('chown logstash:logstash -R /opt/logstash')
    x('cp {0}/logstash/start/shipper /etc/init.d/'.format(CONF_SOURCE))
    x('cp {0}/logstash/start/index /etc/init.d/'.format(CONF_SOURCE))
    x('chmod 700 /etc/init.d/shipper')
    x('chmod 700 /etc/init.d/index')
    x('chkconfig --add shipper')
    x('chkconfig --add index')
    x('chkconfig shipper on')
    x('chkconfig index on')
    x('/etc/init.d/shipper start')
    x('/etc/init.d/index start')


def config_rabbitmq():
    """
    There are no default config for rabbitmq
    Copy config from
    1. First from syco-private
    2. syco var/default config
    """
    x('cp -r {0}/rabbitmq /etc/'.format(CONF_SOURCE))

    # Remove old certs
    x('rm -rf /etc/rabbitmq/ssl')
    x('mkdir -p /etc/rabbitmq/ssl/private')

    x('openssl req -x509 -config {0}/rabbitmq/ssl/openssl.cnf -newkey rsa:4096 -days 3650 -out /etc/rabbitmq/ssl/cacert.pem -outform PEM -subj /CN=RabbitMQ/ -nodes'.format(CONF_SOURCE))

    x('openssl x509 -in /etc/rabbitmq/ssl/cacert.pem -out /etc/rabbitmq/ssl/cacert.cer -outform DER')
    x('openssl genrsa -out /etc/rabbitmq/ssl/key.pem 4096')
    x('cp /etc/rabbitmq/ssl/private/* /etc/rabbitmq/ssl/')
    x('openssl req -new -key /etc/rabbitmq/ssl/key.pem -out /etc/rabbitmq/ssl/req.pem -outform PEM -subj /CN=$(hostname)/O=server/ -nodes')
    x('touch /etc/rabbitmq/ssl/index.txt')
    x('echo 01 > /etc/rabbitmq/ssl/serial')

    x('openssl ca -config {0}/rabbitmq/ssl/openssl.cnf -in /etc/rabbitmq/ssl/req.pem -out /etc/rabbitmq/ssl/cert.pem -notext -batch -extensions server_ca_extensions'.format(CONF_SOURCE))
    x('openssl pkcs12 -export -out /etc/rabbitmq/ssl/keycert.p12 -in /etc/rabbitmq/ssl/cert.pem -inkey /etc/rabbitmq/ssl/key.pem -passout pass:MySecretPassword')

    x('/etc/init.d/rabbitmq-server restart')
    x('setsebool -P nis_enabled 1')
