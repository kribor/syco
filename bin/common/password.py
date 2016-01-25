#!/usr/bin/env python
"""
Application global wide helper functions.

TODO:
Should be
import password
print password.svn
print password.mysql
"""

__author__ = "daniel.lindh@cybercow.se"
__copyright__ = "Copyright 2011, The System Console project"
__maintainer__ = "Kristofer Borgström"
__email__ = "syco@cybercow.se"
__credits__ = ["Daniel Lindh"]
__license__ = "???"
__version__ = "1.0.0"
__status__ = "Production"

import subprocess

from constant import *
import passwordstore

def _get_password_store():
    """
    Get a password store object.

    """
    if (not _get_password_store.password_store):
        _get_password_store.password_store = passwordstore.PasswordStore(PASSWORD_STORE_PATH)

    return _get_password_store.password_store

_get_password_store.password_store = None

def _get_password(service, user_name):
    """
    Get a password from the password store.g

    """
    password = _get_password_store().get_password(service, user_name)
    _get_password_store().save_password_file()
    return password

def get_all_passwords():
    return _get_password_store().get_all_passwords()

def get_custom_password(service, user_name):

    if service is None or user_name is None:
        raise Exception("None service and user name not allowed, please specify both")

    return _get_password(service, user_name)

def get_master_password():
    """
    Get a password from the password store.

    """
    password = _get_password_store().get_master_password()
    _get_password_store().save_password_file()
    return password

def get_root_password():
    """The linux shell root password."""
    return _get_password("linux", "root")

def get_root_password_hash():
    """
    Openssl hash of the linux root password.

    """
    root_password = get_root_password()
    p = subprocess.Popen("openssl passwd -1 '" + root_password + "'", stdout=subprocess.PIPE, shell=True)
    hash_root_password, stderr = p.communicate()
    return str(hash_root_password.strip())

def get_user_password(username):
    """The linux shell password for a specific user."""
    return _get_password("linux", username)

def get_ca_password():
    """The password used when creating CA certificates"""
    return get_root_password()


def init_core_passwords():
    """
    Ask the user for all passwords used by syco, and add to passwordstore.

    """
    get_root_password()
