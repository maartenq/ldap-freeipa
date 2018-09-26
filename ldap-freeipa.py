#!/usr/bin/env python
#
# ldap-freeipa.py
# Dynamic inventory script for FreeIPA using LDAP simple binds
# Steve Bonneville <sbonnevi@redhat.com>
#
# Copyright 2017 Red Hat, Inc.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#    1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
#    2. Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following
#    disclaimer in the documentation and/or other materials provided
#    with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY RED HAT, INC. ``AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL RED HAT, INC. BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import json
import ldap
import logging
import os
import sys
import six
from six.moves import configparser


###################################################
# DO NOT EDIT ABOVE THIS LINE.

##
# Logging
##
logger = logging.getLogger()
handler = logging.StreamHandler()
formatter = logging.Formatter(
            '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.ERROR)


##
# Configuration settings
##

# EDIT: LDAP URI of your FreeIPA server
LDAP_URI = "ldap://utility.lab.example.com"

# EDIT: BaseDN of your FreeIPA server
LDAP_BASEDN = "dc=lab,dc=example,dc=com"

# EDIT: DN and password of a service user on your FreeIPA server
# (anonymous bind can't see all the necessary attributes)
# should not be a normal end-user account since password is exposed
# to anyone with access to this script
# See http://www.freeipa.org/page/HowTo/LDAP (may be outdated)
LDAP_BINDDN = "uid=inventory,cn=users,cn=accounts,dc=lab,dc=example,dc=com"
LDAP_BINDPW = "needabetterpassword"
MEMBER_OF_GRP = ""

# DO NOT EDIT BELOW THIS LINE.
###################################################

# Above settings will be used as defaults.
# These settings can be overwritten by a ini file with a `ldap-freeipa` section
# and valid entries. The path of the ini file can be set with the environment
# variable 'LDAP_FREEIPA_INI_PATH', defaults to `ldap-freeipa.ini` in same
# directory as the `ldap-freeipa.py` script.
#
# Example `ldap-freeipa.ini`:
#
# [ldap-freeipa]
# ldap_uri = ldap://utility.lab.example.com
# ldap_basedn = dc=lab,dc=example,dc=com
# ldap_bindpw = needabetterpassword
# ldap_binddn = uid=inventory,cn=users,cn=accounts,dc=lab,dc=example,dc=com

# Work needed:
# * LDAPS support for FreeIPA
# * Potentially set some host variables from other attributes
# * Make it easier for a newbie to set the LDAP_* variables above


def get_config():
    '''
    Reads the settings from the ldap-freeipa.ini file
    Returns ldap-freeipa setting dict.
    '''

    defaults = {
        'ldap-freeipa': {
            'ldap_uri': LDAP_URI,
            'ldap_basedn': LDAP_BASEDN,
            'ldap_binddn': LDAP_BINDDN,
            'ldap_bindpw': LDAP_BINDPW,
            'member_of_grp': MEMBER_OF_GRP,
            'ini_path': os.path.join(
                os.path.dirname(__file__),
                'ldap-freeipa.ini',
            )
        }
    }

    if six.PY3:
        config = configparser.ConfigParser()
    else:
        config = configparser.SafeConfigParser()

    # where is the config?
    ldap_freeipa_ini_path = os.environ.get(
        'LDAP_FREEIPA_INI_PATH',
        defaults['ldap-freeipa']['ini_path'])
    config.read(ldap_freeipa_ini_path)

    if 'ldap-freeipa' not in config.sections():
        config.add_section('ldap-freeipa')

    # apply defaults
    for k, v in defaults['ldap-freeipa'].items():
        if not config.has_option('ldap-freeipa', k):
            config.set('ldap-freeipa', k, str(v))

    # update ini_path
    config.set('ldap-freeipa', 'ini_path', ldap_freeipa_ini_path)

    return dict(config.items('ldap-freeipa'))


def listgroup(ldap_uri, ldap_basedn, ldap_binddn, ldap_bindpw, member_of_grp):

    # Simple bind to the FreeIPA server and run a subtree
    # search for hostgroups (objectclass=ipahostgroup),
    # and retrieve all values of their 'member' attributes

    conn = ldap.initialize(ldap_uri)
    search_scope = ldap.SCOPE_SUBTREE
    search_filter = "(objectclass=ipahostgroup)"
    search_attribute = ["cn", "member"]

    try:
        conn.protocol_version = ldap.VERSION3
        conn.simple_bind_s(ldap_binddn, ldap_bindpw)
    except ldap.INVALID_CREDENTIALS:
        logger.error("Your bind DN or password is incorrect.")
        sys.exit(1)
    except ldap.LDAPError, e:
        logger.error("LDAPError: %s.", e)
        sys.exit(1)

    try:
        member_of_grp_members = []
        if member_of_grp:
            # Only add hosts that are member of member_of_grp
            # Get this hostgroup and members first.
            member_of_grp_ldap_result = conn.search(
                ldap_basedn,
                search_scope,
                "(&(objectclass=ipahostgroup)(cn=%s))" % member_of_grp,
                search_attribute
            )
            while 1:
                member_of_grp_result_type, member_of_grp_result_data = conn.result(
                    member_of_grp_ldap_result, 0)
                if (member_of_grp_result_data == []):
                    break
                if member_of_grp_result_type == ldap.RES_SEARCH_ENTRY:
                    try:
                        member_of_grp_members = member_of_grp_result_data[0][1]['member']
                    except KeyError:
                        member_of_grp_members = []

        # Get all hostgroups and members.
        ldap_result = conn.search(
            ldap_basedn,
            search_scope,
            search_filter,
            search_attribute
        )
        hostgroup = {}
        while 1:
            result_type, result_data = conn.result(ldap_result, 0)
            if (result_data == []):
                break
            else:
                if result_type == ldap.RES_SEARCH_ENTRY:
                    groupname = result_data[0][1]['cn'][0]
                    try:
                        memberlist = result_data[0][1]['member']
                    except KeyError:
                        memberlist = []

                    # If the RDN of a hostgroup member is "cn",
                    # then it's a nested hostgroup.
                    #
                    # If the RDN of a hostgroup member is "fqdn",
                    # then it's a host.

                    hosts = []
                    children = []
                    for member in memberlist:
                        memberdn = ldap.dn.str2dn(member)
                        if (memberdn[0][0][0] == "cn"):
                            children.append(memberdn[0][0][1])
                        if member_of_grp:
                            if member not in member_of_grp_members:
                                continue
                        if (memberdn[0][0][0] == "fqdn"):
                            hosts.append(memberdn[0][0][1])

                    if hosts:
                        if (children != []):
                            hostgroup[groupname] = {
                                'hosts': hosts,
                                'children': children
                            }
                        else:
                            hostgroup[groupname] = {
                                'hosts': hosts
                            }

        # assume that we have no hostvars
        hostgroup["_meta"] = {'hostvars': {}}
        print(json.dumps(hostgroup))

    except ldap.LDAPError, e:
        logger.error("LDAPError: %s.", e)
    finally:
        conn.unbind_s()


def listhost(hostname):
    # does not check to ensure host exists
    # assume that we have no hostvars
    print(json.dumps({}))


if __name__ == '__main__':
    if len(sys.argv) == 2 and (sys.argv[1] == '--list'):
        config = get_config()
        listgroup(
            config['ldap_uri'],
            config['ldap_basedn'],
            config['ldap_binddn'],
            config['ldap_bindpw'],
            config['member_of_grp'],
        )
    elif len(sys.argv) == 3 and (sys.argv[1] == '--host'):
        listhost(sys.argv[2])
    else:
        print("Usage: %s --list or --host <hostname>" % sys.argv[0])
        sys.exit(1)
