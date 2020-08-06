# coding=utf-8
from __future__ import absolute_import

import json

import ldap
from octoprint_auth_ldap.constants import AUTH_PASSWORD, AUTH_USER, DISTINGUISHED_NAME, OU, OU_FILTER, OU_MEMBER_FILTER, \
    REQUEST_TLS_CERT, SEARCH_BASE, URI
from octoprint_auth_ldap.tweaks import DependentOnSettingsPlugin, SettingsPlugin


class LDAPConnection(DependentOnSettingsPlugin):
    def __init__(self, plugin: SettingsPlugin):
        DependentOnSettingsPlugin.__init__(self, plugin)

    def get_client(self, user=None, password=None):
        uri = self.settings.get([URI])
        if not uri:
            self.logger.debug("No LDAP URI")
            return None

        if not user:
            user = self.settings.get([AUTH_USER])
            password = self.settings.get([AUTH_PASSWORD])

        try:
            self.logger.debug("Initializing LDAP connection to %s" % uri)
            client = ldap.initialize(uri)
            client.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            if self.settings.get([REQUEST_TLS_CERT]):
                self.logger.debug("Requesting TLS certificate")
                client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
            else:
                client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            if user is not None:
                self.logger.debug("Binding to LDAP as %s" % user)
                client.bind_s(user, password)
            return client
        except ldap.INVALID_CREDENTIALS:
            self.logger.error("Invalid credentials to bind to LDAP as %s" % user)
        except ldap.LDAPError as e:
            self.logger.error(json.dumps(e))
        return None

    def search(self, ldap_filter, base=None, scope=ldap.SCOPE_SUBTREE):
        if not base:
            base = self.settings.get([SEARCH_BASE])
        try:
            client = self.get_client()
            if client is not None:
                result = client.search_s(base, scope, ldap_filter)
                client.unbind_s()
                if result:
                    dn, data = result[0]
                    """
                    # Dump LDAP search query results to logger
                    self.logger.debug("dn: %s" % dn)
                    for key, value in data.items():
                        self.logger.debug("%s: %s" % (key, value))
                    """
                    return dict(dn=dn, data=data)
        except ldap.LDAPError as e:
            self.logger.error(json.dumps(e))
        return None

    def get_ou_memberships_for(self, dn):
        memberships = []
        name = dn.split(',')[0]
        ou_common_names = self.settings.get([OU])
        if ou_common_names is None:
            return False

        user = self.search(name)
        memberships = [ group.decode().split(',')[0].replace('CN=','') for \
              group in user['data']['memberOf'] ]
        return memberships


class DependentOnLDAPConnection:
    # noinspection PyShadowingNames
    def __init__(self, ldap: LDAPConnection):
        self._ldap = ldap

    @property
    def ldap(self) -> LDAPConnection:
        return self._ldap
