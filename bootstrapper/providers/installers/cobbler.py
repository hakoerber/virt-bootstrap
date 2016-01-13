#!/usr/bin/env python2
from __future__ import absolute_import

import xmlrpclib

import bootstrapper.providers.installers


class Installer(bootstrapper.providers.installers.Installer):
    def __init__(self, connection, *args, **kwargs):
        super(Installer, self).__init__(connection, *args, **kwargs)
        self._conparam = connection
        self._server = None
        self._token = None

    def connect(self):
        self._server = xmlrpclib.Server(self._conparam.server)
        self._token = self._server.login(
            self._conparam.user,
            self._conparam.password)
        return True

    def has_system(self, system):
        return self._server.find_system({"hostname": system}) != []

    def setup_system(self, nodename, profile, primary_interface, mac, ssh_key,
                     **kwargs):
        new_system = self._server.new_system(self._token)

        def _set(key, value):
            self._server.modify_system(new_system, key, value, self._token)

        _set('name', nodename)
        _set('profile', profile)
        _set('ks_meta', 'authorized_key="{key}"'.format(key=ssh_key))
        _set('hostname', nodename)

        _ifinfo = {}

        def _set_if(key, value):
            fullkey = '{key}-{interface}'.format(
                key=key, interface=primary_interface)
            _ifinfo[fullkey] = value

        _set_if('macaddress', mac)

        if kwargs.get('static'):
            _set_if('static', 'true')
            _set_if('ip_address', kwargs['ip'])
            _set_if('netmask', kwargs['netmask'])

            # this is not interface specific but only available when not static
            _set('gateway', kwargs['gateway'])
            _set('name_servers', ','.join(kwargs['nameservers']))
        else:
            _set_if('static', 'false')

        _set('modify_interface', _ifinfo)

        self._server.save_system(new_system, self._token)

    def disconnect(self):
        pass


class Connection(bootstrapper.providers.installers.Connection):
    def __init__(self, server, user, password):
        super(Connection, self).__init__()
        self.server = server
        self.user = user
        self.password = password
