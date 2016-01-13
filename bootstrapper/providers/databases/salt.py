#!/usr/bin/env python2
from __future__ import absolute_import

import bootstrapper.providers.databases
import bootstrapper.salt


class Database(bootstrapper.providers.databases.Database):
    def __init__(self, connection, *args, **kwargs):
        super(Database, self).__init__(connection)
        self._conparam = connection
        self._connection = None
        self._salt_client = None

    def connect(self):
        self._salt_client = bootstrapper.salt.RemoteClient(
            url=self._conparam.url,
            user=self._conparam.user,
            password=self._conparam.password)
        if not self._salt_client.connect():
            return False
        return True

    def get_nodeinfo(self, nodename):
        return self._salt_client.runner(
            fun='pillar.show_pillar',
            kwarg={'minion': nodename})

    def disconnect(self):
        if self._salt_client is not None:
            self._salt_client.disconnect()


class Connection(bootstrapper.providers.databases.Connection):
    def __init__(self, url, user, password):
        super(Connection, self).__init__()
        self.url = url
        self.user = user
        self.password = password
