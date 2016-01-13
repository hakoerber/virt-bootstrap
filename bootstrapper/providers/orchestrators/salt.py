#!/usr/bin/env python2
from __future__ import absolute_import


import bootstrapper.providers.orchestrators
import bootstrapper.salt


class Orchestrator(bootstrapper.providers.orchestrators.Orchestrator):
    def __init__(self, connection, *args, **kwargs):
        super(Orchestrator, self).__init__(connection, *args, **kwargs)
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

    def update(self, nodes):
        jid = self._salt_client.cmd_async(
            tgt=nodes,
            fun='state.highstate',
            kwarg={'queue': True},
            expr_form='list')
        return jid

    def wait_for_job(self, jid):
        results = self._salt_client.get_cli_returns(jid)
        success = True
        for minion, result in results['data'].items():
            for state, output in result.items():
                if not output['result']:
                    success = False
        return success

    def disconnect(self):
        if self._salt_client is not None:
            self._salt_client.disconnect()


class Connection(bootstrapper.providers.orchestrators.Connection):
    def __init__(self, url, user, password):
        super(Connection, self).__init__()
        self.url = url
        self.user = user
        self.password = password
