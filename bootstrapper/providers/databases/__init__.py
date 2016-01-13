#!/usr/bin/env python2

import bootstrapper.providers


class Database(bootstrapper.providers.Provider):
    def __init__(self, connection):
        super(Database, self).__init__(connection)

    def get_nodeinfo(self, nodename):
        raise NotImplementedError()


class Connection(object):
    def __init__(self):
        pass
