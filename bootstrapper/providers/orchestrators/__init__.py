#!/usr/bin/env python2

import bootstrapper.providers


class Orchestrator(bootstrapper.providers.Provider):
    def __init__(self, connection):
        super(Orchestrator, self).__init__(connection)

    def update(self, nodes):
        raise NotImplementedError()


class Connection(object):
    def __init__(self):
        pass
