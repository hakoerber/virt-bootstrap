#!/usr/bin/env python2

import bootstrapper.providers


class Configurator(bootstrapper.providers.Provider):
    def __init__(self, connection):
        super(Configurator, self).__init__(connection)

    def generate_keys(self, nodename, directory, keysize):
        raise NotImplementedError()

    def configure(self, nodename):
        raise NotImplementedError()


class Connection(object):
    def __init__(self):
        pass
