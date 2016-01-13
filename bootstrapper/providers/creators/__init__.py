#!/usr/bin/env python2

import bootstrapper.providers


class Creator(bootstrapper.providers.Provider):
    def __init__(self, connection):
        super(Creator, self).__init__(connection)

    def domain_exists(self, domain):
        raise NotImplementedError()

    def create(self, params):
        raise NotImplementedError()

    def disable_pxe_boot(self, domain):
        raise NotImplementedError()

    def running(self, domain):
        raise NotImplementedError()

    def start(self, name):
        pass

    def get_memory(self, name):
        raise NotImplementedError()

    def set_memory(self, name, memory):
        raise NotImplementedError()


class Params(object):
    def __init__(self, memory):
        self.memory = memory


class Connection(object):
    def __init__(self):
        pass
