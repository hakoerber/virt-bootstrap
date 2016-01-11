#!/usr/bin/env python2

class Creator(object):
    def __init__(self, connection):
        pass

    def connect(self):
        pass

    def domain_exists(self, domain):
        pass

    def create(self, params):
        pass

    def disable_pxe_boot(self, domain):
        pass

    def running(self, domain):
        pass

    def start(self, name):
        pass

    def get_memory(self, name):
        pass

    def set_memory(self, name, memory):
        pass

    def disconnect(self):
        pass


class Params(object):
    def __init__(self, memory):
        self.memory = memory

class Connection(object):
    def __init__(self):
        pass
