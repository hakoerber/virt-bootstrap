#!/usr/bin/env python2

import bootstrapper.providers


class Installer(bootstrapper.providers.Provider):
    def __init__(self, connection):
        super(Installer, self).__init__(connection)

    def has_system(self, system):
        raise NotImplementedError()

    def setup_system(self, nodename, profile, primary_interface, ssh_key):
        raise NotImplementedError()


class Connection(object):
    def __init__(self):
        pass
