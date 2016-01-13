#!/usr/bin/env python2


class Provider(object):
    def __init__(self, connection):
        pass

    def connect(self):
        raise NotImplementedError()

    def disconnect(self):
        raise NotImplementedError()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


def get_provider(provider_type, name):
    module = __import__(
        __name__ + '.' + provider_type, globals(), locals(), fromlist=[name])
    return module.__dict__[name]
