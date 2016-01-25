#!/usr/bin/env python2
from __future__ import absolute_import

import os
import StringIO
import logging
import time

import bootstrapper.providers.configurators
import bootstrapper.salt

# Salt keysize in bits
DEFAULT_KEYSIZE = 4096

AGENT_KEYDIR = "/etc/salt/pki/minion"

logger = logging.getLogger()


class Agent(object):
    def __init__(self):
        pass

    def store_keys(self, keys, ssh_connection):
        logger.info("Copying salt keys to minion ...")
        sftp = ssh_connection.open_sftp()

        ssh_connection.exec_command(
            'mkdir --mode 700 --parents {}'.format(AGENT_KEYDIR))

        for source, target in {
                keys['pem']: '{}/minion.pem'.format(AGENT_KEYDIR),
                keys['pub']: '{}/minion.pub'.format(AGENT_KEYDIR)}.items():

            logger.debug("Copying \"{source}\" to \"{target}\" on remote host "
                         "...".format(source=source, target=AGENT_KEYDIR))
            ssh_connection.exec_command('rm -f {}'.format(AGENT_KEYDIR))
            # we need to wait a bit between deleting and recreating, otherwise
            # copying might be done before deletion
            time.sleep(0.5)
            # confirm makes the transfer fail
            sftp.put(source, target)
        sftp.close()

    def start(self, ssh_connection):
        # some grace time before starting the minion, or else it might generate
        # its own keys
        time.sleep(1)

        logger.info("Starting salt minion ...")
        ssh_connection.exec_command('service salt-minion restart')


class Configurator(bootstrapper.providers.configurators.Configurator):
    def __init__(self, connection, *args, **kwargs):
        super(Configurator, self).__init__(connection, *args, **kwargs)
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

    def generate_keys(self, nodename, directory, keysize=DEFAULT_KEYSIZE):
        result = self._salt_client.wheel(
            fun='key.gen_accept',
            kwarg={
                'id_': nodename,
                'force': True,
                'keysize': keysize
            })

        if not result['data']['success']:
            return None

        pub = result['data']['return']['pub']
        priv = result['data']['return']['priv']

        key_pub = os.path.join(directory, '{}.pub'.format(nodename))
        key_pem = os.path.join(directory, '{}.pem'.format(nodename))

        with open(key_pub, 'w') as pubfile:
            pubfile.write(pub)

        with open(key_pem, 'w') as privfile:
            privfile.write(priv)

        return({'pub': key_pub, 'pem': key_pem})

    def has_hostkeys(self, nodename, **kwargs):
        result = self._salt_client.wheel(
            fun='file_roots.find',
            kwarg={
                'saltenv': kwargs.get('environment', 'base'),
                'path': os.path.join(kwargs['hostkey_dir'],
                                     nodename,
                                     'ssh_host_rsa_key')
            })
        return result['data']['return'] != []

    def store_hostkeys(self, nodename, key, **kwargs):
        def _write(name, key):
            path = os.path.join(kwargs['hostkey_dir'], nodename, name)
            logger.debug("Path: {}".format(path))
            result = self._salt_client.wheel(
                fun='file_roots.write',
                kwarg={
                    'saltenv': kwargs.get('environment', 'base'),
                    'path': path,
                    'data': key
                })
            return result

        logger.debug("Writing public key.")
        result_pub = _write(
            'ssh_host_rsa_key.pub',
            '{name} {key} {comment}\n'.format(
                name=key.get_name(),
                key=key.get_base64(),
                comment=nodename))

        # paramiko has no way to just give us the raw private key data
        vfile = StringIO.StringIO()
        key.write_private_key(vfile)
        data = vfile.getvalue()
        vfile.close()
        logger.debug("Writing private key.")
        result_priv = _write('ssh_host_rsa_key', data)

        return result_pub['data']['success'] and result_priv['data']['success']

    def ping(self, nodename):
        result = self._salt_client.cmd(
            tgt=nodename,
            fun='test.ping',
            timeout=30)
        try:
            return result[nodename]
        except KeyError:
            return False

    def configure(self, nodename):
        jid = self._salt_client.cmd_async(
            tgt=nodename,
            fun='state.highstate')
        result = self._salt_client.get_cli_returns(jid, timeout=5*60)
        try:
            result = result['data'][nodename]
        except (KeyError, ValueError, TypeError):
            logger.debug("Failed to parse result.")
            return False
        all_ok = True
        for state in result.values():
            if not state['result']:
                logger.debug("Failed state: \"{}\".".format(state.get('name', 'unknown')))
                all_ok = False
            else:
                logger.debug("Successful state: \"{}\".".format(state.get('name', 'unknown')))
        return all_ok

    def disconnect(self):
        if self._salt_client is not None:
            self._salt_client.disconnect()


class Connection(bootstrapper.providers.configurators.Connection):
    def __init__(self, url, user, password):
        super(Connection, self).__init__()
        self.url = url
        self.user = user
        self.password = password
