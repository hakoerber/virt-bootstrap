#!/usr/bin/env python2

import sys
import argparse
import time
import logging
import os
import os.path
import subprocess
import socket
import tempfile
import shutil

import paramiko
import paramiko.client
import yaml

import bootstrapper.providers


# The minimum amount of memory in MiB that is required for installation.
INSTALLATION_MEMORY = 1024

# How long to wait for the installation to finish. If it is not finished after
# this time, the script exists and leaves the installation running on the
# hypervisor
INSTALLATION_TIMEOUT = 600

# How long to wait for SSH to become available after the node reboots when
# installation is finished
SSH_TIMEOUT = 60

# How long to wait until ping is successful after node startup
STARTUP_TIMEOUT = 60

# Seconds between pings when pinging new node
PING_SPACING = 1


logging.getLogger("paramiko").setLevel(logging.WARNING)
logger = None


class RemoteCmdError(Exception):
    def __init__(self, retcode, stderr):
        super(RemoteCmdError, self).__init__()
        self.retcode = retcode
        self.stderr = stderr


class IgnoreMissingKeyPolicy(paramiko.client.MissingHostKeyPolicy):
    """
    Helper class for paramiko to ignore missing host keys when connecting.
    """
    def __init__(self, *args, **kwargs):
        super(IgnoreMissingKeyPolicy, self).__init__(*args, **kwargs)

    def missing_host_key(self, *args, **kargs):
        return


def ensure_node_state(nodename, provider, config):
    creator_connection = provider.Connection(
        **config['connection'])
    with provider.Creator(creator_connection) as creator:
        if creator.running(nodename):
            logger.info("No need to start domain, already active.")
        else:
            logger.info("Starting domain ...")
            creator.start(nodename)

            logger.info("Waiting for node startup ...")
            if not wait_for_ping(target=nodename, timeout=STARTUP_TIMEOUT,
                                 spacing=PING_SPACING):
                logger.critical("Host not responding to ping.")
                sys.exit(1)


def create_new_node(nodename, provider, pillar, config):
    primary_interface = get_primary_interface(pillar)
    creator_connection = provider.Connection(
        **config['connection'])
    with provider.Creator(creator_connection) as creator:
        if creator.domain_exists(nodename):
            logger.error("The domain already exists on the hypervisor.")
            sys.exit(1)

        logger.info("Creating new virtual machine ...")
        mem = pillar['machine']['memory']
        if mem < INSTALLATION_MEMORY:
            logger.debug("Increasing memory from {mem}MiB to {new_mem}MiB for "
                         "installation, reducing later.".format(
                             mem=mem, new_mem=INSTALLATION_MEMORY))
            mem = INSTALLATION_MEMORY

        creator.create(params={
            'name': nodename,
            'memory': mem*1024,
            'vcpus': pillar['machine']['vcpus'],
            'arch': 'x86_64',
            'interfaces': [
                {
                    'mac': primary_interface['mac'],
                    'network': pillar['machine']['network']
                }
            ],
            'disks': [
                {
                    'pool': 'centos',
                    'name': nodename,
                    'size': pillar['machine']['disk']['size']
                }
            ]})

        logger.info("Starting installation ...")
        creator.start(nodename)
        logger.info("Waiting for installation to finish ...")
        i = 0
        success = False
        while i < INSTALLATION_TIMEOUT:
            i += 1
            if not creator.running(nodename):
                success = True
                break
            time.sleep(1)
        if not success:
            logger.critical("Installation timed out.")

        logger.info("Adjusting memory ...")
        creator.set_memory(nodename, pillar['machine']['memory']*1024)

        logger.info("Disabling network boot ...")
        creator.disable_pxe_boot(nodename)


def setup_logger(console_level):
    global logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(console_level)
    formatter = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)-8s] %(message)s",
        datefmt="%H:%M:%S")
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)


def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('nodename')

    group = parser.add_argument_group('required arguments')
    group.add_argument("--config", action='store', metavar='PATH',
                       required=True)

    parser.add_argument("--debug", action='store_true')
    parser.add_argument("--no-install-server", action='store_true')
    parser.add_argument("--no-create", dest="no_install", action='store_true')
    parser.add_argument("--no-ensure-state", action='store_true')
    parser.add_argument("--no-ssh", action='store_true')
    parser.add_argument("--no-prepare-env", action='store_true')
    parser.add_argument("--no-configure", action='store_true')
    parser.add_argument("--no-finalize", action='store_true')
    parser.add_argument("--regen-host-keys", action='store_true')

    return parser.parse_args(argv[1:])


def parse_config(path):
    return yaml.load(open(path))


def load_providers(config):
    def _get_provider(provider_type):
        return bootstrapper.providers.get_provider(
            provider_type + 's', config[provider_type]['provider'])

    providers = ['database',
                 'installer',
                 'creator',
                 'orchestrator',
                 'configurator']

    return dict(zip(providers, map(_get_provider, providers)))


def get_primary_interface(pillar):
    interfaces = pillar.get('interfaces')
    primary_interface = None
    if interfaces is None:
        logger.critical("No interfaces defined for node.")
        sys.exit(1)
    if len(interfaces) == 1:
        primary_interface = interfaces[0]
    else:
        for interface in interfaces:
            if interface['primary'] is True:
                if primary_interface is not None:
                    logger.critical("More than one interface is defined as "
                                    "primary.")
                    sys.exit(1)
                primary_interface = interface
    return primary_interface


def setup_install_server(install_server, nodename, pillar, primary_interface,
                         ssh_key):
    ifoptions = {'static': False}
    if primary_interface['mode'] == 'static':
        ifoptions['static'] = True
        ifoptions['ip'] = primary_interface['ip']

        network = pillar['network'][primary_interface['network']]
        domain = pillar['domain'][primary_interface['network']]
        ifoptions['gateway'] = network['default_gateway']
        ifoptions['netmask'] = network['netmask']
        ifoptions['nameservers'] = [
            ns['ip'] for ns in
            domain['applications']['dns']['zoneinfo']['nameservers']
            if ns['ip'] != ifoptions['ip']]

    ssh_authorized_key = "{name} {key} {comment}".format(
        name=ssh_key.get_name(),
        key=ssh_key.get_base64(),
        comment=nodename)

    install_server.setup_system(
        nodename=nodename,
        profile=pillar['machine']['profile'],
        primary_interface=primary_interface['identifier'],
        mac=primary_interface['mac'],
        ssh_key=ssh_authorized_key,
        **ifoptions)


def generate_ssh_key():
    key = paramiko.rsakey.RSAKey.generate(bits=4096)
    return key


def ssh_connect(nodename, ssh_key):
    logger.info("Trying to connect via SSH ...")
    tries = 0
    connection = None
    while connection is None and tries <= 3:
        try:
            connection = ssh_attempt_connect(nodename, ssh_key)
        except paramiko.ssh_exception.AuthenticationException:
            logger.exception("Unrecoverable error, giving up.")
            break
        except (paramiko.SSHException, socket.timeout, socket.error):
            logger.exception("Failed.")
        tries += 1
        time.sleep(1)
    if connection is None:
        logger.critical("SSH connection failed.")
        sys.exit(1)
    return connection


def ssh_attempt_connect(nodename, ssh_key):
    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(IgnoreMissingKeyPolicy())
    user = 'root'
    port = 22
    logger.debug("Connect to \"{nodename}\" as \"{user}\" on port {port}.".
                 format(nodename=nodename, user=user, port=port))
    try:
        client.connect(nodename,
                       port=port,
                       username=user,
                       timeout=SSH_TIMEOUT,
                       pkey=ssh_key,
                       allow_agent=False,
                       look_for_keys=False)
    except (paramiko.SSHException, socket.timeout, socket.error):
        raise
    return client


def read_ssh_key(directory, name='id_rsa'):
    private_key_file = os.path.join(directory, name)
    if not os.path.exists(private_key_file):
        return None
    ssh_key = paramiko.RSAKey.from_private_key_file(filename=private_key_file,
                                                    password=None)
    return ssh_key


def save_ssh_key(ssh_key, directory, name='id_rsa'):
    if not os.path.exists(directory):
        os.makedirs(directory)

    private_key_file = os.path.join(directory, name)
    ssh_key.write_private_key_file(private_key_file)
    with open(private_key_file + '.pub', 'w') as public_file:
        public_file.write("{name} {key} {comment}".format(
            name=ssh_key.get_name(),
            key=ssh_key.get_base64(),
            comment="minion provisioning"))


def start_update_environment(nodename, orchestrator, pillar):
    # we need to update (a.k.a. run highstate on):
    # - DNS servers
    # - DHCP servers
    servers = set()

    for domain in pillar['domains']:
        nameservers = domain['applications']['dns']['zoneinfo']['nameservers']
        for nameserver in nameservers:
            fqdn = nameserver['name'] + '.' + domain['name']
            servers.add(fqdn)

    for network in pillar['networks']:
        dhcpservers = network['applications']['dhcp']['servers']
        for dhcpserver in dhcpservers:
            fqdn = dhcpserver['name'] + '.' + network['domain']
            servers.add(fqdn)

    # filter ourselves out
    servers = [server for server in servers if server != nodename]

    token = orchestrator.update(servers)
    return token


def wait_for_environment_update(orchestrator, jid):
    logger.info("Waiting for environment preparation to finish ...")
    logger.debug("Waiting for jid {} ...".format(jid))
    success = orchestrator.wait_for_job(jid)

    if not success:
        logger.critical("Environment update failed.")
        sys.exit(1)


def wait_for_ping(target, timeout, spacing):
    logger.debug("Waiting for successful ping to \"{}\".".format(target))
    while timeout > 0:
        timeout -= spacing

        ping_args = ['ping',
                     '-c', '1',
                     '-w', '1',
                     '-q', target]
        process = subprocess.Popen(ping_args, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        returncode = process.wait()

        if returncode == 0:
            logger.debug("Ping successful.")
            return True
        logger.debug("Ping: no response")
        time.sleep(spacing)
    logger.debug("Ping timeout.")
    return False


def main(argv):
    args = parse_args(argv)
    config = parse_config(args.config)

    providers = load_providers(config)

    nodename = args.nodename
    if args.debug:
        console_level = logging.DEBUG
    else:
        console_level = logging.INFO

    setup_logger(console_level)

    database_connection = providers['database'].Connection(
        **config['database']['connection'])

    with providers['database'].Database(database_connection) as database:
        pillar = database.get_nodeinfo(nodename)

    if not pillar:
        logger.critical("No pillar data found for node \"{}\".".format(
            nodename))
        sys.exit(1)

    primary_interface = get_primary_interface(pillar)

    ssh_key = None

    tempdir = os.path.join(tempfile.gettempdir(), 'bootstrap')
    temp_keydir = os.path.join(tempdir, nodename)
    if not args.no_ssh:
        if not args.no_install:
            logger.info("Generating ephemeral SSH key ...")
            ssh_key = generate_ssh_key()

            logger.info("Saving SSH keys to \"{}\".".format(temp_keydir))
            save_ssh_key(ssh_key, temp_keydir)
        else:
            logger.info("Reloading key from disk ...")
            ssh_key = read_ssh_key(temp_keydir)
            if ssh_key is None:
                logger.critical("SSH key not found in \"{}\"".format(
                    temp_keydir))
                sys.exit(1)

    if not (args.no_install_server or args.no_install):
        install_server_connection = providers['installer'].Connection(
            **config['installer']['connection'])

        with providers['installer'].Installer(install_server_connection) \
                as install_server:
            if (install_server.has_system(nodename) and
                    not config['installer'].get('overwrite', False)):
                logger.critical("A system with the same name already exists "
                                "on the install server.")
                sys.exit(1)

            logger.info("Setting up install server ...")

            setup_install_server(install_server, nodename, pillar,
                                 primary_interface, ssh_key)

    if not args.no_prepare_env:
        orchestrator_connection = providers['orchestrator'].Connection(
            **config['orchestrator']['connection'])

        # no "with" statement because we need the object it later
        orchestrator = providers['orchestrator'].Orchestrator(
            orchestrator_connection)
        orchestrator.connect()
        logger.info("Preparing environment for new node ...")
        env_jid = start_update_environment(
            nodename, orchestrator, pillar)

    connection = None
    if not args.no_install:
        create_new_node(
            nodename, providers['creator'], pillar, config['creator'])

    if not args.no_prepare_env:
        wait_for_environment_update(orchestrator, env_jid)
        # now we are done with the object
        orchestrator.disconnect()

    if not args.no_ensure_state:
        ensure_node_state(nodename, providers['creator'], config['creator'])

    configurator_connection = providers['configurator'].Connection(
        **config['configurator']['connection'])
    configurator = providers['configurator'].Configurator(
        configurator_connection)
    configurator.connect()

    connection = None
    if not args.no_ssh:
        if not args.no_install:
            logger.info("Waiting 5 seconds for SSH server startup on node ...")
            time.sleep(5)
        connection = ssh_connect(nodename, ssh_key)

        keys = configurator.generate_keys(
            nodename=nodename,
            directory=temp_keydir)
        if keys is None:
            logger.critical("Key generation failed.")
            sys.exit(1)

        agent = providers['configurator'].Agent()
        agent.store_keys(keys, connection)

        agent.start(connection)

    if args.regen_host_keys or not configurator.has_hostkeys(
            nodename, **config['configurator']):
        logger.info("Generating SSH host keys ...")
        key = generate_ssh_key()

        if not configurator.store_hostkeys(
                nodename, key, **config['configurator']):
            logger.critical("Hostkey store failed.")
            sys.exit(1)
    else:
        logger.info("SSH host keys already exist, not regenerating.")

    if not args.no_configure:
        # give some time to connect
        time.sleep(5)

        logger.info("Testing minion connection ...")
        if not configurator.ping(nodename):
            logger.critical("Minion did not show up.")
            sys.exit(1)

        logger.info("Configuring new node ...")
        if not configurator.configure(nodename):
            logger.critical("Configuration failed.")
            sys.exit(1)

    configurator.disconnect()

    if not args.no_finalize:
        if not args.no_ssh:
            logger.info("Cleaning authorized key file on new node ...")
            try:
                connection.exec_command("> /root/.ssh/authorized_keys")
            except paramiko.SSHException as e:
                logger.critical("Key cleanup failed: {}".format(e.message))
                sys.exit(1)

        logger.info("Removing temporary directory ...")
        shutil.rmtree(temp_keydir)

    if connection is not None:
        connection.close()

    logger.info("Finished successfully!")
