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
import StringIO

#import salt
#import salt.config
#import salt.runner
import paramiko
import paramiko.client

import bootstrapper.creators.libvirt
import bootstrapper.salt


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

# The default salt environment (producion, dev, ...)
DEFAULT_SALT_ENV = 'base'

# Salt keysize in bits
SALT_KEYSIZE = 4096

# Where to store SSH host keys. They will be stored in a subdirectory named
# after the host they belong to
DEFAULT_HOST_KEY_DIR = 'files/ssh/hostkeys/'

# Where the SSH key to access the hypervisor is stored
DEFAULT_SSH_HYPERVISOR_KEY = os.path.join(
    os.environ.get('HOME', '/root'), '.ssh/id_rsa')

# defaults URL to the salt cherrypy API
DEFAULT_SALT_URL = 'https://salt:8000'

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


def setup_logger(console_level):
    global logger
    logger = logging.getLogger(__file__)
    logger.setLevel(logging.DEBUG)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(console_level)
    formatter = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)-8s] %(message)s",
        datefmt="%H:%M:%S")
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)


def parse_args(argv):
    parser = argparse.ArgumentParser(description='Boostrap a new machine')
    parser.add_argument('nodename')

    group = parser.add_argument_group('generic options')
    group.add_argument("--debug", action='store_true')
    group.add_argument("--no-install-server", dest="no_cobbler", action='store_true')
    group.add_argument("--no-create", dest="no_install", action='store_true')
    group.add_argument("--no-ensure-state", action='store_true')
    group.add_argument("--no-ssh", action='store_true')
    group.add_argument("--no-prepare-env", action='store_true')
    group.add_argument("--no-configure", dest="no_salt_run", action='store_true')
    group.add_argument("--no-finalize", action='store_true')
    group.add_argument("--regen-host-keys", action='store_true')

    group = parser.add_argument_group('libvirt options')
    group.add_argument("--libvirt-keyfile", dest="hypervisor_keyfile",
                       action='store', metavar='FILE',
                       default=DEFAULT_SSH_HYPERVISOR_KEY)

    group = parser.add_argument_group('cobbler options')
    group.add_argument("--overwrite-cobbler", action='store_true')

    group = parser.add_argument_group('salt options')
    group.add_argument("--salt-env", action='store', default=DEFAULT_SALT_ENV,
                       metavar='ENV')
    group.add_argument("--host-key-dir", action='store',
                       default=DEFAULT_HOST_KEY_DIR, metavar='DIR')
    group.add_argument("--salt-url", action='store',
                       default=DEFAULT_SALT_URL, metavar='URL')
    group.add_argument("--salt-user", action='store', metavar='USER',
                       required=True)
    group.add_argument("--salt-password", action='store', metavar='PASSWORD',
                       required=True)

    group.add_argument("--no-salt-keygen", action='store_true')
    return parser.parse_args(argv[1:])


def execute_with_salt(salt_client, target, command, func='cmd'):
    logger.debug("cmd: " + " ".join(command))
    result = getattr(salt_client, func)(
        tgt=target,
        fun='cmd.run_all',
        arg=[" ".join(command)])
    result = result[target]
    if result['retcode'] != 0:
        raise RemoteCmdError(retcode=result['retcode'], stderr=result['stderr'])
    logger.debug("out: " + result['stdout'] + result['stderr'])
    return result


def _suppress_output(func, *args, **kwargs):
    """
    This is needed because the salt API pillar runner outputs to stdout for some
    reason.
    """
    save_stdout = sys.stdout
    sys.stdout = open('/dev/null', 'w')
    ret = func(*args, **kwargs)
    sys.stdout = save_stdout
    return ret


def get_pillar(salt_client, nodename):
    pillar = salt_client.runner(
        fun='pillar.show_pillar',
        kwarg={'minion': nodename})
    return pillar


def get_primary_interface(pillar):
    interfaces = pillar.get('interfaces')
    if interfaces is None:
        logger.critical("No interfaces defined for node.")
        sys.exit(1)
    if len(interfaces) == 1:
        primary_interface = interfaces
    else:
        primary_interfaces = {k: v for k, v  in interfaces.items()
                              if v.get('primary', False)}
        if len(primary_interfaces) != 1:
            logger.critical(
                "More than one interface is defined as primary: "
                "{interfaces}".format(
                    interfaces=[i['identifier'] for i in
                                primary_interfaces.values()]))
            sys.exit(1)
        primary_interface = primary_interfaces
    primary_interface[primary_interface.keys()[0]]['network'] = \
        primary_interface.keys()[0]
    return primary_interface.values()[0]


def cobbler_get_systems(salt_client, cobbler_server):
    args_cobbler = ['cobbler', 'system', 'list']
    try:
        result = execute_with_salt(salt_client,
                                   target=cobbler_server,
                                   command=args_cobbler)
    except RemoteCmdError:
        raise
    return [system.strip() for system in result['stdout'].splitlines()]


def get_cobbler_server(pillar, primary_interface):
    provisioning_server = pillar['network'][primary_interface['network']]\
            ['applications']['provisioning']['server']['name']
    return provisioning_server


def setup_cobbler(salt_client, cobbler_server, nodename, pillar,
                  primary_interface, ssh_key):
    args_cobbler = ['cobbler', 'system', 'add',
                    '--name', nodename,
                    '--profile', pillar['machine']['profile'],
                    '--hostname', nodename,
                    '--clobber']

    if ssh_key is not None:
        args_cobbler.extend([
            '--ksmeta', 'authorized_key="{}"'.format(
                get_authorized_key_line(ssh_key, 'cobbler').replace(
                    ' ', r'\ '))])


    args_cobbler.extend([
        '--interface', primary_interface['identifier'],
        '--mac-address', primary_interface['mac']])

    if primary_interface['mode'] == 'static':
        ip_address = primary_interface['ip']
        network = pillar['network'][primary_interface['network']]
        domain = pillar['domain'][primary_interface['network']]
        gateway = network['default_gateway']
        netmask = network['netmask']
        nameservers = [ns['ip'] for ns in
                       domain['applications']['dns']['zoneinfo']['nameservers']
                       if ns['ip'] != ip_address]

        args_cobbler.extend([
            '--static', 'true',
            '--name-servers', '\"{}\"'.format(' '.join(nameservers)),
            '--gateway', gateway,
            '--netmask', netmask,
            '--ip-address', ip_address
        ])

    try:
        execute_with_salt(salt_client,
                          target=cobbler_server,
                          command=args_cobbler)
    except RemoteCmdError:
        raise


def generate_ssh_key():
    key = paramiko.rsakey.RSAKey.generate(bits=4096)
    return key


def ssh_connect_to_new_host(nodename, ssh_key):
    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(IgnoreMissingKeyPolicy())
    user = 'root'
    port = 22
    logger.debug("Connect to \"{nodename}\" as \"{user}\" on port {port}.".
                 format(
                     nodename=nodename, user=user, port=port))
    try:
        client.connect(nodename,
                       port=port,
                       username=user,
                       timeout=SSH_TIMEOUT,
                       pkey=ssh_key,
                       allow_agent=False,
                       look_for_keys=False)
    except paramiko.SSHException:
        raise
    except socket.timeout:
        raise
    except socket.error:
        return None
    return client


def delete_ssh_key(directory):
    private_key_file = os.path.join(directory, 'id_rsa')
    public_key_file = private_key_file + '.pub'
    for key in (private_key_file, public_key_file):
        try:
            os.remove(key)
        except OSError:
            raise


def read_ssh_key(directory, name='id_rsa'):
    private_key_file = os.path.join(directory, name)
    if not os.path.exists(private_key_file):
        return None
    ssh_key = paramiko.RSAKey.from_private_key_file(filename=private_key_file,
                                                    password=None)
    return ssh_key


def generate_host_keys(salt_client, nodename, directory, saltenv):
    key = generate_ssh_key()
    def _write(name, key):
        path = os.path.join(directory, nodename, name)
        logger.debug("Path: {}".format(path))
        result = salt_client.wheel(
            fun='file_roots.write',
            kwarg={
                'saltenv': saltenv,
                'path': path,
                'data': key
            })
        return result

    logger.debug("Writing public key.")
    result_pub = _write(
        'ssh_host_rsa_key.pub',
        '{name} {key} {comment}'.format(
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


def host_keys_exist(salt_client, nodename, directory, saltenv):
    logger.debug("Looking for host keys in \"{}\", saltenv \"{}\".".
                 format(directory, saltenv))
    result = salt_client.wheel(
        fun='file_roots.find',
        kwarg={
            'saltenv': saltenv,
            'path': os.path.join(directory, nodename, 'ssh_host_rsa_key')
        })
    exist = result['data']['return'] != []
    if exist:
        logger.debug("Found keys.")
    else:
        logger.debug("No keys found.")
    return exist


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


def load_salt_keys(nodename, directory):
    key_pub = os.path.join(directory, '{}.pub'.format(nodename))
    key_pem = os.path.join(directory, '{}.pem'.format(nodename))
    for key in key_pub, key_pem:
        if not os.path.exists(key):
            return None
    return({'pub': key_pub, 'pem': key_pem})


def generate_salt_keys(salt_client, nodename, directory):
    result = salt_client.wheel(
        fun='key.gen_accept',
        kwarg={
            'id_': nodename,
            'force': True,
            'keysize': SALT_KEYSIZE
        })

    if not result['data']['success']:
        logger.critical("Salt key generation failed.")
        sys.exit(1)

    pub = result['data']['return']['pub']
    priv = result['data']['return']['priv']

    key_pub = os.path.join(directory, '{}.pub'.format(nodename))
    key_pem = os.path.join(directory, '{}.pem'.format(nodename))

    with open(key_pub, 'w') as pubfile:
        pubfile.write(pub)

    with open(key_pem, 'w') as privfile:
        privfile.write(priv)

    return({'pub': key_pub, 'pem': key_pem})


def copy_salt_keys_to_minion(ssh_connection, keys):
    targetdir = "/etc/salt/pki/minion"
    sftp = ssh_connection.open_sftp()

    ssh_connection.exec_command(
        'mkdir --mode 700 --parents {}'.format(targetdir))

    for source, target in {
            keys['pem']: '{}/minion.pem'.format(targetdir),
            keys['pub']: '{}/minion.pub'.format(targetdir)}.items():

        logger.debug("Copying \"{source}\" to \"{target}\" on remote host "
                     "...".format(source=source, target=target))
        ssh_connection.exec_command('rm -f {}'.format(target))
        # we need to wait a bit between deleting and recreating, otherwise
        # copying might be done before deletion
        time.sleep(0.5)
        # confirm makes the transfer fail
        sftp.put(source, target)
    sftp.close()


def start_minion(ssh_connection):
    ssh_connection.exec_command('systemctl restart salt-minion')


def get_authorized_key_line(key, comment):
    return "{name} {key} {comment}".format(
        name=key.get_name(),
        key=key.get_base64(),
        comment=comment)


def start_update_environment(nodename, salt_client, pillar):
    # we need to update (a.k.a. run highstate on):
    # - DNS servers
    # - DHCP servers
    servers = set()

    for domain, dominfo in pillar['domain'].items():
        nameservers = dominfo['applications']['dns']['zoneinfo']['nameservers']
        for nameserver in nameservers:
            fqdn = nameserver['name'] + '.' + domain
            servers.add(fqdn)

    for network, netinfo in pillar['network'].items():
        dhcpservers = netinfo['applications']['dhcp']['servers']
        for dhcpserver in dhcpservers:
            fqdn = dhcpserver['name'] + '.' + netinfo['domain']
            servers.add(fqdn)

    # filter ourselves out
    servers = [server for server in servers if server != nodename]

    jid = salt_client.cmd_async(
        tgt=servers,
        fun='state.highstate',
        kwarg={'queue': True},
        expr_form='list')
    logger.debug("Started jid {}.".format(jid))
    return jid


def wait_for_environment_update(salt_client, jid):
    logger.debug("Waiting for jid {} ...".format(jid))
    results = salt_client.get_cli_returns(jid)
    fail = False
    for minion, result in results['data'].items():
        for state, output in result.items():
            if not output['result']:
                logger.critical("State \"{0}\" on minion \"{1}\" failed.".
                                format(output['name'], minion))
                fail = True
    if fail:
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
    return False


def salt_test_connection(salt_client, nodename):
    result = salt_client.cmd(
        tgt=nodename,
        fun='test.ping',
        timeout=30)
    try:
        return result[nodename]
    except KeyError:
        return False


def salt_trigger_highstate(salt_client, nodename):
    result = salt_client.cmd(
        tgt=nodename,
        fun='state.highstate',
        timeout=5*60)
    try:
        result = result[nodename]
    except (KeyError, ValueError, TypeError):
        logger.critical("Highstate failed: " + str(result))
        sys.exit(1)
    failed_states = list()
    all_ok = True
    for state in result.values():
        if not state['result']:
            all_ok = False
            failed_states.append(state)
    return (all_ok, failed_states)


def main(argv):
    args = parse_args(argv)
    nodename = args.nodename
    if args.debug:
        console_level = logging.DEBUG
    else:
        console_level = logging.INFO

    setup_logger(console_level)

    salt_client = bootstrapper.salt.RemoteClient(
        url=args.salt_url,
        user=args.salt_user,
        password=args.salt_password)
    if not salt_client.connect():
        logger.critical("Salt connection failed.")
        sys.exit(1)

    pillar = get_pillar(salt_client, nodename)

    if not pillar:
        logger.critical("No pillar data found for node \"{}\".".format(nodename))
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

    if not (args.no_cobbler or args.no_install):
        cobbler_server = get_cobbler_server(pillar, primary_interface)
        try:
            cobbler_systems = cobbler_get_systems(salt_client, cobbler_server)
        except RemoteCmdError as e:
            logger.critical("Could not get cobbler systems: " + e.stderr)
        if nodename in cobbler_systems and not args.overwrite_cobbler:
            logger.critical("A system with the same name already exists on the "
                            "cobbler server. Use --overwrite-cobbler to "
                            "overwrite.")
            sys.exit(1)

        logger.info("Setting up cobbler ...")
        try:
            setup_cobbler(salt_client, cobbler_server, nodename, pillar,
                          primary_interface, ssh_key)
        except RemoteCmdError as e:
            logger.critical("Could not setup cobbler: " + e.stderr)
            sys.exit(1)

    if not args.no_prepare_env:
        logger.info("Preparing environment for new node ...")
        env_jid = start_update_environment(
            nodename, salt_client, pillar)

    connection = None
    if not args.no_install:
        connection = bootstrapper.creators.libvirt.LibvirtConnection(
            uri='qemu+ssh://root@{hypervisor}/system?keyfile={keyfile}'.format(
                hypervisor=pillar['machine']['hypervisor'],
                keyfile=args.hypervisor_keyfile))
        creator = bootstrapper.creators.libvirt.LibvirtCreator(
            connection=connection)
        creator.connect()

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
        ok = False
        while i < INSTALLATION_TIMEOUT:
            i += 1
            if not creator.running(nodename):
                ok = True
                break
            time.sleep(1)
        if not ok:
            logger.critical("Installation timed out.")

        logger.info("Adjusting memory ...")
        creator.set_memory(nodename, pillar['machine']['memory']*1024)

        logger.info("Disabling network boot ...")
        creator.disable_pxe_boot(nodename)

    if not args.no_prepare_env:
        logger.info("Waiting for environment preparation to finish ...")
        wait_for_environment_update(salt_client, env_jid)

    if not args.no_ensure_state:
        if connection is None:
            connection = bootstrapper.creators.libvirt.LibvirtConnection(
                uri='qemu+ssh://root@10.1.1.156/system'
                    '?keyfile=/home/hannes/.ssh/virt_rsa')
            creator = bootstrapper.creators.libvirt.LibvirtCreator(
                connection=connection)
            creator.connect()
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

            logger.info("Waiting 5 seconds for SSH server startup on node ...")
            time.sleep(5)

    if not args.no_ssh:
        logger.info("Trying to connect via SSH ...")
        tries = 0
        connection = None
        while connection is None and tries <= 3:
            try:
                connection = ssh_connect_to_new_host(nodename, ssh_key)
            except paramiko.SSHException as e:
                logger.critical("SSH connection failed: {}".format(e.message))
                sys.exit(1)
            except socket.timeout:
                logger.critical("SSH connection timed out.")
                sys.exit(1)
            tries += 1


        if not args.no_salt_keygen:
            logger.info("Generating new salt keys ...")
            keys = generate_salt_keys(
                salt_client, nodename, directory=temp_keydir)
        else:
            logger.info("Loading salt keys from disk ...")
            keys = load_salt_keys(nodename, directory=temp_keydir)
            if keys is None:
                logger.critical("Salt keys not found in \"{}\"".format(
                    temp_keydir))
                sys.exit(1)

        logger.info("Copying salt keys to minion ...")
        copy_salt_keys_to_minion(connection, keys)

        # some grace time before starting the minion, or else it might generate
        # its own keys
        time.sleep(1)

        logger.info("Starting salt minion ...")
        start_minion(connection)


    host_key_dir = args.host_key_dir
    logger.debug("SSH host key directory: \"{}\".".format(host_key_dir))
    if args.regen_host_keys or not host_keys_exist(salt_client, nodename,
                                                   host_key_dir,
                                                   args.salt_env):
        logger.info("Generating SSH host keys ...")
        if not generate_host_keys(salt_client, nodename, host_key_dir,
                                  args.salt_env):
            logger.critical("Host key generation failed.")
            sys.exit(1)
    else:
        logger.info("SSH host keys already exist, not regenerating.")

    if not args.no_salt_run:
        # give salt some time to connect
        time.sleep(5)
        logger.info("Testing minion connection ...")
        if not salt_test_connection(salt_client, nodename):
            logger.critical("Minion did not show up.")
            sys.exit(1)

        logger.info("Triggering highstate on minion ...")
        (all_ok, failed_states) = salt_trigger_highstate(salt_client, nodename)
        if not all_ok:
            messages = []
            for state in failed_states:
                if state.get('name'):
                    messages.append('- {name}: {comment}'.format(
                        name=state['name'],
                        comment=state['comment']))
            logger.critical("Highstate failed. Failed states ({count}):\n"
                            "{states}".format(
                                count=len(messages),
                                states='\n'.join(messages)))
            sys.exit(1)

    if not (args.no_finalize or args.no_ssh):
        logger.info("Cleaning authorized key file on new node ...")
        try:
            connection.exec_command("> /root/.ssh/authorized_keys")
        except paramiko.SSHException as e:
            logger.critical("Key cleanup failed: {}".format(e.message))
            sys.exit(1)

        logger.info("Removing ephemeral SSH key ...")
        try:
            delete_ssh_key(temp_keydir)
        except OSError as e:
            logger.critical("Removing SSH key failed: {}".format(e.message))

        connection.close()

    logger.info("Finished successfully!")
