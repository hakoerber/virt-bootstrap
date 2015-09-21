#!/usr/bin/env python2

import sys
import argparse
import time
import logging
import os.path
import subprocess
import shutil
import socket

import salt
import salt.config
import salt.runner
import paramiko
import paramiko.client


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

# Where to store SSH host keys. They will be stored in a subdirectory named
# after the host they belong to
DEFAULT_HOST_KEY_DIR = '/srv/salt/{environment}/files/ssh/hostkeys/'

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


def parse_args():
    parser = argparse.ArgumentParser(description='Boostrap a new machine')
    parser.add_argument('nodename')
    parser.add_argument("--debug", action='store_true')
    parser.add_argument("--no-cobbler", action='store_true')
    parser.add_argument("--overwrite-cobbler", action='store_true')
    parser.add_argument("--no-ssh", action='store_true')
    parser.add_argument("--no-install", action='store_true')
    parser.add_argument("--no-salt-keygen", action='store_true')
    parser.add_argument("--no-prepare-env", action='store_true')
    parser.add_argument("--no-salt-run", action='store_true')
    parser.add_argument("--no-finalize", action='store_true')
    parser.add_argument("--regen-host-keys", action='store_true')
    parser.add_argument("--salt-env", action='store', default=DEFAULT_SALT_ENV,
                        metavar='ENV')
    parser.add_argument("--host-key-dir", action='store',
                        default=DEFAULT_HOST_KEY_DIR, metavar='DIR')
    return parser.parse_args(sys.argv[1:])


def execute_with_salt(salt_client, target, command, func='cmd'):
    logger.debug("cmd: " + " ".join(command))
    result = getattr(salt_client, func)(
        target,
        'cmd.run_all',
        [" ".join(command)])
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


def get_pillar(nodename):
    opts = salt.config.master_config('/etc/salt/master')
    runner = salt.runner.RunnerClient(opts)
    pillar = _suppress_output(runner.cmd, 'pillar.show_pillar', [nodename])
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
                       domain['applications']['dns']['zoneinfo']['nameservers']]

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


def libvirt_get_domains(salt_client, hypervisor, only_active=False):
    args_virt_domains = ['virsh', 'list', '--name']
    if only_active:
        args_virt_domains.append('--state-running')
    else:
        args_virt_domains.append('--all')

    try:
        result = execute_with_salt(salt_client,
                                   target=hypervisor,
                                   command=args_virt_domains)
    except RemoteCmdError:
        raise
    return [domain.strip() for domain in result['stdout'].splitlines()]


def libvirt_start_domain(salt_client, hypervisor, domain):
    args_virt_start_domain = ['virsh', 'start', domain]
    try:
        execute_with_salt(salt_client,
                          target=hypervisor,
                          command=args_virt_start_domain)
    except RemoteCmdError:
        raise


def start_installation(salt_client, nodename, pillar, primary_interface):
    mem = pillar['machine']['memory']
    if mem < INSTALLATION_MEMORY:
        logger.debug("Increasing memory from {mem}MiB to {new_mem}MiB for "
                     "installation, reducing later.".format(
                         mem=mem, new_mem=INSTALLATION_MEMORY))
        mem = INSTALLATION_MEMORY

    args_virt_install = [
        'virt-install',
        '--connect', 'qemu:///system',
        '--name', nodename,
        '--memory', str(mem),
        '--vcpus', str(pillar['machine']['vcpus']),
        '--cpu', 'none', # uses hypervisor default
        '--pxe',
        '--arch', 'x86_64',
        '--sound', 'none',
        '--os-variant', pillar['machine']['os'],
        '--disk', 'pool=centos,size={size},bus=virtio,discard=unmap'.format(
            size=pillar['machine']['disk']['size']),
        '--network', 'network={network},model=virtio,mac={mac}'.format(
            network=pillar['machine']['network'],
            mac=primary_interface['mac']),
        '--graphics', 'spice',
        '--wait', '-1', # wait an hour, a negative value would mean wait forever
        '--noreboot',
        '--noautoconsole']

    logger.debug("cmd: " + " ".join(args_virt_install))
    jid = salt_client.cmd_async(pillar['machine']['hypervisor'],
                                'cmd.run_all',
                                [" ".join(args_virt_install)])
    logger.debug("Started jid {}.".format(jid))
    return jid


def adjust_memory(salt_client, nodename, pillar):
    mem = pillar['machine']['memory']
    if mem < INSTALLATION_MEMORY:
        logger.debug("Adjusting memory to {mem}MiB".format(mem=mem))
        args_virt_adjust_mem = [
            'virsh',
            '--connect', 'qemu:///system',
            'setmaxmem',
            nodename, str(mem) + 'M',
            '--config']
        logger.debug("Sleeping 5 seconds to wait for machine startup.")
        time.sleep(5)
        try:
            execute_with_salt(salt_client,
                              target=pillar['machine']['hypervisor'],
                              command=args_virt_adjust_mem)
        except RemoteCmdError:
            raise
    else:
        logger.debug("No memory adjustment necessary.")


def wait_for_installation_to_finish(salt_client, jid, pillar):
    logger.debug("Waiting for jid {} ...".format(jid))
    target = pillar['machine']['hypervisor']
    results = salt_client.get_cli_returns(
        jid, [pillar['machine']['hypervisor']], timeout=INSTALLATION_TIMEOUT)
    for result in results:
        if target in result.keys():
            result = result[target]['ret']
            if result['retcode'] != 0:
                logger.critical("Installation failed: " + result['stderr'])
                sys.exit(1)
            else:
                return


def generate_ssh_key():
    key = paramiko.rsakey.RSAKey.generate(bits=4096)
    return key


def ssh_connect_to_new_host(nodename, ssh_key):
    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(IgnoreMissingKeyPolicy())
    try:
        client.connect(nodename,
                       port=22,
                       username='root',
                       timeout=SSH_TIMEOUT,
                       pkey=ssh_key,
                       allow_agent=False,
                       look_for_keys=False)
    except paramiko.SSHException:
        raise
    except socket.timeout:
        raise
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


def generate_host_keys(nodename, directory):
    key = generate_ssh_key()
    target = os.path.join(directory, nodename)
    save_ssh_key(key, target, name='ssh_host_rsa_key')


def host_keys_exist(nodename, directory):
    target = os.path.join(directory, nodename)
    logger.debug("Looking for host keys in \"{}\".".format(target))
    return (read_ssh_key(target, name='ssh_host_rsa_key') is not None)


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


def master_accept_minion_keys(nodename, keys):
    master_opts = salt.config.client_config('/etc/salt/master')
    minion_keys = os.path.join(master_opts['pki_dir'], 'minions')
    minion_key_path = os.path.join(minion_keys, nodename)

    shutil.copyfile(keys['pub'], minion_key_path)


def generate_salt_keys(nodename, directory):
    master_opts = salt.config.client_config('/etc/salt/master')
    minion_keys = os.path.join(master_opts['pki_dir'], 'minions')
    minion_key_path = os.path.join(minion_keys, nodename)

    if os.path.exists(minion_key_path):
        logger.error("Salt already has an accepted key for that host.")
        sys.exit(1)

    args = ["salt-key",
            "--gen-keys", nodename,
            "--gen-keys-dir", directory]
    process = subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.wait()

    key_pub = os.path.join(directory, '{}.pub'.format(nodename))
    key_pem = os.path.join(directory, '{}.pem'.format(nodename))

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


def start_update_environment(salt_client, pillar):
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

    servers = list(servers)

    jid = salt_client.cmd_async(
        tgt=servers,
        fun='state.highstate',
        kwarg={'queue': True},
        expr_form='list')
    logger.debug("Started jid {}.".format(jid))
    return (jid, servers)


def wait_for_environment_update(salt_client, jid, servers):
    logger.debug("Waiting for jid {} ...".format(jid))
    result = salt_client.get_cli_returns(jid, servers)
    for _ in result:
        pass


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
    result = result[nodename]
    state_results = [state['result'] for state in result.values()]
    return all(state_results)


def main():
    args = parse_args()
    nodename = args.nodename
    if args.debug:
        console_level = logging.DEBUG
    else:
        console_level = logging.INFO

    setup_logger(console_level)

    pillar = get_pillar(nodename)
    if len(pillar) == 0:
        logger.critical("No pillar data found for node \"{}\".".format(nodename))
        sys.exit(1)

    primary_interface = get_primary_interface(pillar)

    temp_keydir = '/root/{}.d'.format(nodename)
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

    salt_client = salt.client.LocalClient()

    if not args.no_cobbler:
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
        (env_jid, servers) = start_update_environment(salt_client, pillar)

    if not args.no_install:
        try:
            libvirt_domains = libvirt_get_domains(
                salt_client, pillar['machine']['hypervisor'])
        except RemoteCmdError as e:
            logger.critical("Could not get domains: " + e.stderr)
            sys.exit(1)

        if nodename in libvirt_domains:
            logger.error("The domain already exists on the hypervisor. Use "
                         "--reinstall to recreate the domain.")
            sys.exit(1)

        logger.info("Starting installation ...")
        install_jid = start_installation(salt_client, nodename, pillar,
                                         primary_interface)

        logger.info("Adjusting memory ...")
        try:
            adjust_memory(salt_client, nodename, pillar)
        except RemoteCmdError as e:
            logger.critical("Could not adjust memory: " + e.stderr)
            sys.exit(1)

        logger.info("Waiting for installation to finish ...")
        wait_for_installation_to_finish(salt_client, install_jid, pillar)

        if not args.no_prepare_env:
            logger.info("Waiting for environment preparation to finish ...")
            wait_for_environment_update(salt_client, env_jid, servers)

    try:
        libvirt_active_domains = libvirt_get_domains(
            salt_client, pillar['machine']['hypervisor'], only_active=True)
    except RemoteCmdError as e:
        logger.critical("Could not get domains: " + e.stderr)
        sys.exit(1)
    if nodename in libvirt_active_domains:
        logger.info("No need to start domain, already active.")
    else:
        logger.info("Starting node ...")
        try:
            libvirt_start_domain(salt_client, pillar['machine']['hypervisor'],
                                 nodename)
        except RemoteCmdError as e:
            logger.critical("Could not start node: " + e.stderr)
            sys.exit(1)

        logger.info("Waiting for node startup ...")
        if not wait_for_ping(target=nodename, timeout=STARTUP_TIMEOUT,
                            spacing=PING_SPACING):
            logger.critical("Host not responding to ping.")
            sys.exit(1)

        logger.info("Waiting 5 seconds for SSH server startup on node ...")
        time.sleep(5)

    if not args.no_ssh:
        logger.info("Trying to connect via SSH ...")
        try:
            connection = ssh_connect_to_new_host(nodename, ssh_key)
        except paramiko.SSHException as e:
            logger.critical("SSH connection failed: {}".format(e.message))
            sys.exit(1)
        except socket.timeout:
            logger.critical("SSH connection timed out.")
            sys.exit(1)

        if not args.no_salt_keygen:
            logger.info("Generating new salt keys ...")
            keys = generate_salt_keys(nodename, directory=temp_keydir)
        else:
            logger.info("Loading salt keys from disk ...")
            keys = load_salt_keys(nodename, directory=temp_keydir)
            if keys is None:
                logger.critical("Salt keys not found in \"{}\"".format(
                    temp_keydir))
                sys.exit(1)

        master_accept_minion_keys(nodename, keys)

        logger.info("Copying salt keys to minion ...")
        copy_salt_keys_to_minion(connection, keys)

        # some grace time before starting the minion, or else it might generate
        # its own keys
        time.sleep(1)

        logger.info("Starting salt minion ...")
        start_minion(connection)


    host_key_dir = args.host_key_dir.format(environment=args.salt_env)
    logger.debug("SSH host key directory: \"{}\".".format(host_key_dir))
    if ((not host_keys_exist(nodename, host_key_dir)) or
            args.regen_host_keys):
        logger.info("Generating SSH host keys ...")
        generate_host_keys(nodename, host_key_dir)
    else:
        logger.info("SSH host keys already exist, not regenerating.")

    # give salt some time to connect
    time.sleep(5)

    if not args.no_salt_run:
        logger.info("Testing minion connection ...")
        if not salt_test_connection(salt_client, nodename):
            logger.critical("Minion did not show up.")
            sys.exit(1)

        logger.info("Triggering highstate on minion ...")
        if not salt_trigger_highstate(salt_client, nodename):
            logger.critical("Highstate failed.")
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


if __name__ == '__main__':
    main()
