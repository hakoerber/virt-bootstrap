#!/usr/bin/env python2

import sys
import argparse
import time
import logging

import salt
import salt.runner

# The minimum amount of memory in MiB that is required for installation.
INSTALLATION_MEMORY = 1024

# How long to wait for the installation to finish. If it is not finished after
# this time, the script exists and leaves the installation running on the
# hypervisor
INSTALLATION_TIMEOUT = 600


class RemoteCmdError(Exception):
    def __init__(self, retcode, stderr):
        super(RemoteCmdError, self).__init__()
        self.retcode = retcode
        self.stderr = stderr


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
    parser.add_argument("--overwrite-cobbler", action='store_true')
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
    pillar = _suppress_output(runner.cmd, 'pillar.show_pillar', ['test.lab'])
    return pillar


def get_primary_interface(pillar):
    if len(pillar.get('interfaces')) == 1:
        primary_interface = pillar.get('interfaces')
    else:
        primary_interfaces = {k: v for k, v  in pillar.get('interfaces').items()
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
                  primary_interface):
    args_cobbler = ['cobbler', 'system', 'add',
                    '--name', nodename,
                    '--profile', pillar['machine']['profile'],
                    '--hostname', nodename,
                    '--clobber',
                    '--interface', primary_interface['identifier'],
                    '--mac-address', primary_interface['mac']]
    try:
        execute_with_salt(salt_client,
                          target=cobbler_server,
                          command=args_cobbler)
    except RemoteCmdError:
        raise


def libvirt_get_domains(salt_client, hypervisor):
    args_virt_domains = ['virsh', 'list', '--all', '--name']
    try:
        result = execute_with_salt(salt_client,
                                   target=hypervisor,
                                   command=args_virt_domains)
    except RemoteCmdError:
        raise
    return [domain.strip() for domain in result['stdout'].splitlines()]


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
        '--noautoconsole']

    logger.debug("cmd: " + " ".join(args_virt_install))
    jid = salt_client.cmd_async(pillar['machine']['hypervisor'],
                                'cmd.run_all',
                                [" ".join(args_virt_install)])
    return jid


def adjust_memory(salt_client, nodename, pillar):
    mem = pillar['machine']['memory']
    if mem < INSTALLATION_MEMORY:
        logger.debug("Adjusing memory to {mem}MiB".format(mem=mem))
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
    result = salt_client.get_cli_returns(
        jid, [pillar['machine']['hypervisor']], timeout=INSTALLATION_TIMEOUT)
    result = result.next()[pillar['machine']['hypervisor']]['ret']
    if result['retcode'] != 0:
        logger.critical("Installation failed: " + result['stderr'])
    logger.debug(result['stdout'])


def main():
    args = parse_args()
    nodename = args.nodename
    if args.debug:
        console_level = logging.DEBUG
    else:
        console_level = logging.INFO

    setup_logger(console_level)

    pillar = get_pillar(nodename)

    primary_interface = get_primary_interface(pillar)
    cobbler_server = get_cobbler_server(pillar, primary_interface)

    salt_client = salt.client.LocalClient()

    try:
        cobbler_systems = cobbler_get_systems(salt_client, cobbler_server)
    except RemoteCmdError as e:
        logger.critical("Could not get cobbler systems: " + e.stderr)
    if nodename in cobbler_systems and not args.overwrite_cobbler:
        logger.critical("A system with the same name already exists on the "
                        "cobbler server. Use --overwrite-cobbler to overwrite.")
        sys.exit(1)

    logger.info("Setting up cobbler ...")
    try:
        setup_cobbler(salt_client, cobbler_server, nodename, pillar,
                      primary_interface)
    except RemoteCmdError as e:
        logger.critical("Could not setup cobbler: " + e.stderr)
        sys.exit(1)

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
    jid = start_installation(salt_client, nodename, pillar, primary_interface)

    logger.info("Adjusting memory ...")
    try:
        adjust_memory(salt_client, nodename, pillar)
    except RemoteCmdError as e:
        logger.critical("Could not adjust memory: " + e.stderr)
        sys.exit(1)

    logger.info("Waiting for installation to finish ...")
    wait_for_installation_to_finish(salt_client, jid, pillar)

if __name__ == '__main__':
    main()
