#!/usr/bin/env python2

import sys
import argparse
import time
import logging

import salt
import salt.runner

# The minimum amount of memory in MiB that is required for installation.
INSTALLATION_MEMORY = 1024

logger = logging.getLogger(__file__)
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter(fmt="[%(asctime)s] [%(levelname)-8s] %(message)s",
                              datefmt="%H:%M:%S")
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


def parse_args():
    parser = argparse.ArgumentParser(description='Boostrap a new machine')
    parser.add_argument('nodename')
    parser.add_argument("--debug", action='store_true')
    return parser.parse_args(sys.argv[1:])


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


def setup_cobbler(salt_client, nodename, pillar, primary_interface):
    args_cobbler = ['cobbler', 'system', 'add',
                    '--name', nodename,
                    '--profile', pillar['machine']['profile'],
                    '--hostname', nodename,
                    '--clobber',
                    '--interface', primary_interface['identifier'],
                    '--mac-address', primary_interface['mac']]
    logger.debug("cmd: " + " ".join(args_cobbler))


    provisioning_server = pillar['network'][primary_interface['network']]\
        ['applications']['provisioning']['server']['name']

    result = salt_client.cmd(provisioning_server,
                             'cmd.run',
                             [" ".join(args_cobbler)])
    logger.debug("out: " + result[provisioning_server])


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
                                'cmd.run',
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
        logger.debug("cmd: " + " ".join(args_virt_adjust_mem))
        result = salt_client.cmd(pillar['machine']['hypervisor'],
                                 'cmd.run',
                                 [" ".join(args_virt_adjust_mem)])
        logger.debug("out: " + result[pillar['machine']['hypervisor']])
    else:
        logger.debug("No memory adjustment necessary.")


def wait_for_installation_to_finish(salt_client, jid, pillar):
    result = salt_client.get_cli_returns(jid, pillar['machine']['hypervisor'])
    logger.debug(result.next())


def main():
    args = parse_args()
    nodename = args.nodename
    if args.debug:
        console_handler.setLevel(logging.DEBUG)
    pillar = get_pillar(nodename)

    primary_interface = get_primary_interface(pillar)

    salt_client = salt.client.LocalClient()

    logger.info("Setting up cobbler ...")
    setup_cobbler(salt_client, nodename, pillar, primary_interface)
    logger.info("Done.")

    logger.info("Starting installation ...")
    jid = start_installation(salt_client, nodename, pillar, primary_interface)
    logger.info("Done.")

    logger.info("Adjusting memory ...")
    adjust_memory(salt_client, nodename, pillar)
    logger.info("Done.")

    logger.info("Waiting for installation to finish ...")
    wait_for_installation_to_finish(salt_client, jid, pillar)
    logger.info("Done.")

if __name__ == '__main__':
    main()
