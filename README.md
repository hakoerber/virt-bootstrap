# virt-bootstrap

Script to bootstrap a new host on a libvirt hypervisor using cobbler.

Communiaction with the cobbler server and the hypervisor is done through salt.

The parameters for the new host are read from the salt pillar.

## Stages

1. Generate temporary SSH keys or load them from disk
2. Configure install server
3. Create the new node
4. Update the environment for the new node
5. Start the node
6. Connect via SSH
7. Generate and copy new configuration management keys for the node
9. Generate and copy new SSH host keys for the node
10. Trigger configuration management run
11. Clean up temporary keys

## Generic components

### Database

This component must provide information about the new node, such as networking
and hardware.

*Available backends:*

- salt (pillar)

### Installer

The install server that provides the PXE environment for installation.

*Available backends:*

- cobbler

### Creator

This component is what actually creates the new node.

*Available backends:*

- libvirt

### Orchestrator

This is mean to prepare other nodes in the network for the new node, such as
updating DNS records and DHCP reservations.

*Available backends:*

- salt

### Configurator

This component is supposed to configure the new node to the desired state

*Available backends:*

- salt

## Options

| Option               | Description                                                                       |
| -------------------- | --------------------------------------------------------------------------------- |
| `--debug`            | show debugging output                                                             |
| `--no-install-server`| skip configuring the install server                                               |
| `--no-create`        | assume the machine is already installed                                           |
| `--no-ensure-state`  | assume the node is already powered on                                             |
| `--no-ssh`           | do not SSH into the machine,                                                      |
| `--no-prepare-env`   | do not update other services (DNS, DHCP)                                          |
| `--no-configure`     | do not trigger a highstate run on the new node                                    |
| `--no-finalize`      | do not clean up ephemeral SSH keys after successful install                       |
| `--regen-host-keys`  | regenerate SSH host keys                                                          |

**Note**: ``--debug`` output might contain sensitive information, such as
authentication passwords or private SSH keys.
