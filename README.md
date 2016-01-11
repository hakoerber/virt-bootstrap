# virt-bootstrap

Script to bootstrap a new host on a libvirt hypervisor using cobbler.

Communiaction with the cobbler server and the hypervisor is done through salt.

The parameters for the new host are read from the salt pillar.

## Stages:

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

## Generic components:

- *installer*: cobbler
- *creators*: libvirt
- *configurators*: salt

## Options

### Generic options:

| Option               | Description                                                                      |
| -------------------- | -------------------------------------------------------------------------------- |
| `--debug`            | show debugging output                                                            |
| `--no-install-server`| skip configuring the install server                                              |
| `--no-create`        | assume the machine is already installed                                          |
| `--no-ensure-state`  | assume the node is already powered on                                            |
| `--no-ssh`           | do not SSH into the machine,                                                     |
| `--no-prepare-env`   | do not update other services (DNS, DHCP)                                         |
| `--no-configure`     | do not trigger a highstate run on the new node                                   |
| `--no-finalize`      | do not clean up ephemeral SSH keys after successful install                      |
| `--regen-host-keys`  | regenerate SSH host keys                                                         |

### Libvirt options:

| Option               | Description                                                                      |
| -------------------- | -------------------------------------------------------------------------------- |
| `--libvirt-keyfile`  | path to the SSH keyfile to use when connecting to the hypervisor                 |

### Cobbler options:

| Option               | Description                                                                       |
| -------------------- | --------------------------------------------------------------------------------- |
| `--overwrite-cobbler`| when a node profile for cobbler already exist, overwrite it instead of failing    |

### Salt options:

| Option               | Description                                                                       |
| -------------------- | --------------------------------------------------------------------------------- |
| `--salt-env`         | name of the salt environment to use, defaults to `base`                           |
| `--host-key-dir`     | path to the directory that contains the host keys on the salt master, relative to |
|                      | the file root, defaults to `files/ssh/hostkeys`                                   |
