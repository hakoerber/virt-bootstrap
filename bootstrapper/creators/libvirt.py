#!/usr/bin/env python2
from __future__ import absolute_import

import xml.etree.ElementTree

import libvirt
import jinja2

import bootstrapper.creators


DOM_XML_TEMPLATE = """<domain type='kvm'>
  <name>{{ name }}</name>
  <memory unit='KiB'>{{ memory }}</memory>
  <currentMemory unit='KiB'>{{ memory }}</currentMemory>
  <vcpu placement='static'>{{ vcpus }}</vcpu>
  <os>
    <type arch='{{ arch }}'>hvm</type>
    <boot dev='network'/>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
  </features>
  <clock offset='utc'>
    <timer name='rtc' tickpolicy='catchup'/>
  </clock>
  <devices>
    {% for disk in disks %}
    <disk type='volume' device='disk'>
      <driver name='qemu' type='raw' cache='none' io='native' discard='unmap'/>
      <source pool='{{ disk.pool }}' volume='{{ name }}'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    {% endfor %}
    <controller type='virtio-serial' index='0'>
      <alias name='virtio-serial0'/>
    </controller>
    {% for interface in interfaces %}
    <interface type='network'>
      <mac address='{{ interface['mac'] }}'/>
      <source network='{{ interface['network'] }}'/>
      <model type='virtio'/>
      <driver name='vhost'/>
    </interface>
    {% endfor %}
    <input type='tablet' bus='usb'/>
    <input type='mouse' bus='ps2'/>
    <input type='keyboard' bus='ps2'/>
    <graphics type='spice' autoport='yes' listen='127.0.0.1'/>
    <video>
      <model type='qxl'/>
    </video>
    <channel type='spicevmc'>
      <target type='virtio'/>
      <alias name='channel0'/>
      <address type='virtio-serial' controller='0' bus='0' port='1'/>
    </channel>
  </devices>
</domain>"""

VOL_XML_TEMPLATE = """<volume type='block'>
  <name>{{ name }}</name>
  <capacity unit='GiB'>{{ size }}</capacity>
</volume>"""

class LibvirtCreator(bootstrapper.creators.Creator):
    def __init__(self, connection):
        super(LibvirtCreator, self).__init__(connection)
        self._conparam = connection
        self._connection = None

    def connect(self):
        self._connection = libvirt.open(self._conparam.uri)

    def domain_exists(self, domain):
        return domain in [dom.name() for
                          dom in self._connection.listAllDomains()]

    def create(self, params):
        for disk in params['disks']:
            poolname = disk['pool']
            try:
                pool = self._connection.storagePoolLookupByName(poolname)
            except libvirt.libvirtError:
                raise ValueError("Storage pool \"{}\" does no exist.".format(
                    poolname))
            if not pool.isActive() == 1:
                pool.create()

            if disk['name'] not in [vol.name() for vol in
                                    pool.listAllVolumes()]:
                # create the volume
                vol_xml = jinja2.Template(VOL_XML_TEMPLATE).render(**disk)
                pool.createXML(vol_xml)

        domain_xml = jinja2.Template(DOM_XML_TEMPLATE).render(**params)
        self._connection.defineXML(domain_xml)

    def disable_pxe_boot(self, domain):
        domain_xml = self._connection.lookupByName(domain).XMLDesc()
        domain_xml = xml.etree.ElementTree.fromstring(domain_xml)
        for bootopt in domain_xml.find('os').findall('boot'):
            if bootopt.attrib['dev'] == 'network':
                domain_xml.find('os').remove(bootopt)
        domain_xml_new = xml.etree.ElementTree.tostring(domain_xml).decode(
            'utf-8')
        self._connection.defineXML(domain_xml_new)

    def running(self, domain):
        return self._connection.lookupByName(domain).isActive() == 1

    def start(self, name):
        self._connection.lookupByName(name).create()

    def get_memory(self, name):
        return self._connection.lookupByName(name).info()[1]

    def set_memory(self, name, memory):
        if self.running(name):
            raise ValueError("Cannot change memory of running domain.")
        self._connection.lookupByName(name).setMaxMemory(memory)
        self._connection.lookupByName(name).setMemoryFlags(
            memory, flags=libvirt.VIR_DOMAIN_AFFECT_CONFIG)

    def disconnect(self):
        if self._connection is not None:
            self._connection.close()


class LibvirtConnection(bootstrapper.creators.Connection):
    def __init__(self, uri):
        super(LibvirtConnection, self).__init__()
        self.uri = uri
