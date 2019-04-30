from __future__ import (absolute_import, division, print_function)

import re

import requests
import urllib3
import yaml
from ansible.errors import AnsibleParserError
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable, Cacheable
from six import iteritems
from yaml.scanner import ScannerError

__metaclass__ = type

# disable InsecureRequestWarning
urllib3.disable_warnings()


DOCUMENTATION = '''
    name: proxmox
    plugin_type: inventory
    short_description: Proxmox inventory source
    version_added: "2.7"
    author:
      - Bruno Meneguello
    description:
        Inventory plugin for Proxmox
    extends_documentation_fragment:
      - inventory_cache
    requirements:
      - "Python >= 2.7"
    options:
        url:
            description: Proxmox URL
            env:
              - name: PROXMOX_URL
            ini:
              - section: proxmox
                key: url
        username:
            description: Proxmox API username
            env:
              - name: PROXMOX_USERNAME
            ini:
              - section: proxmox
                key: username
        password:
            description: Proxmox API password
            env:
              - name: PROXMOX_PASSWORD
            ini:
              - section: proxmox
                key: password
        qemu_interface:
            description: Interface to check IP 
            env:
              - name: PROXMOX_QEMU_INTERFACE
            ini:
              - section: proxmox
                key: qemu_interface
        qemu_interface_ignore:
            description: Regex of ignored interface names
            default: lo|((br-|docker|veth).*)
            env:
              - name: PROXMOX_QEMU_INTERFACE_IGNORE
            ini:
              - section: proxmox
                key: qemu_interface_ignore
        validate:
            description: TBD
            default: false
'''


class ProxmoxNodeList(list):
    def get_names(self):
        return [node['node'] for node in self if node['status'] == 'online']


class ProxmoxVM(dict):
    def get_variables(self):
        variables = {}
        for key, value in iteritems(self):
            variables['proxmox_' + key] = value
        return variables


class ProxmoxVMList(object):
    def __init__(self, data=None, pxmxver=0.0):
        self.ver = pxmxver
        self.vms = []
        for item in data or []:
            self.vms.append(ProxmoxVM(item))

    def get_names(self):
        if self.ver >= 4.0:
            return [vm['name'] for vm in self.vms if vm['template'] != 1]
        else:
            return [vm['name'] for vm in self.vms]

    def get_by_name(self, name):
        results = [vm for vm in self.vms if vm['name'] == name]
        return results[0] if len(results) > 0 else None

    def get_variables(self):
        variables = {}
        for vm in self.vms:
            variables[vm['name']] = vm.get_variables()

        return variables


class ProxmoxPoolList(list):
    def get_names(self):
        return [pool['poolid'] for pool in self]


class ProxmoxVersion(dict):
    def get_version(self):
        return float(self['version'])


class ProxmoxPool(dict):
    def get_members_name(self):
        return [member['name'] for member in self['members'] if 'template' in member and member['template'] != 1]


class ProxmoxAPI(object):
    def __init__(self, plugin):
        self.credentials = None

        if not plugin.get_option('url'):
            raise AnsibleParserError('missing mandatory variable url')
        self.url = plugin.get_option('url')

        if not plugin.get_option('username'):
            raise AnsibleParserError('missing mandatory variable username')
        self.username = plugin.get_option('username')

        if not plugin.get_option('password'):
            raise AnsibleParserError('missing mandatory variable password')
        self.password = plugin.get_option('password')

        self.validate = plugin.get_option('validate')

        # URL should end with a trailing slash
        if not self.url.endswith("/"):
            self.url = self.url + "/"

    def auth(self):
        request_path = '{0}api2/json/access/ticket'.format(self.url)

        request_params = {
            'username': self.username,
            'password': self.password,
        }

        data = requests.post(request_path, data=request_params, verify=self.validate).json()

        self.credentials = {
            'ticket': data['data']['ticket'],
            'CSRFPreventionToken': data['data']['CSRFPreventionToken'],
        }

    def get(self, url, data=None):
        request_path = '{0}{1}'.format(self.url, url)

        headers = {'Cookie': 'PVEAuthCookie={0}'.format(self.credentials['ticket'])}
        response_raw = requests.get(
            request_path,
            data=data,
            headers=headers,
            verify=self.validate
        )
        response = response_raw.json()

        return response['data']

    def nodes(self):
        return ProxmoxNodeList(self.get('api2/json/nodes'))

    def vms_by_type(self, node, type):
        return ProxmoxVMList(self.get('api2/json/nodes/{0}/{1}'.format(node, type)), self.version().get_version())

    def vm_description_by_type(self, node, vm, vm_type):
        return self.get('api2/json/nodes/{0}/{1}/{2}/config'.format(node, vm_type, vm))

    def node_qemu(self, node):
        return self.vms_by_type(node, 'qemu')

    def node_qemu_description(self, node, vm):
        return self.vm_description_by_type(node, vm, 'qemu')

    def node_qemu_ip(self, node, vm):
        try:
            return self.get('api2/json/nodes/{0}/qemu/{1}/agent/network-get-interfaces'.format(node, vm))
        except Exception:
            return {'result': []}

    def pools(self):
        return ProxmoxPoolList(self.get('api2/json/pools'))

    def pool(self, poolid):
        return ProxmoxPool(self.get('api2/json/pools/{0}'.format(poolid)))

    def version(self):
        return ProxmoxVersion(self.get('api2/json/version'))


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):

    NAME = 'proxmox'

    def __init__(self):
        super(InventoryModule, self).__init__()

    def verify_file(self, path):

        valid = False
        if super(InventoryModule, self).verify_file(path):
            if path.endswith(('proxmox.yaml', 'proxmox.yml')):
                valid = True

        return valid

    def parse(self, inventory, loader, path, cache=False):

        super(InventoryModule, self).parse(inventory, loader, path, cache=cache)

        self._read_config_data(path)

        proxmox_api = ProxmoxAPI(self)
        proxmox_api.auth()

        for node in proxmox_api.nodes().get_names():
            try:
                qemu_list = proxmox_api.node_qemu(node)
            except requests.HTTPError as error:
                # Proxmox API raises error code 595 when target node is unavailable, skip it
                if error.response.status_code == 595:
                    continue
                # on other errors
                raise AnsibleParserError("{reason}".format(reason=error), orig_exc=error)
            for host in qemu_list.get_names():
                self.inventory.add_host(host)
                variables = qemu_list.get_by_name(host).get_variables()
                for key, value in variables.items():
                    self.inventory.set_variable(host, key, value)
                vmid = variables['proxmox_vmid']
                node_ip = proxmox_api.node_qemu_ip(node, vmid)
                if not node_ip or 'error' in node_ip['result']:
                    continue  # FIXME
                for vm_interface in node_ip['result']:
                    if self.interface_matches(vm_interface):
                        for ip_address in vm_interface['ip-addresses']:
                            if ip_address['ip-address-type'] == 'ipv4':
                                self.inventory.set_variable(host, 'ansible_host', ip_address['ip-address'])
                                break
                vm_type = variables.get('proxmox_type', 'qemu')

                description = proxmox_api.vm_description_by_type(node, vmid, vm_type).get('description')

                metadata = None
                for chunk in description.split('---'):
                    try:
                        metadata = yaml.load(chunk)
                    except ScannerError:
                        pass

                if metadata:
                    if 'ansible_groups' in metadata:
                        for group_name in metadata['ansible_groups']:
                            if group_name not in self.inventory.get_groups_dict():
                                self.inventory.add_group(group_name)
                            self.inventory.add_child(group_name, host)
                    if 'ansible_vars' in metadata:
                        for name, value in metadata['ansible_vars'].items():
                            self.inventory.set_variable(host, name, value)

                # Create group 'running'
                # so you can: --limit 'running'
                if variables['proxmox_status'] == 'running':
                    if 'running' not in self.inventory.get_groups_dict():
                        self.inventory.add_group('running')
                    self.inventory.add_child('running', host)

        # pools
        for pool in proxmox_api.pools().get_names():
            if pool not in self.inventory.get_groups_dict():
                self.inventory.add_group(pool)
            for host in proxmox_api.pool(pool).get_members_name():
                self.inventory.add_child(pool, host)

        self.inventory.reconcile_inventory()

    def interface_matches(self, vm_interface):
        if self.get_option('qemu_interface'):
            return vm_interface['name'] == self.get_option('qemu_interface')
        else:
            return not re.match(self.get_option('qemu_interface_ignore'), vm_interface['name'], re.IGNORECASE)
