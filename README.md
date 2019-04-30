# Ansible Proxmox Inventory Plugin

## About

Proxmox inventory plugin. Based on 
[original plugin](https://raw.githubusercontent.com/ansible/ansible/devel/contrib/inventory/proxmox.py) from 
Mathieu Gauthier-Lafaye and [updated plugin](https://github.com/xezpeleta/Ansible-Proxmox-inventory) by Xabi Ezpeleta
and [another updated plugin](https://github.com/RaSerge/ansible-proxmox-inventory) by RaSerge


### Requirements

installed qemu-guest-agent on Proxmox vm's

### Features

- **Removed ansible lib requirements**
- **Requests instead of urllib**
- **Qemu interfaces ip detection**: You should have [qemu-guest-agent](https://pve.proxmox.com/wiki/Qemu-guest-agent) 
    installed and activated 
- **ProxmoxVE cluster**: if your have a ProxmoxVE cluster, it will gather the whole VM list from your cluster
- **Advanced filtering**: you can filter the VM list based in their status or a custom tag included in the `Notes` field

## Instructions

Clone this repository into "inventory_plugins" dir relative to your playbook:

```sh
git clone https://github.com/bkmeneguello/ansible-proxmox-inventory.git inventory_plugins/proxmox
```

Add some configurations to your "ansible.cfg":

```
[defaults]
inventory_plugins=./inventory_plugins

[inventory]
enable_plugins = proxmox
```

Create an inventory file with "proxmox.yml" suffix:

```yaml
plugin: proxmox
url: https://pve.example.com:8006
username: root
password: password
```

Let's test it:

```sh
ansible-inventory -i inventory.proxmox.yml --list
```

If you get a list with all the VM in your Proxmox cluster, everything is ok.

you can include the dynamic inventory in your ansible commands:

```sh
# Ping: connect to all VM in Proxmox using root user
ansible -i inventory.proxmox.yml all -m ping -u root
```

#$ Added support for using the Notes field of a VM to define groups and variables:
> Any YAML document starting with "---" anywhere in Notes field will be parsed an
> if contains an "ansible_groups" entry the host will be added to these groups. If
> it conains an "ansible_variables" entry they will be added to the host vars:

For instance, you can use the following text code in a VM host notes:

```text
Lorem Ipsum ...
---
ansible_groups:
  - windows
ansible_variables:
  ansible_user: Administrator
```

So if you want to exclude Windows machines, you could do the following:

```sh
# Run a playbook in every running Linux machine in Proxmox
ansible-playbook -i inventory.proxmox.yml --limit='running,!windows' playbook-example/playbook.yml
```
