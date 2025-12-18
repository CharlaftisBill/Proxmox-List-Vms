import re
import sys
import socket
import struct
import urllib3
import requests
import argparse

from tabulate import tabulate
from proxmoxer import ProxmoxAPI
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

# Suppress insecure request warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global variable to hold the bind IP
BIND_IP = None

# --- Custom Adapter to bind Source IP ---
class SourceAddressAdapter(HTTPAdapter):
    def __init__(self, source_address, **kwargs):
        self.source_address = source_address
        super(SourceAddressAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            source_address=(self.source_address, 0)
        )

# --- Monkey Patch requests.Session ---
# This ensures that even inside the ProxmoxAPI library, 
# the session gets our custom adapter automatically.
_original_session_init = requests.Session.__init__

def patched_session_init(self, *args, **kwargs):
    _original_session_init(self, *args, **kwargs)
    if BIND_IP:
        adapter = SourceAddressAdapter(BIND_IP)
        self.mount('http://', adapter)
        self.mount('https://', adapter)

requests.Session.__init__ = patched_session_init

def get_ip_from_interface(ifname):
    """
    Linux specific: Returns the IP address string of a given network interface name.
    """
    try:
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
    except ImportError:
        print("Error: Interface binding only works on Linux/Unix systems.")
        sys.exit(1)
    except IOError:
        print(f"Error: Interface '{ifname}' not found or has no IP.")
        sys.exit(1)

def get_vm_ip(prox, node, vmid):
    try:
        interfaces = prox.nodes(node).qemu(vmid).agent('network-get-interfaces').get()
        for iface in interfaces.get('result', []):
            if iface.get('name') == 'lo':
                continue
            for ip_info in iface.get('ip-addresses', []):
                if ip_info['ip-address-type'] == 'ipv4':
                    return ip_info['ip-address']
    except Exception:
        return "N/A"
    return "N/A"

def parse_size(size_str):
    if not size_str: return 0.0
    match = re.search(r'size=([\d\.]+)([TGMK])?', size_str)
    if not match: return 0.0
    value = float(match.group(1))
    unit = match.group(2)
    if unit == 'T': return value * 1024
    if unit == 'G': return value
    if unit == 'M': return value / 1024
    if unit == 'K': return value / 1024 / 1024
    return value

def get_total_storage(config):
    total_gib = 0.0
    disk_prefixes = ('scsi', 'ide', 'sata', 'virtio')
    for key, value in config.items():
        if any(key.startswith(p) and key[-1].isdigit() for p in disk_prefixes):
            if 'media=cdrom' in value: continue
            total_gib += parse_size(value)
    return round(total_gib, 1)

def main():
    global BIND_IP
    parser = argparse.ArgumentParser(description="List Proxmox VMs per node.")
    parser.add_argument("host", help="Proxmox host IP or FQDN")
    parser.add_argument("user", help="User (e.g., root@pam)")
    parser.add_argument("--password", help="Password")
    parser.add_argument("--token_name", help="API Token Name")
    parser.add_argument("--token_value", help="API Token Value")
    parser.add_argument("--verify_ssl", action="store_true", help="Verify SSL Certificate")
    parser.add_argument("--interface", help="Network Interface to use (e.g., tun0, eth1)")

    args = parser.parse_args()

    # Set Global Bind IP if interface provided
    if args.interface:
        print(f"Attempting to bind to interface: {args.interface}")
        BIND_IP = get_ip_from_interface(args.interface)
        print(f"Interface {args.interface} resolved to IP: {BIND_IP}")

    # Authentication Logic
    try:
        if args.token_name and args.token_value:
            prox = ProxmoxAPI(
                args.host, user=args.user, token_name=args.token_name, 
                token_value=args.token_value, verify_ssl=args.verify_ssl
            )
        elif args.password:
            # Note: We removed the 'session=' argument. 
            # The monkey patch above handles the binding now.
            prox = ProxmoxAPI(
                args.host, user=args.user, password=args.password, 
                verify_ssl=args.verify_ssl
            )
        else:
            print("Error: Credentials required.")
            return
    except Exception as e:
        print(f"Connection failed: {e}")
        return

    table_data = []
    print("Fetching Node list...")
    
    try:
        nodes = prox.nodes.get()
    except Exception as e:
        print(f"Failed to fetch nodes. Check network/VPN connection. Error: {e}")
        return

    for node in nodes:
        node_name = node['node']
        print(f"Processing node: {node_name}...")
        vms = prox.nodes(node_name).qemu.get()

        for vm in vms:
            vmid = vm['vmid']
            vm_name = vm.get('name', 'Unknown')
            status = vm.get('status', 'unknown')
            
            ip_address = "N/A"
            os_type = "Unknown"
            cores = 0
            memory_gb = 0
            storage_gb = 0

            try:
                config = prox.nodes(node_name).qemu(vmid).config.get()
                os_type = config.get('ostype', 'other')
                sockets = int(config.get('sockets', 1))
                c_cores = int(config.get('cores', 1))
                cores = sockets * c_cores
                memory_gb = round(int(config.get('memory', 0)) / 1024, 1)
                storage_gb = get_total_storage(config)

                if status == 'running':
                    if config.get('agent', '0') == '1': 
                        ip_address = get_vm_ip(prox, node_name, vmid)
                    else:
                        ip_address = "No Agent"
                else:
                    ip_address = "Stopped"

            except Exception:
                pass

            table_data.append([
                node_name, vm_name, os_type, ip_address, cores, f"{memory_gb} G", f"{storage_gb} G"
            ])

    table_data.sort(key=lambda x: (x[0], x[1]))
    headers = ["Node", "VM Name", "OS Type", "IP", "Cores", "RAM", "Storage"]
    print("\n" + tabulate(table_data, headers=headers, tablefmt="psql"))

if __name__ == "__main__":
    main()