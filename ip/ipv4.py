from . import *

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

