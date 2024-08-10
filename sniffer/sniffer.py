#!/usr/bin/python3
from scapy.all import *
import datetime
import sys
import socket
# import re
# import json

class colors:
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

class Req:
    def __init__(self, src_ip, dst_ip, src_port='-1', dst_port='-1', text=''):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.text = text

    def __eq__(self, other):
        if isinstance(other, Req):
            return self.src_ip == other.src_ip and self.dst_ip == other.dst_ip
        return False
    
    def __str__(self):
        return f"{self.text}"
    
    def set_text(self, text):
        self.text = text

# Constants
PORT_DEFAULT_HTTPS = 443
PORT_DEFAULT_HTTPS_TEXT = 'https'
PORT_DEFAULT_HTTP = 80
PORT_DEFAULT_HTTP_TEXT = 'http'
PORT_DEFAULT_HTTP_TEXT_WWW = 'www_http'
DNS_SERVER_GOOGLE = '8.8.8.8'
DOMAIN_NAME_UNKNOWN = 'Unknown'

# DNS_CACHE_FILENAME = 'dns_cache.json'

# Globals
dns_cache = {'127.0.0.0': 'localhost', '127.0.0.1': 'localhost'}

prev_req = Req('', '' ,'' ,'') # Previous Request

def get_local_ip():
    '''Get local machine ip address'''

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((DNS_SERVER_GOOGLE, PORT_DEFAULT_HTTP))
    ip = s.getsockname()[0]
    s.close()

    return ip

def port_is_http(port):
    return port == PORT_DEFAULT_HTTP or port == PORT_DEFAULT_HTTP_TEXT or port == PORT_DEFAULT_HTTP_TEXT_WWW

def port_is_https(port):
    return port == PORT_DEFAULT_HTTPS or port == PORT_DEFAULT_HTTPS_TEXT

def get_domain_name(packet) -> str:
    '''Get HTTP/S Request domain name'''
    global dns_cache

    domain_name = DOMAIN_NAME_UNKNOWN

    if (not is_http_request(packet)) or (not is_https_request(packet)) or (not packet.haslayer(Raw)):
        return DOMAIN_NAME_UNKNOWN

    load = packet[Raw].load.decode('utf-8', errors='ignore')

    server_ip = packet[IP].src
    if (port_is_http(packet[TCP].dport) or port_is_https(packet[TCP].dport)):
        server_ip = packet[IP].dst
    
    is_http = is_http_request(packet)

    if (server_ip in dns_cache):
        domain_name = dns_cache[server_ip]
    elif (is_http):
        try:
            domain_name = load.split('Host: ')[1].split('\r\n')[0]
            print(f"{colors.OKBLUE}Site Name: {domain_name}{colors.ENDC}")
        except Exception as e:
            print(f"{colors.WARNING}Failed to extract site name: {str(e)}{colors.ENDC}")

    return domain_name

def get_hostname(ip_addr: str) -> str:
    '''Get hostname by ip address'''

    try:
        hostname, _, _ = socket.gethostbyaddr(ip_addr)
        return hostname
        # srch = re.search(r'(?<=\.)[\w-]+\.[\w.]+', hostname)
        # domain_name = srch.group() if srch != None else "Unknown"
        return domain_name
    except socket.herror:
        return "Unknown"
    except Exception as e:
        return "Unknown"

def get_hostnames(packet, req: Req):
    '''Get Domain/Host names of src and dst'''

    # Domain Name
    ip_local = get_local_ip()
    ip_remote = req.dst_ip if req.src_ip == ip_local else req.src_ip

    remote_domain_name, local_domain_name = get_hostname(ip_remote), get_hostname(ip_local)

    src_hostname, dst_hostname = (remote_domain_name, local_domain_name)
    if req.src_ip == ip_local:
        src_hostname, dst_hostname = (local_domain_name, remote_domain_name)

    return (src_hostname, dst_hostname)
    
def is_http_request(packet) -> bool:
    return packet.haslayer(TCP) and (port_is_http(packet[TCP].sport) or port_is_http(packet[TCP].dport))

def is_https_request(packet) -> bool:
    return packet.haslayer(TCP) and (port_is_https(packet[TCP].sport) or port_is_https(packet[TCP].dport))

def is_dns_request(packet) -> bool:
    return packet.haslayer(UDP) and packet.haslayer(DNS)
    
def process_request_dns(packet, cyber=True) -> Req:
    global dns_cache

    if DNSRR not in packet or not hasattr(packet, 'an'):
        return Req('', '')
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[UDP].sport
    dst_port = packet[UDP].dport

    ip = ''
    domain_name = ''

    an_count = 0
    for ans in packet.an:
        an_count += 1
        ip = ans.rdata  # Extract the IP address
        domain_name = ans.rrname.decode()  # Extract the domain name
        dns_cache[ip] = domain_name

    req = Req(src_ip, dst_ip, src_port, dst_port, f'{colors.BROWN}Saved {an_count} domain names. {ip} -> {domain_name}{colors.ENDC}')

    return req

def process_request_http(packet, cyber=True) -> Req:
    if not packet.haslayer(Raw):
        return Req('', '')
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport

    req = Req(src_ip, dst_ip, src_port, dst_port, f'{colors.BROWN}Domain: {get_domain_name(packet)}{colors.ENDC}')

    return req

def process_request(packet, cyber=True) -> None:
    '''Process request'''
    global prev_req
    
    if (not packet.haslayer(IP)):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    req = Req(src_ip, dst_ip)

    # If the current req == previous req
    if (req == prev_req):
        return
    prev_req = req

    req_type = ''

    if (is_dns_request(packet)):
        # DNS Request
        req = process_request_dns(packet)
        req_type = 'DNS'
    elif (is_http_request(packet) or is_https_request(packet)):
        # HTTP/S Request
        req = process_request_http(packet)
        is_https = is_https_request(packet)
        req_type = 'HTTPS' if is_https else 'HTTP'
    else:
        return

    if (req == Req('', '')):
        return

    # Request Header
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"{colors.OKGREEN}[{timestamp}] {req_type} Request{colors.ENDC}")

    # Request Text
    print(req)

    # Get Domain/Host names
    src_hostname, dst_hostname = get_hostnames(packet, req)

    # SRC and DST stats
    if (cyber):
        print(f"{colors.OKBLUE}{req.src_ip}:{req.src_port} ({src_hostname}) -> {req.dst_ip}:{req.dst_port} ({dst_hostname}){colors.ENDC}")
    
    print()

def init_sniffing():
    try:
        print(f"{colors.HEADER}[*] Starting HTTP/HTTPS Sniffer. Press Ctrl+C to stop.{colors.ENDC}")
        sniff(filter="(tcp port 80) or (tcp port 8080) or (tcp port 443) or (udp src port 53)", prn=process_request, store=0)
        # sniff(filter="(tcp port 80) or (tcp port 8080)", prn=process_request, store=0)

    except KeyboardInterrupt:
        print(f"\n{colors.FAIL}[*] Stopping HTTP/HTTPS Sniffer...{colors.ENDC}")
        sys.exit(0)

    except Exception as e:
        print(f"{colors.FAIL}[-] An error occurred: {str(e)}{colors.ENDC}")
        sys.exit(1)

def main():
    init_sniffing()

if __name__ == "__main__":
    main()
