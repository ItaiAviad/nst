#!/usr/bin/python3

from config import *

def main():
    print(argv)

    net_info = get_network_info()

    if (not argv.quiet):
        print(f'{M_INFO} Network Information:')
        print(f'{M_JSON_KEYS} {net_info}')

    lan_devices = {}
    if (argv.enumerate):
        lan_devices = enumerate_lan(net_info)
        net_info['lan_devices'] = lan_devices
    
    if (argv.arp_spoof):
        arp_spoofing(net_info)
    
    if (argv.dns_spoof):
        dns_spoofing(net_info)

    if (not argv.quiet):
        print(f'{M_INFO} Done!')

if __name__ == '__main__':
    main()
