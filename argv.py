from config import *

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
    parser.add_argument('--json', action='store_true', help='Print data as JSON')

    argv = parser.parse_args()

    return argv
