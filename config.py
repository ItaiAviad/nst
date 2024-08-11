import builtins
import ipaddress
import sys
from scapy.all import Ether, ARP, srp, send, get_if_addr, conf
import argparse
import time
import os
import subprocess
import socket
import json
import requests
import re
from netfilterqueue import NetfilterQueue
from concurrent.futures import ThreadPoolExecutor, as_completed

# Messages
M_IMPORTANT = '[!]'
M_INFO = '[-]'
M_SUCCESS = '[+]'
M_ERROR = '[X]'
M_JSON = '[j]'
M_JSON_KEYS = '[jk]'
M_JSON_ENFORCED = '[J]'
M_JSONS = [M_JSON, M_JSON_KEYS, M_JSON_ENFORCED]
M_TYPES = [M_IMPORTANT, M_INFO, M_SUCCESS, M_ERROR, *M_JSONS]

# Constants
SUBNET_SIZE = 256
MAX_POOL_THREAD_WORKERS = 128

OUI_URL = 'https://standards-oui.ieee.org/oui/oui.txt'
MAC_OUT_FILE = "oui.txt"

MAX_HOSTNAME_LENGTH = 45

# Globals
from argv import *
argv = arg_parse_init()

mac_vendors = {}

from style import *
from ip import *
from arp import *