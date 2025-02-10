import requests
import pydig
from threading import Thread, Lock
from queue import Queue
from collections import defaultdict
from pathlib import Path


def resolver(queue, resolved, failed, resolved_lock, failed_lock):
    resolver = pydig.Resolver(nameservers=['1.1.1.1', '8.8.8.8', '208.67.220.220', '208.67.222.222'])
    while True:
        item = queue.get()
        try:
            socks_addr = resolver.query(item, 'A')
        except Exception as e:
            socks_addr = []
        if len(socks_addr) > 0 and socks_addr != ['']:
            with resolved_lock:
                resolved[item] = socks_addr[0]
        else:
            with failed_lock:
                if item in failed:
                    count = failed[item]
                    if count < 3:
                        failed[item] = count + 1
                        queue.put(item)
                else:
                    failed[item] = 1
                    queue.put(item)
        queue.task_done()

COUNTRY_TO_CONTINENT = {
    'africa': [
        'dz', 'ao', 'bj', 'bw', 'bf', 'bi', 'cv', 'cm', 'cf', 'td', 'km', 'cd', 'cg', 'dj', 'eg', 'gq', 'er', 'sz', 'et', 'ga', 'gm', 'gh', 'gn', 'gw', 'ci', 'ke', 'ls', 'lr', 'ly', 'mg', 'mw', 'ml', 'mr', 'mu', 'ma', 'mz', 'na', 'ne', 'ng', 'rw', 'st', 'sn', 'sc', 'sl', 'so', 'za', 'ss', 'sd', 'tz', 'tg', 'tn', 'ug', 'zm', 'zw'
    ],
    'antarctica': [
        'aq'
    ],
    'asia': [
        'af', 'am', 'az', 'bh', 'bd', 'bt', 'bn', 'kh', 'cn', 'cy', 'ge', 'in', 'id', 'ir', 'iq', 'il', 'jp', 'jo', 'kz', 'kw', 'kg', 'la', 'lb', 'my', 'mv', 'mn', 'mm', 'np', 'kp', 'om', 'pk', 'ps', 'ph', 'qa', 'sa', 'sg', 'kr', 'lk', 'sy', 'tw', 'tj', 'th', 'tr', 'tm', 'ae', 'uz', 'vn', 'ye'
    ],
    'europe': [
        'al', 'ad', 'at', 'by', 'be', 'ba', 'bg', 'hr', 'cz', 'dk', 'ee', 'fi', 'fr', 'de', 'gr', 'hu', 'is', 'ie', 'it', 'xk', 'lv', 'li', 'lt', 'lu', 'mt', 'md', 'mc', 'me', 'nl', 'mk', 'no', 'pl', 'pt', 'ro', 'ru', 'sm', 'rs', 'sk', 'si', 'es', 'se', 'ch', 'ua', 'gb', 'va'
    ],
    'north_america': [
        'ag', 'bs', 'bb', 'bz', 'ca', 'cr', 'cu', 'dm', 'do', 'sv', 'gd', 'gt', 'ht', 'hn', 'jm', 'mx', 'ni', 'pa', 'kn', 'lc', 'vc', 'tt', 'us'
    ],
    'oceania': [
        'au', 'fj', 'ki', 'mh', 'fm', 'nr', 'nz', 'pw', 'pg', 'ws', 'sb', 'to', 'tv', 'vu'
    ],
    'south_america': [
        'ar', 'bo', 'br', 'cl', 'co', 'ec', 'gy', 'py', 'pe', 'sr', 'uy', 've'
    ]
}

def write_to_file(filename, ips):
    with open((Path("./repo") / filename.with_suffix('.txt')).as_posix(), 'w') as f:
        for ip in ips:
            f.write(f"{ip}:1080\n")

queue = Queue()
resolved = {}
failed = {}
resolved_lock = Lock()
failed_lock = Lock()

r = requests.get('https://api.mullvad.net/www/relays/wireguard/').json()

for host in r:
    if host.get('socks_name') and host['active']:
        queue.put(host['socks_name'])

threads = []
for i in range(3):
    thread = Thread(target=resolver, args=(queue, resolved, failed, resolved_lock, failed_lock), daemon=True)
    thread.start()
    threads.append(thread)

queue.join()

country_ips = defaultdict(list)
continent_ips = defaultdict(list)

for host in r:
    socks_name = host.get('socks_name')
    if socks_name and host['active'] and socks_name in resolved:
        socks_addr = resolved[socks_name]
        country_code = host['country_code']
        country_ips[country_code].append(socks_addr)
        
        continent = None
        for cont, countries in COUNTRY_TO_CONTINENT.items():
            if country_code in countries:
                continent = cont
                break
        if continent:
            continent_ips[continent].append(socks_addr)

for country_code, ips in country_ips.items():
    write_to_file(f'country_{country_code}', ips)

for continent, ips in continent_ips.items():
    write_to_file(f'continent_{continent}', ips)

all_ips = [resolved[host['socks_name']] for host in r 
           if host.get('socks_name') and 
           host['active'] and 
           host['socks_name'] in resolved]
write_to_file('all_proxies', all_ips)
