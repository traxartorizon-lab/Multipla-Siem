"""One-shot metrics collector. No shell, inbound listener, commands or external dependencies."""
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request


def cpu_snapshot():
    with open('/proc/stat', encoding='ascii') as stream:
        fields = stream.readline().split()
    if not fields or fields[0] != 'cpu':
        raise ValueError('CPU counters unavailable')
    values = [int(value) for value in fields[1:9]]  # exclude guest counters (already counted)
    return sum(values), values[3] + values[4]


def network_snapshot():
    received = sent = 0
    with open('/proc/net/dev', encoding='ascii') as stream:
        for line in stream:
            if ':' not in line:
                continue
            name, data = line.split(':', 1)
            if name.strip() == 'lo':
                continue
            fields = data.split()
            received += int(fields[0])
            sent += int(fields[8])
    return received, sent


def memory_percent():
    with open('/proc/meminfo', encoding='ascii') as stream:
        values = {fields[0].rstrip(':'): int(fields[1]) for line in stream if len(fields := line.split()) >= 2}
    total = values['MemTotal']
    available = values.get('MemAvailable', values.get('MemFree', 0))
    return round(100 * max(0, min(total, total - available)) / total, 2)


def disk_metrics():
    disks, seen = [], set()
    with open('/proc/self/mountinfo', encoding='utf-8') as stream:
        for line in stream:
            left, right = line.rstrip().split(' - ', 1)
            fields, fs = left.split(), right.split()[0]
            if fs not in {'ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'zfs', 'f2fs'}:
                continue
            mount = fields[4].replace('\\040', ' ').replace('\\134', '\\')
            if len(mount) > 120 or not re.fullmatch(r'/[a-zA-Z0-9_./ -]*', mount) or fields[2] in seen:
                continue
            try:
                stats = os.statvfs(mount)
            except OSError:
                continue
            if stats.f_blocks <= 0:
                continue
            seen.add(fields[2])
            disks.append({'drive': mount, 'used_percent': round(100 * (stats.f_blocks - stats.f_bfree) / stats.f_blocks, 2)})
            if len(disks) == 32:
                break
    return disks


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        raise ValueError('Redirect refused')


def collect():
    first_cpu, first_network, started = cpu_snapshot(), network_snapshot(), time.monotonic()
    time.sleep(1)
    last_cpu, last_network = cpu_snapshot(), network_snapshot()
    elapsed = max(.1, time.monotonic() - started)
    total = last_cpu[0] - first_cpu[0]
    idle = last_cpu[1] - first_cpu[1]
    cpu = 100 * (1 - idle / total) if total > 0 else 0
    return {'hostname': socket.gethostname(), 'cpu': round(max(0, min(100, cpu)), 2),
            'memory': memory_percent(), 'disks': disk_metrics(),
            'receive_bytes_per_second': max(0, last_network[0] - first_network[0]) / elapsed,
            'send_bytes_per_second': max(0, last_network[1] - first_network[1]) / elapsed}


def main():
    directory = os.environ['CREDENTIALS_DIRECTORY']
    with open(os.path.join(directory, 'config'), encoding='utf-8') as stream:
        config = json.load(stream)
    origin = urllib.parse.urlsplit(config['server'])
    if origin.scheme != 'https' or not origin.hostname or origin.username or origin.password or origin.query or origin.fragment or origin.path not in {'', '/'}:
        raise ValueError('Invalid HTTPS origin')
    with open(os.path.join(directory, 'token'), encoding='ascii') as stream:
        key = stream.read(129).strip()
    if not re.fullmatch(r'[a-zA-Z0-9_-]{32,128}', key):
        raise ValueError('Invalid key')
    url = config['server'].rstrip('/') + '/api/device-metrics/' + urllib.parse.quote(config['ip'], safe='')
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(url, data=json.dumps(collect(), allow_nan=False).encode('utf-8'),
                                    headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'}, method='POST')
    with opener.open(request, timeout=10) as response:
        if response.status != 200:
            raise ValueError('Metrics refused')
    key = None


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Never log exception content, request headers or bearer tokens.
        print('Coleta/envio indisponivel. Verifique HTTPS, chave e acesso ao SIEM.', file=sys.stderr)
        sys.exit(1)
