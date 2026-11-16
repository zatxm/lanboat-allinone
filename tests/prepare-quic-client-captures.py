#!/usr/bin/env python3
"""Prepare pinned packet-only fixtures; reference code never enters the core."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import urllib.error
import urllib.request

REV = '4e23d91ff8b8635ecdb9322ac945f91559b19775'
CASES = {
    'apple_safari_18_5_icloud_private_relay_disabled': ('safari', '4198317814e539c20f7a25a62b1b27918c214de8dfeba6099baea4545b41e89b'),
    'chrome_113_0_5672_126': ('chromium', '4f1a97103539f9701229102d7f303f6115acfb4e7878782e124ce159c52d55e6'),
    'chrome_148': ('chromium', '124057f2fb1a4f906c8c966c0eb9516b5e2e441bfb62a385eb02586db39c698a'),
    'firefox_149': ('firefox', '3f8e93f936bd8c125d9c931d95dafe1db985d75e36f30f9bb4344c5f7b0041ea'),
    'firefox_149_high_packet_numbers': ('firefox', 'fbeaeec9c6d5cb5787071f4766a643b92e9ea55f3641f2441a3a2a817bb84278'),
    'multi_chrome_146': ('chromium', 'b8dd9c268f5584cb1a9da1087c103fdb9bbed2201418d3ee9697d22041db1aef'),
    'multi_firefox_149': ('firefox', '0c12b1f47853dd4a8dffd0870d140a1a8a39da5e3555d6e9b6daa574d85ae6bf'),
}
ROOT = Path(__file__).resolve().parents[1] / '.cache/quic-client/captures'


def packets(raw):
    """Read the pinned traces after tcpdump normalizes their PCAP container."""
    little = [b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1']
    assert raw[:4] in little + [b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d']
    order = '<' if raw[:4] in little else '>'
    link = struct.unpack_from(order + 'I', raw, 20)[0]
    pos = 24
    while pos < len(raw):
        _, _, n, _ = struct.unpack_from(order + 'IIII', raw, pos)
        pos += 16
        assert n <= len(raw) - pos
        frame, pos = raw[pos:pos+n], pos+n
        if link == 1:
            offset, eth = 14, int.from_bytes(frame[12:14], 'big')
            while eth in [0x8100, 0x88a8]:
                eth = int.from_bytes(frame[offset+2:offset+4], 'big')
                offset += 4
            if eth not in [0x800, 0x86dd]:
                continue
            frame = frame[offset:]
        elif link == 113:
            frame = frame[16:]
        elif link == 276:
            frame = frame[20:]
        else:
            assert link in [101, 228, 229], link
        if not frame:
            continue
        if frame[0] >> 4 == 4:
            if len(frame) < 20 or frame[9] != 17 or int.from_bytes(frame[6:8], 'big') & 0x3fff:
                continue
            offset = (frame[0] & 15) * 4
            udp = frame[offset:min(len(frame), int.from_bytes(frame[2:4], 'big'))]
        elif frame[0] >> 4 == 6:
            if len(frame) < 40 or frame[6] != 17:
                continue
            udp = frame[40:min(len(frame), 40 + int.from_bytes(frame[4:6], 'big'))]
        else:
            continue
        if len(udp) < 8:
            continue
        length = int.from_bytes(udp[4:6], 'big')
        assert 8 <= length <= len(udp)
        yield udp[8:length]


def download(url):
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(1 << 20)
    assert len(data) < 1 << 20
    return data


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    report = {'source': 'https://github.com/refraction-networking/quic-fingerprint-conformance', 'revision': REV, 'cases': []}
    for name, (want, digest) in CASES.items():
        case = ROOT / name
        case.mkdir(exist_ok=True)
        base = report['source'].replace('github.com/', 'raw.githubusercontent.com/') + '/' + REV + '/corpus/' + name + '/'
        for file in ['input.pcapng', 'expected.json', 'meta.json']:
            target = case / file
            if not target.exists():
                try:
                    data = download(base + file)
                except urllib.error.HTTPError as error:
                    if error.code != 404 or file != 'input.pcapng':
                        raise
                    data = download(base + 'input.pcap')
                target.write_bytes(data)
        assert hashlib.sha256((case / 'input.pcapng').read_bytes()).hexdigest() == digest, name
        golden = json.loads((case / 'expected.json').read_text())
        labels = {item['conn_key']: want for item in golden}
        # Two background flows have Apple Network.framework-style TLS parameters.
        if name == 'multi_chrome_146':
            for key in ['488154e074464e0a', '5e5f730cdb2fa553']:
                labels[key] = 'safari'
        flows = {key: [] for key in sorted(labels)}
        subprocess.run(['tcpdump', '-r', str(case / 'input.pcapng'), '-w', str(case / 'normalized.pcap')], check=True, capture_output=True)
        for data in packets((case / 'normalized.pcap').read_bytes()):
            if len(data) < 7 or data[0] & 0xc0 != 0xc0:
                continue
            version = int.from_bytes(data[1:5], 'big')
            if version not in [1, 0x6b3343cf] or data[0] & 0x30 != (0x10 if version == 0x6b3343cf else 0):
                continue
            key = data[6:6+data[5]].hex()
            if key in flows:
                flows[key].append(data)
        entries = []
        for key, datagrams in flows.items():
            assert datagrams, (name, key)
            paths = []
            for i, data in enumerate(datagrams[:32]):
                target = case / (key + '-' + str(i) + '.bin')
                target.write_bytes(data)
                paths.append(str(target))
            entries.append({'dcid': key, 'want': labels[key], 'datagrams': paths})
        report['cases'].append({'name': name, 'want': want, 'pcap_sha256': digest, 'flows': entries})
    manifest = ROOT / 'manifest.json'
    manifest.write_text(json.dumps(report, indent=2) + '\n')
    print(manifest)


if __name__ == '__main__':
    main()
