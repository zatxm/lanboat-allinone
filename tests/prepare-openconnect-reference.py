#!/usr/bin/env python3
"""Pinned Ubuntu OpenConnect/ocserv binaries, extracted locally for tests only."""
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[1] / '.cache/openconnect-reference'
ASSETS = [
  {
    "name": "libcjose0_0.6.2.8-1_amd64.deb",
    "url": "https://archive.ubuntu.com/ubuntu/pool/universe/c/cjose/libcjose0_0.6.2.8-1_amd64.deb",
    "sha256": "393e04d43a6a568d3cbeed66783ffce647b3b489ba577ed9ccbc0db97e84079a",
    "package": "libcjose0",
    "version": "0.6.2.8-1"
  },
  {
    "name": "libev4t64_1%3a4.33-2.1build2_amd64.deb",
    "url": "https://archive.ubuntu.com/ubuntu/pool/universe/libe/libev/libev4t64_4.33-2.1build2_amd64.deb",
    "sha256": "b69dd50df7ac1dfc5c67f44e825944e2aa76eaacbc270a996d2790f188fe8568",
    "package": "libev4t64",
    "version": "1:4.33-2.1build2"
  },
  {
    "name": "libllhttp9.4_9.4.3+~cs12.11.9-2_amd64.deb",
    "url": "https://archive.ubuntu.com/ubuntu/pool/universe/l/llhttp/libllhttp9.4_9.4.3%2b%7ecs12.11.9-2_amd64.deb",
    "sha256": "07090d45ce06ffdb9beff5f3e264a58c0e880d0375d20792228a1d272ff9b3fe",
    "package": "libllhttp9.4",
    "version": "9.4.3+~cs12.11.9-2"
  },
  {
    "name": "liboath0t64_2.6.14-1build2_amd64.deb",
    "url": "https://archive.ubuntu.com/ubuntu/pool/main/o/oath-toolkit/liboath0t64_2.6.14-1build2_amd64.deb",
    "sha256": "97ccefd0434c632581340178121afbb161ecdd22661abe813eb4a5c5d76011d8",
    "package": "liboath0t64",
    "version": "2.6.14-1build2"
  },
  {
    "name": "libopenconnect5_9.21-5_amd64.deb",
    "url": "https://archive.ubuntu.com/ubuntu/pool/universe/o/openconnect/libopenconnect5_9.21-5_amd64.deb",
    "sha256": "3f57c7f2561b3e194e643bf47a9135997891a2cfa6d9deecc7cf8ac8444cc4b2",
    "package": "libopenconnect5",
    "version": "9.21-5"
  },
  {
    "name": "libprotobuf-c1_1.5.1-1ubuntu2_amd64.deb",
    "url": "https://archive.ubuntu.com/ubuntu/pool/universe/p/protobuf-c/libprotobuf-c1_1.5.1-1ubuntu2_amd64.deb",
    "sha256": "7770083b0a5a7524c04327acbe8101498228df713f7e4f7532bce55f92287095",
    "package": "libprotobuf-c1",
    "version": "1.5.1-1ubuntu2"
  },
  {
    "name": "libpskc0t64_2.6.14-1build2_amd64.deb",
    "url": "https://archive.ubuntu.com/ubuntu/pool/main/o/oath-toolkit/libpskc0t64_2.6.14-1build2_amd64.deb",
    "sha256": "40fb763c3f697bf6afa63a34f18b124d067b92b81e78052be614890e6e2b40be",
    "package": "libpskc0t64",
    "version": "2.6.14-1build2"
  },
  {
    "name": "libradcli4_1.2.11-1build4_amd64.deb",
    "url": "https://archive.ubuntu.com/ubuntu/pool/universe/r/radcli/libradcli4_1.2.11-1build4_amd64.deb",
    "sha256": "944ec0d047d8b8828adffbb6d11e81389cc2a603b4d32cabfd6c4a822bb929c1",
    "package": "libradcli4",
    "version": "1.2.11-1build4"
  },
  {
    "name": "libstoken1t64_0.93-2_amd64.deb",
    "url": "https://archive.ubuntu.com/ubuntu/pool/universe/s/stoken/libstoken1t64_0.93-2_amd64.deb",
    "sha256": "92f769b1b7d4a00fef503c1595e9bf2c32d4d123ded3db6df1dd330870fbb4b7",
    "package": "libstoken1t64",
    "version": "0.93-2"
  },
  {
    "name": "libtalloc2_2%3a2.4.4+samba4.24.7+dfsg-1ubuntu1_amd64.deb",
    "url": "https://archive.ubuntu.com/ubuntu/pool/main/s/samba/libtalloc2_2.4.4%2bsamba4.24.7%2bdfsg-1ubuntu1_amd64.deb",
    "sha256": "ad0aba64808cb00835e20d7b7505ff522a24096afaad20e6f1121556240eabf0",
    "package": "libtalloc2",
    "version": "2:2.4.4+samba4.24.7+dfsg-1ubuntu1"
  },
  {
    "name": "libtomcrypt1_1.18.2+dfsg-7build2_amd64.deb",
    "url": "https://archive.ubuntu.com/ubuntu/pool/universe/libt/libtomcrypt/libtomcrypt1_1.18.2%2bdfsg-7build2_amd64.deb",
    "sha256": "108fc3bf6c54398c610907be317272a0b54cfaf9c49588fa9bc91aa8f24f326f",
    "package": "libtomcrypt1",
    "version": "1.18.2+dfsg-7build2"
  },
  {
    "name": "libtommath1_1.3.0-1build1_amd64.deb",
    "url": "https://archive.ubuntu.com/ubuntu/pool/universe/libt/libtommath/libtommath1_1.3.0-1build1_amd64.deb",
    "sha256": "1aff68d374c636a86dcfc367a7bd1bdd9247d687f8c74e183e80f7fb3b3397ce",
    "package": "libtommath1",
    "version": "1.3.0-1build1"
  },
  {
    "name": "libtss2-tctildr0t64_4.1.3-7ubuntu1_amd64.deb",
    "url": "https://archive.ubuntu.com/ubuntu/pool/main/t/tpm2-tss/libtss2-tctildr0t64_4.1.3-7ubuntu1_amd64.deb",
    "sha256": "d6a994b1f33d84db1aeeac682de9e035e464eb0f00326bc763f92a92fd16bb54",
    "package": "libtss2-tctildr0t64",
    "version": "4.1.3-7ubuntu1"
  },
  {
    "name": "libxmlsec1-10312_1.3.12-1_amd64.deb",
    "url": "https://archive.ubuntu.com/ubuntu/pool/main/x/xmlsec1/libxmlsec1-10312_1.3.12-1_amd64.deb",
    "sha256": "b3c43ce7e014047e421c3a71db0045d1b26cdfa562329692abfe1c36d55b7d64",
    "package": "libxmlsec1-10312",
    "version": "1.3.12-1"
  },
  {
    "name": "libxmlsec1-openssl10312_1.3.12-1_amd64.deb",
    "url": "https://archive.ubuntu.com/ubuntu/pool/main/x/xmlsec1/libxmlsec1-openssl10312_1.3.12-1_amd64.deb",
    "sha256": "a20e73b8939bc27b6280388d52768a7bbd8a1e379dcae50ac3a36082dfa7e5af",
    "package": "libxmlsec1-openssl10312",
    "version": "1.3.12-1"
  },
  {
    "name": "ocserv_1.5.0-1build1_amd64.deb",
    "url": "https://archive.ubuntu.com/ubuntu/pool/universe/o/ocserv/ocserv_1.5.0-1build1_amd64.deb",
    "sha256": "d5bc57982e64a0c8747c529a56c45c653de2651cb75c5ae2746b3c91f940aedb",
    "package": "ocserv",
    "version": "1.5.0-1build1"
  },
  {
    "name": "openconnect_9.21-5_amd64.deb",
    "url": "https://archive.ubuntu.com/ubuntu/pool/universe/o/openconnect/openconnect_9.21-5_amd64.deb",
    "sha256": "76057b62014b3c6ac354868e6d976de8425d345314e1a0f06c81f9040b977171",
    "package": "openconnect",
    "version": "9.21-5"
  }
]
(ROOT / 'pkgs').mkdir(parents=True, exist_ok=True)
for asset in ASSETS:
    path = ROOT / 'pkgs' / asset['name']
    if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != asset['sha256']:
        data = urllib.request.urlopen(asset['url'], timeout=60).read()
        if hashlib.sha256(data).hexdigest() != asset['sha256']:
            raise SystemExit('OpenConnect reference checksum mismatch: ' + asset['name'])
        path.write_bytes(data)
    subprocess.run(['dpkg-deb', '-x', str(path), str(ROOT / 'root')], check=True)
binaries = ['usr/sbin/openconnect', 'usr/sbin/ocserv', 'usr/sbin/ocserv-worker', 'usr/bin/ocpasswd']
(ROOT / 'provenance.json').write_text(json.dumps(dict(
    assets=ASSETS,
    binaries={name: hashlib.sha256((ROOT / 'root' / name).read_bytes()).hexdigest() for name in binaries},
    scope='Official Ubuntu packages OpenConnect9.21-5 and ocserv1.5.0-1build1 plus runtime libraries, test-only processes in isolated user/network namespaces; not linked or shipped with product. Linux amd64/Ubuntu26.10 fixture requires host system libraries.'
), indent=2) + '\n')
print(ROOT / 'root')
