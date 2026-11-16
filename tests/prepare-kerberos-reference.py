"""Extract pinned MIT Kerberos tools/libraries for isolated tests; install nothing."""
from pathlib import Path
import hashlib,json,subprocess,urllib.request

repo=Path(__file__).resolve().parents[1]
root=repo/'.cache/kerberos-reference'
downloads=root/'downloads'
downloads.mkdir(parents=True,exist_ok=True)
assets=json.loads((repo/'tests/kerberos-reference/assets.json').read_text())
for asset in assets:
    package=downloads/asset['name']
    if not package.exists() or hashlib.sha256(package.read_bytes()).hexdigest()!=asset['sha256']:
        with urllib.request.urlopen(asset['url'],timeout=60) as response:
            data=response.read(32<<20)
        if hashlib.sha256(data).hexdigest()!=asset['sha256']:raise SystemExit('Kerberos reference hash mismatch')
        package.write_bytes(data)
    subprocess.run(['dpkg-deb','-x',str(package),str(root/'root')],check=True)
for path in (root/'root').rglob('*'):
    if path.is_file() and not path.is_symlink():
        mode=path.stat().st_mode
        if mode&0o6000:path.chmod(mode&~0o6000)
(root/'provenance.json').write_text(json.dumps(dict(assets=assets,scope='Unmodified MIT Kerberos KDC/GSSAPI in isolated test processes only;never linked into production.'),indent=2)+'\n')
print(root/'root')
