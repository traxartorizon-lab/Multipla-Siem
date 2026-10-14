"""Verify the Windows application's exact reproducible file hashes and offline signature."""
import hashlib,json,os,shutil,subprocess
from pathlib import Path
root=Path('app-package');manifest=Path('release/windows-manifest.json')
tool=shutil.which('openssl') or str(Path(os.environ.get('ProgramFiles','C:/Program Files'))/'Git/usr/bin/openssl.exe')
subprocess.run([tool,'pkeyutl','-verify','-pubin','-inkey','release/trusted-release-public.pem','-rawin','-in',str(manifest),'-sigfile','release/windows-manifest.sig'],check=True)
data=json.loads(manifest.read_text());assert data['version']==Path('VERSION').read_text().strip();assert data['product']=='Multipla SIEM'
actual={str(p.relative_to(root)).replace('\\','/') for p in root.rglob('*') if p.is_file() and p.name!='self-test-result.txt'}
assert actual==set(data['files']),('Unexpected or missing Windows files',actual^set(data['files']))
for name,entry in data['files'].items():
 path=root/name;assert path.stat().st_size==entry['size'];assert hashlib.sha256(path.read_bytes()).hexdigest()==entry['sha256'],name
print('Windows offline signature and exact reproducible hashes verified')
