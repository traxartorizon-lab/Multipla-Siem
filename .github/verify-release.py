"""Public-key verification only. No private signing key is used by CI."""
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

config = json.loads(Path('update.example.json').read_text())
public = base64.b64decode(config['public_key'], validate=True)
assert len(public) == 32
der = bytes.fromhex('302a300506032b6570032100') + public
version = None
with tempfile.TemporaryDirectory() as directory:
    key = Path(directory) / 'public.pem'
    key.write_text('-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(der).decode() + '\n-----END PUBLIC KEY-----\n')
    for arch in ('amd64', 'arm64'):
        path = Path('release') / f'manifest-{arch}.json'
        signature = path.with_suffix('.sig')
        assert len(signature.read_bytes()) == 64
        subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(key), '-rawin', '-in', str(path), '-sigfile', str(signature)], check=True)
        manifest = json.loads(path.read_text())
        assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', manifest['version'])
        assert manifest['arch'] == arch
        version = version or manifest['version']
        assert manifest['version'] == version
        binary = Path('dist') / f'multipla-siem-linux-{arch}'
        assert binary.stat().st_size == manifest['size']
        assert hashlib.sha256(binary.read_bytes()).hexdigest() == manifest['sha256']
print('Signatures and reproducible release binaries verified.')
