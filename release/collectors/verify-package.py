#!/usr/bin/env python3
"""Verify authenticated artifacts before elevation; the trust anchor is provisioned separately."""
import argparse,base64,hashlib,json,re,subprocess,tempfile
from pathlib import Path
parser=argparse.ArgumentParser()
parser.add_argument('--key',required=True,help='Trusted Ed25519 public key PEM, obtained independently')
parser.add_argument('--manifest',required=True)
parser.add_argument('--signature',required=True)
parser.add_argument('--root',required=True)
parser.add_argument('--version',required=True)
args=parser.parse_args()
subprocess.run(['openssl','pkeyutl','-verify','-pubin','-inkey',args.key,'-rawin','-in',args.manifest,'-sigfile',args.signature],check=True)
manifest=json.loads(Path(args.manifest).read_text(encoding='utf-8'))
if manifest.get('product')!='Multipla SIEM' or manifest.get('schema')!=1 or manifest.get('version')!=args.version:
 raise SystemExit('Product, schema or exact version mismatch')
root=Path(args.root).resolve()
if not isinstance(manifest.get('files'),dict) or not 1<=len(manifest['files'])<=512:raise SystemExit('Invalid files')
for name,digest in manifest['files'].items():
 if '\\' in name or name.startswith('/') or '..' in Path(name).parts:raise SystemExit('Invalid path')
 file=root/name
 if file.is_symlink() or not file.is_file() or not file.resolve().is_relative_to(root):raise SystemExit('Invalid file')
 if file.stat().st_size!=digest['size'] or hashlib.sha256(file.read_bytes()).hexdigest()!=digest['sha256']:raise SystemExit('Artifact integrity mismatch: '+name)
print('Verified signature, product, version and all artifact hashes. No elevation performed.')
