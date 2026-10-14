from pathlib import Path
import json,shutil,zipfile
r=Path('.');out=Path('published');out.mkdir(exist_ok=True)
version=(r/'VERSION').read_text().strip()
(r/'dist').mkdir(exist_ok=True)
for binary in out.glob('multipla-*-linux-*'):shutil.copy2(binary,r/'dist'/binary.name)
for name in ['manifest-amd64.json','manifest-amd64.sig','manifest-arm64.json','manifest-arm64.sig','bootstrap-manifest-amd64.json','bootstrap-manifest-amd64.sig','bootstrap-manifest-arm64.json','bootstrap-manifest-arm64.sig','windows-manifest.json','windows-manifest.sig','iso-manifest.json','iso-manifest.sig','trusted-release-public.pem','sbom.json','source-provenance.json']:
 shutil.copy2(r/'release'/name,out/name)
with zipfile.ZipFile(out/f'Multipla-SIEM-Coletores-{version}-Assinados.zip','w',zipfile.ZIP_DEFLATED) as archive:
 for file in sorted((r/'release/collectors').iterdir()):
  if file.is_file():archive.write(file,file.name)
# Complete signed bootstrap package for both architectures.
files=set()
for arch in ['amd64','arm64']:files.update(json.loads((r/'release'/f'bootstrap-manifest-{arch}.json').read_text())['files'])
files.update(['release/bootstrap-manifest-amd64.json','release/bootstrap-manifest-amd64.sig','release/bootstrap-manifest-arm64.json','release/bootstrap-manifest-arm64.sig'])
with zipfile.ZipFile(out/f'Multipla-SIEM-Linux-{version}-Assinado.zip','w',zipfile.ZIP_DEFLATED) as archive:
 for name in sorted(files):archive.write(r/name,name)
