"""Repack a signature-verified Debian netinst ISO. Python 3 + pycdlib + Pillow.

The caller verifies Debian's detached checksum signature before invoking this.
No disk partitions, passwords, TLS keys or account credentials are embedded.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

import pycdlib
from PIL import Image, ImageDraw, ImageFont

def font(size):
    candidates = ['C:/Windows/Fonts/segoeuib.ttf', '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf']
    for path in candidates:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default(size=size)

def graphic(width, height, banner=False):
    im = Image.new('RGB', (width, height), '#0b131c')
    d = ImageDraw.Draw(im)
    if not banner:
        for r in (160, 235, 310):
            d.ellipse((width-100-r, height-80-r, width-100+r, height-80+r), outline='#19372f', width=1)
    y = 14 if banner else 40
    d.rounded_rectangle((28, y, 65, y+43), radius=8, fill='#53dec1')
    d.text((36, y+3), 'M', font=font(25), fill='#0b2922')
    d.text((82, y-2), 'MULTIPLA SIEM', font=font(30 if banner else 33), fill='#eef6f9')
    if not banner:
        d.text((31, 106), 'Central de seguranca para sua infraestrutura', font=font(14), fill='#9cafbd')
        d.text((31, height-57), 'BASE DEBIAN', font=font(12), fill='#53dec1')
        d.text((31, height-34), 'Selecao de disco e formatacao exigem sua confirmacao.', font=font(10), fill='#91a2b1')
    else:
        d.text((500, 30), 'Debian', font=font(13), fill='#53dec1')
    if not banner:
        im = Image.blend(im, Image.new('RGB', im.size, '#000000'), 0.38)
    out = io.BytesIO(); im.save(out, format='PNG'); return out.getvalue()

def newc_file(name, data, inode=100000):
    name_bytes = name.encode() + b'\0'
    fields = [inode, 0o100644, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name_bytes), 0]
    header = b'070701' + ''.join(f'{x:08x}' for x in fields).encode()
    prefix = header + name_bytes
    prefix += b'\0' * (-len(prefix) % 4)
    result = prefix + data
    return result + b'\0' * (-len(data) % 4)

def brand_initrd(data):
    # Kernel initramfs supports concatenated compressed newc archives.
    logo = graphic(800, 75, banner=True)
    overlay = newc_file('usr/share/graphics/logo_debian.png', logo)
    overlay += newc_file('TRAILER!!!', b'', inode=100001)
    return data + gzip.compress(overlay, compresslevel=9, mtime=0)

def package(root):
    files = ['update.example.json', 'scripts/multipla-update', 'dist/multipla-update-linux-amd64', 'UPDATES.md', 'scripts/install-updates.sh', 'config.example.json', 'deploy/multipla-siem.service', 'deploy/multipla-firstboot.service', 'scripts/install.sh', 'scripts/multipla-setup', 'scripts/verify-installation.sh', 'dist/multipla-siem-linux-amd64', 'README.md', 'VERSION', 'CHANGELOG.md', 'INSTALLATION-ISO.md', 'SECURITY-REVIEW.md', 'BACKUP-DRIVE.md', 'UNIFI-SNMP-WEBHOOK.md', 'THIRD-PARTY-NOTICES.md', 'integrations/custom-multipla-siem', 'integrations/wazuh.xml', 'deploy/proxmox-rsyslog.conf']
    for path in files:
        if not (root/path).is_file():
            raise ValueError('Missing payload file: '+path)
    manifest = ''.join(hashlib.sha256((root/p).read_bytes()).hexdigest()+'  '+p+'\n' for p in files).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        for path in files:
            data = (root/path).read_bytes()
            info = tarfile.TarInfo(path); info.size = len(data); info.mode = 0o755 if path.startswith(('scripts/','dist/')) else 0o644; info.mtime=0
            tar.addfile(info, io.BytesIO(data))
        info=tarfile.TarInfo('manifest.sha256'); info.size=len(manifest);info.mode=0o644;info.mtime=0;tar.addfile(info,io.BytesIO(manifest))
    return buf.getvalue()

def build(base, root, output, verification):
    proof=json.loads(verification.read_text())
    if proof.get('verified') is not True:
        raise ValueError('Debian signature verification is required')
    h=hashlib.sha512()
    with base.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):h.update(chunk)
    if h.hexdigest()!=proof['release']['sha512']:
        raise ValueError('Debian base SHA512 mismatch')
    iso=pycdlib.PyCdlib();iso.open(str(base));buffers=[];changed={}
    def get(path):
        b=io.BytesIO();iso.get_file_from_iso_fp(b,rr_path=path);return b.getvalue()
    def put(path,data,iso_path=None):
        try:
            rec=iso.get_record(rr_path=path);iso_path=iso.full_path_from_dirrecord(rec)
            iso.rm_file(iso_path=iso_path,joliet_path=path)
        except pycdlib.pycdlibexception.PyCdlibInvalidInput:
            if iso_path is None:raise
        stream=io.BytesIO(data);buffers.append(stream)
        iso.add_fp(stream,len(data),iso_path=iso_path,rr_name=Path(path).name,joliet_path=path,file_mode=0o100644)
        changed['.'+path]=hashlib.md5(data).hexdigest()
    iso.add_directory(iso_path='/MULTIPLA',rr_name='multipla',joliet_path='/multipla')
    put('/multipla/preseed.cfg',(root/'installer/preseed.cfg').read_bytes(),'/MULTIPLA/PRESEED.CFG;1')
    put('/multipla/post-install.sh',(root/'installer/post-install.sh').read_bytes(),'/MULTIPLA/POSTINST.SH;1')
    put('/multipla/payload.tar.gz',package(root),'/MULTIPLA/PAYLOAD.TGZ;1')
    put('/multipla/base-verification.json',verification.read_bytes(),'/MULTIPLA/BASEVER.JSON;1')
    put('/isolinux/splash.png',graphic(640,480))
    put('/install.amd/gtk/initrd.gz',brand_initrd(get('/install.amd/gtk/initrd.gz')))
    params='file=/cdrom/multipla/preseed.cfg priority=high'
    old_grub=get('/boot/grub/grub.cfg').decode()
    prefix=old_grub.split('insmod play')[0]
    grub=prefix+f'''\nset color_normal=white/black
set color_highlight=black/light-gray
set menu_color_normal=white/black
set menu_color_highlight=black/light-gray
set default=0
set timeout=-1
menuentry 'Multipla Siem - Instalar (grafico)' {{
  linux /install.amd/vmlinuz vga=788 {params} --- quiet
  initrd /install.amd/gtk/initrd.gz
}}
menuentry 'Multipla Siem - Instalar (texto)' {{
  linux /install.amd/vmlinuz {params} --- quiet
  initrd /install.amd/initrd.gz
}}
menuentry 'Debian - Recuperacao do sistema' {{
  linux /install.amd/vmlinuz rescue/enable=true --- quiet
  initrd /install.amd/initrd.gz
}}
'''
    put('/boot/grub/grub.cfg',grub.encode())
    menu='''menu hshift 4
menu width 70
menu title Multipla Siem - Instalacao
include stdmenu.cfg
include gtk.cfg
include txt.cfg
'''
    put('/isolinux/menu.cfg',menu.encode())
    std=get('/isolinux/stdmenu.cfg').decode()
    std+='\nmenu color title 1;37;40 #ffffffff #d0000000 std\nmenu color unsel 37;40 #ffffffff #b0000000 std\nmenu color sel 1;37;40 #ffffffff #ff174438 all\nmenu color tabmsg 37;40 #ffffffff #d0000000 std\nmenu color help 37;40 #ffffffff #d0000000 std\n'
    put('/isolinux/stdmenu.cfg',std.encode())
    put('/isolinux/gtk.cfg',f'''label multipla-gui
 menu label ^Multipla Siem - Instalar (grafico)
 menu default
 kernel /install.amd/vmlinuz
 append initrd=/install.amd/gtk/initrd.gz vga=788 {params} --- quiet
'''.encode())
    put('/isolinux/txt.cfg',f'''label multipla-text
 menu label Multipla Siem - Instalar (^texto)
 kernel /install.amd/vmlinuz
 append initrd=/install.amd/initrd.gz {params} --- quiet
'''.encode())
    sums={}
    for line in get('/md5sum.txt').decode().splitlines():
        parts=line.split(None,1)
        if len(parts)==2:sums[parts[1].lstrip('*')]=parts[0]
    sums.update(changed)
    put('/md5sum.txt',''.join(f'{v}  {k}\n' for k,v in sorted(sums.items())).encode())
    iso.pvd.volume_identifier=b'MULTIPLA_SIEM'.ljust(32,b' ')
    if iso.joliet_vd:iso.joliet_vd.volume_identifier='MULTIPLA_SIEM'.ljust(16).encode('utf-16-be')
    output.parent.mkdir(parents=True,exist_ok=True);iso.write(str(output));iso.close()
    final=hashlib.sha256()
    with output.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):final.update(chunk)
    output.with_suffix('.iso.sha256').write_text(final.hexdigest()+'  '+output.name+'\n')
    print('Created',output,'SHA256',final.hexdigest())

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--base',type=Path,required=True);p.add_argument('--root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--verification',type=Path,required=True);args=p.parse_args();build(args.base,args.root,args.output,args.verification)



