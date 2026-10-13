"""Exercise installer control flow without root writes, real packages or network."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent

class InstallerTests(unittest.TestCase):
    def run_installer(self, fail=False, mode='', existing=False):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); commands=root/'bin'; commands.mkdir(); units=root/'units'; units.mkdir(); conf=root/'conf'; code=root/'code'; trace=root/'trace'
            source=(ROOT/'linux-collector-install.sh').read_text().replace('__COLLECTOR_BODY__',(ROOT/'linux-collector.py').read_text())
            source=source.replace('/run/systemd/system',str(root)).replace('/etc/multipla-siem-collector',str(conf)).replace('/usr/local/lib/multipla-siem-collector',str(code)).replace('/etc/systemd/system',str(units)).replace('/etc/ssl/certs/ca-certificates.crt',str(root/'ca'))
            (root/'ca').write_text('fixture'); installer=root/'installer.sh'; installer.write_text(source)
            def command(name,body):
                file=commands/name;file.write_text('#!/bin/bash\n'+body+'\n');file.chmod(0o755)
            command('id','echo 0');command('stat','echo 0');command('sleep','true');command('journalctl','echo "Conexao HTTPS indisponivel"');command('systemd-analyze','exit 0')
            command('install','args=(); while (($#)); do case "$1" in -o|-g) shift 2;; *) args+=("$1");shift;; esac; done; /usr/bin/install "${args[@]}"')
            command('systemctl',f'''echo "$*" >>"{trace}"
case "$1" in
 --version) echo 'systemd 252';;
 reset-failed) exit 1;;
 show) echo success;;
 start) [[ "$2" != multipla-metrics.service || "${{FAIL_TEST:-0}}" != 1 ]];;
 *) exit 0;;
esac''')
            if existing:
                conf.mkdir();code.mkdir();(conf/'config.json').write_text('{"server":"https://example.test:8443","ip":"100.86.221.98"}');(conf/'token').write_text('a'*40)
            env=dict(os.environ,PATH=str(commands)+':'+os.environ['PATH'],FAIL_TEST='1' if fail else '0')
            result=subprocess.run(['bash',str(installer)]+([mode] if mode else []),input='https://example.test:8443\n100.86.221.98\n'+'a'*40+'\n',text=True,capture_output=True,env=env)
            return result,trace.read_text() if trace.exists() else ''

    def test_first_collection_before_timer(self):
        result,trace=self.run_installer();self.assertEqual(result.returncode,0,result.stderr);self.assertLess(trace.index('start multipla-metrics.service'),trace.index('enable --now multipla-metrics.timer'));self.assertIn('SUCESSO',result.stdout)
    def test_failed_collection_does_not_enable_timer(self):
        result,trace=self.run_installer(fail=True);self.assertNotEqual(result.returncode,0);self.assertNotIn('enable --now',trace);self.assertNotIn('SUCESSO',result.stdout);self.assertEqual(trace.count('start multipla-metrics.service'),3)
    def test_repair_preserves_existing_config(self):
        result,trace=self.run_installer(mode='--repair',existing=True);self.assertEqual(result.returncode,0,result.stderr);self.assertIn('stop multipla-metrics.timer',trace);self.assertIn('enable --now',trace)

if __name__=='__main__':unittest.main()
