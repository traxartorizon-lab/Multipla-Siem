const fs=require('fs'),vm=require('vm'),assert=require('assert');
let rule;
const polkit={Result:{YES:'yes'},addRule:callback=>rule=callback};
vm.runInNewContext(fs.readFileSync('deploy/49-multipla-reboot.rules','utf8'),{polkit});
for(const user of ['multipla-siem','siemadmin','other'])for(const id of ['org.freedesktop.login1.reboot','org.freedesktop.login1.reboot-multiple-sessions','org.freedesktop.login1.reboot-ignore-inhibit','org.freedesktop.login1.power-off','org.freedesktop.login1.suspend','org.freedesktop.systemd1.manage-units']){
 const allowed=user==='multipla-siem'&&['org.freedesktop.login1.reboot','org.freedesktop.login1.reboot-multiple-sessions'].includes(id);
 assert.equal(rule({id},{user}),allowed?'yes':undefined,user+' '+id);
}
console.log('Política: reinício com/sem outras sessões somente para multipla-siem; demais operações não autorizadas.');
