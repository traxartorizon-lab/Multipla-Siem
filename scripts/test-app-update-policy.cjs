'use strict';
const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
const policy=fs.readFileSync(path.join(__dirname,'../deploy/49-multipla-app-update.rules'),'utf8');
let rule;vm.runInNewContext(policy,{polkit:{addRule(fn){rule=fn},Result:{YES:'yes'}}});
function allowed(user,id,unit,verb){return rule({id,lookup:k=>({unit,verb})[k]},{user})==='yes'}
assert(allowed('multipla-siem','org.freedesktop.systemd1.manage-units','multipla-app-update.service','start'));
for(const user of ['root','siemadmin','other'])assert(!allowed(user,'org.freedesktop.systemd1.manage-units','multipla-app-update.service','start'));
for(const unit of ['ssh.service','multipla-siem.service','evil.service'])assert(!allowed('multipla-siem','org.freedesktop.systemd1.manage-units',unit,'start'));
for(const verb of ['stop','restart','reload','set-property'])assert(!allowed('multipla-siem','org.freedesktop.systemd1.manage-units','multipla-app-update.service',verb));
assert(!allowed('multipla-siem','org.freedesktop.systemd1.manage-unit-files','multipla-app-update.service','start'));
console.log('PASS: update policy permits only fixed unit start');
