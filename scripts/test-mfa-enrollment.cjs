'use strict';
const fs=require('fs'),vm=require('vm'),assert=require('assert');
async function scenario(enrolled=false,fail=false){
 const nodes={};for(const id of ['mfa-account','mfa-secret','mfa-uri','mfa-enrollment','mfa-qr','mfa-expiry','mfa-status','mfa-form'])nodes[id]={value:'',textContent:'',hidden:true,removeAttribute(name){delete this[name]}};
 const button={disabled:true};const code={value:'',focus(){this.focused=true},addEventListener(name,handler){this.input=handler}};
 const form=nodes['mfa-form'];form.elements={code};form.querySelector=()=>button;
 const calls=[],location={href:'/auth/mfa'};
 const context={document:{getElementById:id=>nodes[id],querySelector:selector=>selector==='button'?button:code},location,fetch:async(path,options)=>{
  calls.push({path,options});if(fail)return{ok:false,text:async()=> 'Sessão expirada'};
  const data=path.endsWith('/status')?{email:'fixture@example.invalid',csrf:'fixture-csrf',enrolled}:path.endsWith('/enroll')?{secret:'fixture',uri:'otpauth://totp/fixture',qr:'/auth/mfa/qr.png'}:{ok:true};
  return{ok:true,json:async()=>data};
 }};
 vm.runInNewContext(fs.readFileSync('web/mfa.js','utf8'),context);for(let i=0;i<6;i++)await new Promise(resolve=>setImmediate(resolve));
 return{nodes,button,code,calls,location,form};
}
(async()=>{
 let s=await scenario();assert.equal(s.nodes['mfa-qr'].src,'/auth/mfa/qr.png');assert.equal(s.nodes['mfa-enrollment'].hidden,false);assert.equal(s.code.focused,undefined);assert.equal(s.button.disabled,false);assert.equal(s.calls[1].options.headers['X-CSRF-Token'],'fixture-csrf');
 s.code.value='123 456';s.code.input({target:s.code});assert.equal(s.code.value,'123456');await s.form.onsubmit({preventDefault(){},currentTarget:s.form});assert.equal(s.location.href,'/');assert.equal(JSON.parse(s.calls.at(-1).options.body).code,'123456');assert.equal(s.nodes['mfa-secret'].value,'');assert.equal(s.nodes['mfa-qr'].src,undefined);assert.equal(s.nodes['mfa-qr'].hidden,true);assert.equal(s.nodes['mfa-uri'].href,undefined);
 s=await scenario(true);assert.equal(s.calls.length,1);assert.equal(s.code.focused,true);assert.equal(s.nodes['mfa-enrollment'].hidden,true);
 s=await scenario(false,true);assert.equal(s.button.disabled,true);assert.equal(s.nodes['mfa-status'].textContent,'Sessão expirada');
 console.log('MFA UI: local QR, paste normalization, CSRF, successful login and expired session passed');
})().catch(e=>{console.error(e);process.exitCode=1});
