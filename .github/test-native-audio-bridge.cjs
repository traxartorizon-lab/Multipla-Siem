'use strict';
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const sent=[],timers=[],nodes=new Map();let receiver,status='';
function node(){return {checked:false,value:'',disabled:false,textContent:'',children:[],replaceChildren(){this.children=[]},append(n){this.children.push(n)},dispatchEvent(){this.onchange?.()}}}
function $(id){if(!nodes.has(id))nodes.set(id,node());return nodes.get(id)}
const webview={postMessage:m=>sent.push(m),addEventListener:(event,fn)=>{assert.equal(event,'message');receiver=fn}};
const window={chrome:{webview}};window.top=window;
const context={window,isNativeAudioHost:()=>true,$,el:(tag,text)=>({...node(),tag,textContent:text}),alertSoundSettings:{enabled:false},stopAlertSound:()=>{},alertOutputChoose:node(),alertOutputSelect:node(),alertOutputHelp:node(),alertSoundStatus:s=>status=s,setTimeout:(fn,ms)=>timers.push({fn,ms})};
vm.createContext(context);vm.runInContext(fs.readFileSync('web/native-audio.js','utf8'),context);
assert.equal(window.multiplaNativeAudio,undefined,'test deliberately omits injected marker');
assert.equal(sent[0].action,'outputs');assert.match(context.alertOutputHelp.textContent,/Não requer acesso ao microfone/);
timers.find(t=>t.ms===3000).fn();assert.match(status,/não respondeu/);assert.equal(context.alertOutputSelect.disabled,true);
context.alertOutputChoose.onclick();assert.equal(sent.at(-1).action,'outputs');
receiver({data:{type:'unrelated',outputs:[]}});assert.equal(window.multiplaNativeAudioConfirmed,false);
receiver({data:{type:'multipla.audio.state',outputs:[{id:'',label:'Padrão'},{id:'speakers',label:'Caixas'}],selected:'speakers',enabled:true,volume:37,sound:'siren'}});
assert.equal(window.multiplaNativeAudioConfirmed,true);assert.equal(context.alertOutputSelect.children.length,2);assert.equal(context.alertOutputSelect.value,'speakers');assert.equal($('#alert-sound-volume').value,37);
assert.equal(context.alertSoundSettings.enabled,true);$('#alert-sound-enabled').checked=false;$('#alert-sound-enabled').onchange();assert.equal(context.alertSoundSettings.enabled,false);assert.equal(sent.at(-1).enabled,false);
context.alertOutputChoose.onclick();assert.equal(sent.at(-1).action,'choose');
context.alertOutputSelect.onchange();assert.equal(sent.at(-1).device,'speakers');
$('#alert-sound-test').onclick();assert.equal(sent.at(-1).action,'test');$('#alert-sound-stop').onclick();assert.equal(sent.at(-1).action,'stop');
console.log('PASS native audio bridge: missing marker, handshake retry, explicit failure, late reconnection, outputs/selection/test/stop; no microphone API');
// Exercise the actual Events button against the native configure handler.
context.eventSoundButton={};context.syncEventSoundButton=()=>{};context.Event=class Event{};
const controls=fs.readFileSync('web/critical-controls.js','utf8'),start=controls.indexOf('eventSoundButton.onclick=');
vm.runInContext(controls.slice(start,controls.indexOf(';document.querySelector',start)),context);
$('#alert-sound-enabled').checked=true;context.eventSoundButton.onclick();assert.equal(sent.at(-1).action,'configure');assert.equal(sent.at(-1).enabled,false);
context.eventSoundButton.onclick();assert.equal(sent.at(-1).enabled,true);
console.log('PASS Events sound toggle configures native master state');
