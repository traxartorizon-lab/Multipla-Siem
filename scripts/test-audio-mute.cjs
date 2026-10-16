'use strict';
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const nodes=new Map(),players=[],listeners={},storage=new Map();let payload={notifications:[],cleared:new Date(0).toISOString()},deferPlay=false,deferSink=false,releasePlay,releaseSink;
function $(key){if(!nodes.has(key))nodes.set(key,{checked:false,value:'',textContent:'',classList:{toggle(){}},dispatchEvent(){this.onchange?.({target:this})}});return nodes.get(key)}
class Audio{constructor(file){this.file=file;this.paused=true;players.push(this)}pause(){this.paused=true}async setSinkId(){if(deferSink)await new Promise(resolve=>releaseSink=resolve)}async play(){if(deferPlay)await new Promise(resolve=>releasePlay=resolve);this.paused=false}}
const window={addEventListener:(name,fn)=>(listeners[name]??=[]).push(fn)};window.top=window;
const context={window,$,Audio,localStorage:{getItem:key=>storage.get(key)??null,setItem:(key,value)=>storage.set(key,value)},clearTimeout:()=>{},setTimeout:()=>1,setInterval:()=>{},snapshot:{},api:async()=>payload,observeInvasionAlerts:()=>{},alertOutputDevice:'',console};
vm.createContext(context);const prefix=fs.readFileSync('web/alert-sounds.js','utf8').split('// Audio hardware belongs')[0];vm.runInContext(prefix,context);vm.runInContext(fs.readFileSync('web/isolation-alerts.js','utf8'),context);
const run=code=>vm.runInContext(code,context),tick=()=>new Promise(resolve=>setImmediate(resolve));
const isolation={id:'isolation',time:new Date().toISOString(),read:false,sound:true,continuous:true,isolation_ip:'100.86.221.98',focus:{detector:'direct-siem-isolation'}};
async function main(){
 run("alertSoundAccount='a';alertSoundSettings.enabled=true;alertSoundReady=true");
 payload={notifications:[{...isolation,focus:null,sound:false,title:'Capacidade da coleta'}],cleared:new Date(0).toISOString()};await run('observeIsolationNotifications()');assert.equal(players.length,0,'capacity started isolation siren');
 payload.notifications=[isolation];await run('observeIsolationNotifications()');assert.equal(players.length,1);assert.equal(players[0].paused,false);
 run('setAlertSoundEnabled(false)');assert.equal(players[0].paused,true);await run('observeIsolationNotifications()');assert.equal(players.length,1,'pending isolation bypassed master off');assert.equal(payload.notifications[0].read,false,'mute changed read');
 run('alertSoundSettings.enabled=true');deferPlay=true;const playing=run('playAlertSound("siren")');await tick();run('setAlertSoundEnabled(false)');releasePlay();await playing;assert(players.every(p=>p.paused),'late play revived muted sound');deferPlay=false;
 run("alertSoundSettings.enabled=true;alertOutputDevice='speakers'");deferSink=true;const selecting=run('playAlertSound()');await tick();run('setAlertSoundEnabled(false)');releaseSink();await selecting;assert(players.every(p=>p.paused),'late sink selection revived sound');deferSink=false;
 run("alertOutputDevice='';alertSoundSettings.enabled=true");deferPlay=true;const loop=run('observeIsolationNotifications()');await tick();run('setAlertSoundEnabled(false)');releasePlay();await loop;assert(players.every(p=>p.paused),'late continuous play revived sound');deferPlay=false;
 run('alertSoundSettings.enabled=true');await run('observeIsolationNotifications()');payload.notifications=[{...isolation,read:true}];await run('observeIsolationNotifications()');assert(players.every(p=>p.paused),'read isolation kept playing');
 run("syncAlertSoundSettings('b');alertSoundSettings.enabled=true;alertSoundReady=true");const event={id:'e1',time:new Date().toISOString(),level:15,classification:{critical:true,sound:true}};context.s={email:'b',events:[event]};run('observeCriticalSounds(s)');const before=players.length;context.s.events.push({...event,id:'e2',classification:null});run('observeCriticalSounds(s)');await tick();assert.equal(players.length,before,'unconfigured critical sounded');
 context.s.events.push({...event,id:'e3'});run('observeCriticalSounds(s)');await tick();assert.equal(players.length,before+1,'opt-in fresh event did not play');context.s.events=context.s.events.map(e=>({...e,classification:{critical:false,sound:false}}));run('observeCriticalSounds(s)');assert(players.every(p=>p.paused),'removed rules left current event playing');
 run('alertSoundSettings.enabled=true');listeners.storage[0]({key:'multipla.alert-sound.b',newValue:'{"enabled":false}'});assert.equal(run('alertSoundSettings.enabled'),false);assert(players.every(p=>p.paused));
 assert.equal(payload.notifications[0].read,true);console.log('PASS browser audio mute: capacity silent, master off, async play/sink races, continuous/read, explicit opt-in, deletion and cross-tab mute; no real audio');
}
main().catch(error=>{console.error(error);process.exitCode=1});
