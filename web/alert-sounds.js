'use strict';
const alertSoundFiles={beep:'/audio/alert-beep.ogg',siren:'/audio/alert-siren.ogg'};
let alertSoundAccount='',alertSoundSettings={enabled:false,sound:'beep',volume:40},alertSoundSeen=new Set(),alertSoundPrimed=false,alertSoundReady=false,alertSoundPlayer=null,alertSoundStopTimer;
function alertSoundStatus(message){$('#alert-sound-status').textContent=message;if(typeof syncEventSoundButton==='function')syncEventSoundButton()}
function saveAlertSoundSettings(){try{localStorage.setItem('multipla.alert-sound.'+alertSoundAccount,JSON.stringify(alertSoundSettings))}catch{alertSoundStatus('Não foi possível salvar a preferência neste navegador.')}}
function syncAlertSoundSettings(account){
 if(account===alertSoundAccount)return;stopAlertSound();alertSoundAccount=account;alertSoundReady=false;alertSoundPrimed=false;alertSoundSeen.clear();alertSoundSettings={enabled:false,sound:'beep',volume:40};
 try{const p=JSON.parse(localStorage.getItem('multipla.alert-sound.'+account)||'null');if(p)alertSoundSettings={enabled:p.enabled===true,sound:Object.hasOwn(alertSoundFiles,p.sound)?p.sound:'beep',volume:Number.isInteger(p.volume)&&p.volume>=0&&p.volume<=100?p.volume:40}}catch{}
 $('#alert-sound-enabled').checked=alertSoundSettings.enabled;$('#alert-sound-choice').value=alertSoundSettings.sound;$('#alert-sound-volume').value=alertSoundSettings.volume;
 alertSoundStatus(alertSoundSettings.enabled?'Clique em Testar e habilitar áudio para permitir a reprodução nesta sessão.':'Alerta sonoro desativado.');
}
function stopAlertSound(){clearTimeout(alertSoundStopTimer);if(alertSoundPlayer){alertSoundPlayer.pause();alertSoundPlayer.currentTime=0;alertSoundPlayer=null}}
async function playAlertSound(){
 stopAlertSound();const player=new Audio(alertSoundFiles[alertSoundSettings.sound]);alertSoundPlayer=player;player.volume=alertSoundSettings.volume/100;
 try{await player.play();alertSoundReady=true;alertSoundStatus('Áudio disponível nesta sessão.');alertSoundStopTimer=setTimeout(()=>{if(alertSoundPlayer===player)stopAlertSound()},4000)}catch{alertSoundReady=false;alertSoundStatus('Reprodução bloqueada ou indisponível. Clique em Testar e habilitar áudio.')}
}
function observeCriticalSounds(s){
 syncAlertSoundSettings(s.email);let found=false;const now=Date.now();
 for(const event of [...(s.events||[]),...(s.critical_events||[])]){const critical=event.classification?.critical!==false&&event.review?.status!=='false_positive'&&(Number(event.review?.level||event.level)>=12||!!event.diagnosis);if(!critical||!event.id)continue;
  if(!alertSoundSeen.has(event.id)){alertSoundSeen.add(event.id);if(alertSoundPrimed&&Date.parse(event.time)>=now-120000&&event.classification?.sound!==false)found=true}
 }
 alertSoundPrimed=true;if(alertSoundSeen.size>4000)alertSoundSeen=new Set([...alertSoundSeen].slice(-2000));
 if(!found||!alertSoundSettings.enabled)return;if(!alertSoundReady){alertSoundStatus('Novo evento crítico. Habilite o áudio pelo botão de teste.');return}
 try{const key='multipla.alert-sound.last.'+s.email,last=Number(localStorage.getItem(key)||0);if(now-last<10000)return;localStorage.setItem(key,String(now))}catch{}
 playAlertSound();
}
$('#alert-sound-enabled').onchange=event=>{alertSoundSettings.enabled=event.target.checked;saveAlertSoundSettings();if(event.target.checked)playAlertSound();else{stopAlertSound();alertSoundStatus('Alerta sonoro desativado.')}};
$('#alert-sound-choice').onchange=event=>{alertSoundSettings.sound=event.target.value;saveAlertSoundSettings()};
$('#alert-sound-volume').oninput=event=>{alertSoundSettings.volume=Number(event.target.value);saveAlertSoundSettings()};
$('#alert-sound-test').onclick=()=>playAlertSound();
$('#alert-sound-stop').onclick=()=>stopAlertSound();
window.addEventListener('pagehide',stopAlertSound);
