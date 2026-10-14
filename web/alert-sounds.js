'use strict';
const alertSoundFiles={beep:'/audio/alert-beep.ogg',siren:'/audio/alert-siren.ogg'};
let alertSoundAccount='',alertSoundSettings={enabled:false,sound:'beep',volume:40},alertSoundSeen=new Set(),alertSoundPrimed=false,alertSoundReady=false,alertSoundPlayer=null,alertSoundStopTimer;
function alertSoundStatus(message){$('#alert-sound-status').textContent=message;if(typeof syncEventSoundButton==='function')syncEventSoundButton()}
function saveAlertSoundSettings(){try{localStorage.setItem('multipla.alert-sound.'+alertSoundAccount,JSON.stringify(alertSoundSettings))}catch{alertSoundStatus('Não foi possível salvar a preferência neste navegador.')}}
function syncAlertSoundSettings(account){
 if(window.multiplaNativeAudio){alertSoundAccount=account;return;}
 if(account===alertSoundAccount)return;stopAlertSound();alertSoundAccount=account;alertSoundReady=false;alertSoundPrimed=false;alertSoundSeen.clear();alertSoundSettings={enabled:false,sound:'beep',volume:40};
 try{const p=JSON.parse(localStorage.getItem('multipla.alert-sound.'+account)||'null');if(p)alertSoundSettings={enabled:p.enabled===true,sound:Object.hasOwn(alertSoundFiles,p.sound)?p.sound:'beep',volume:Number.isInteger(p.volume)&&p.volume>=0&&p.volume<=100?p.volume:40}}catch{}
 $('#alert-sound-enabled').checked=alertSoundSettings.enabled;$('#alert-sound-choice').value=alertSoundSettings.sound;$('#alert-sound-volume').value=alertSoundSettings.volume;
 alertSoundStatus(alertSoundSettings.enabled?'Clique em Testar e habilitar áudio para permitir a reprodução nesta sessão.':'Alerta sonoro desativado.');
}
function stopAlertSound(){clearTimeout(alertSoundStopTimer);if(alertSoundPlayer){alertSoundPlayer.pause();alertSoundPlayer.currentTime=0;alertSoundPlayer=null}}
async function playAlertSound(sound=alertSoundSettings.sound){
 if(window.multiplaNativeAudio){alertSoundStatus("No app, o áudio usa a saída do Windows configurada acima.");return;}
 stopAlertSound();const player=new Audio(alertSoundFiles[sound]);alertSoundPlayer=player;player.volume=alertSoundSettings.volume/100;
 try{if(alertOutputDevice){if(typeof player.setSinkId!=='function')throw new Error('Saída não suportada');await player.setSinkId(alertOutputDevice)}if(alertSoundPlayer!==player)return;await player.play();alertSoundReady=true;alertSoundStatus('Áudio disponível nesta sessão.');alertSoundStopTimer=setTimeout(()=>{if(alertSoundPlayer===player)stopAlertSound()},4000)}catch{alertSoundReady=false;alertSoundStatus(alertOutputDevice?'Não foi possível usar a saída selecionada. Selecione novamente a saída de áudio.':'Reprodução bloqueada ou indisponível. Clique em Testar e habilitar áudio.')}
}
function observeCriticalSounds(s){
 if(window.multiplaNativeAudio)return;
 syncAlertSoundSettings(s.email);observeInvasionAlerts(s);let found=false,chosenSound=alertSoundSettings.sound;const now=Date.now();
 for(const event of [...(s.events||[]),...(s.critical_events||[])]){const critical=event.classification?.critical!==false&&event.review?.status!=='false_positive'&&(Number(event.review?.level||event.level)>=12||!!event.diagnosis);if(!critical||!event.id||event.detector==='ssh-login-burst')continue;
  if(!alertSoundSeen.has(event.id)){alertSoundSeen.add(event.id);if(alertSoundPrimed&&Date.parse(event.time)>=now-120000&&event.classification?.sound!==false){found=true;chosenSound=event.classification?.sound_type||alertSoundSettings.sound}}
 }
 alertSoundPrimed=true;if(alertSoundSeen.size>4000)alertSoundSeen=new Set([...alertSoundSeen].slice(-2000));
 if(!found||!alertSoundSettings.enabled)return;if(!alertSoundReady){alertSoundStatus('Novo evento crítico. Habilite o áudio pelo botão de teste.');return}
 try{const key='multipla.alert-sound.last.'+s.email,last=Number(localStorage.getItem(key)||0);if(now-last<10000)return;localStorage.setItem(key,String(now))}catch{}
 playAlertSound(chosenSound);
}
$('#alert-sound-enabled').onchange=event=>{alertSoundSettings.enabled=event.target.checked;saveAlertSoundSettings();if(event.target.checked)playAlertSound();else{stopAlertSound();alertSoundStatus('Alerta sonoro desativado.')}};
$('#alert-sound-choice').onchange=event=>{alertSoundSettings.sound=event.target.value;saveAlertSoundSettings()};
$('#alert-sound-volume').oninput=event=>{alertSoundSettings.volume=Number(event.target.value);saveAlertSoundSettings()};
$('#alert-sound-test').onclick=()=>playAlertSound();
$('#alert-sound-stop').onclick=()=>stopAlertSound();
window.addEventListener('pagehide',stopAlertSound);

// Audio hardware belongs to this browser/computer, never to the SIEM server.
let alertOutputDevice='';
try{alertOutputDevice=localStorage.getItem('multipla.alert-output')||''}catch{}
const alertOutputLabel=el('label','Saída de áudio dos alertas'),alertOutputSelect=el('select'),alertOutputChoose=el('button','Escolher saída de áudio','secondary'),alertOutputHelp=el('small','Escolha caixas de som ou outra saída disponível neste computador. A preferência vale somente neste navegador.');
alertOutputSelect.setAttribute('aria-label','Saída de áudio dos alertas');alertOutputChoose.type='button';alertOutputLabel.append(alertOutputSelect);$('#alert-sound-choice').closest('label').after(alertOutputLabel,alertOutputChoose,alertOutputHelp);
function saveAlertOutput(id){stopAlertSound();alertOutputDevice=id;try{localStorage.setItem('multipla.alert-output',id)}catch{}alertSoundStatus('Saída alterada. Clique em Testar e habilitar áudio para conferir.')}
async function refreshAlertOutputs(){
 if(window.multiplaNativeAudio)return;
 alertOutputSelect.replaceChildren();const standard=el('option','Padrão do sistema');standard.value='';alertOutputSelect.append(standard);
 if(typeof HTMLMediaElement.prototype.setSinkId!=='function'){alertOutputSelect.disabled=true;alertOutputChoose.disabled=true;alertOutputHelp.textContent='Este navegador não permite escolher a saída pelo SIEM. Use o mixer de volume do sistema para direcionar o navegador às caixas de som.';return}
 try{const devices=await navigator.mediaDevices.enumerateDevices();let index=0;for(const device of devices.filter(d=>d.kind==='audiooutput'&&d.deviceId&&d.deviceId!=='default')){const option=el('option',device.label||'Saída de áudio '+(++index));option.value=device.deviceId;alertOutputSelect.append(option)}}catch{}
 if(alertOutputDevice&&!Array.from(alertOutputSelect.options).some(o=>o.value===alertOutputDevice)){const saved=el('option','Saída salva — selecione novamente se indisponível');saved.value=alertOutputDevice;alertOutputSelect.append(saved)}alertOutputSelect.value=alertOutputDevice;
 if(typeof navigator.mediaDevices?.selectAudioOutput!=='function'){alertOutputChoose.textContent='Autorizar lista de saídas';alertOutputChoose.disabled=typeof navigator.mediaDevices?.getUserMedia!=='function';alertOutputHelp.textContent='No Chrome/Edge, listar saídas pode exigir permissão de microfone. Clique em Autorizar lista de saídas: o acesso será encerrado imediatamente, sem gravar nem enviar áudio. Depois escolha a saída acima. Você pode usar o mixer do sistema se preferir não autorizar.'}
}
alertOutputSelect.onchange=()=>saveAlertOutput(alertOutputSelect.value);
alertOutputChoose.onclick=async()=>{
 alertOutputChoose.disabled=true;
 try{
  if(typeof navigator.mediaDevices?.selectAudioOutput==='function'){const device=await navigator.mediaDevices.selectAudioOutput({deviceId:alertOutputDevice});saveAlertOutput(device.deviceId)}
  else {const stream=await navigator.mediaDevices.getUserMedia({audio:true,video:false});stream.getTracks().forEach(track=>track.stop());alertSoundStatus('Permissão concedida. Escolha a saída de áudio e clique em Testar e habilitar áudio.')}
  await refreshAlertOutputs();alertOutputSelect.focus();
 }catch{alertSoundStatus('Permissão cancelada ou indisponível. Confira a permissão de microfone do site ou use o mixer do sistema.')}
 finally{if(typeof HTMLMediaElement.prototype.setSinkId==='function')alertOutputChoose.disabled=false}
};
if(!window.multiplaNativeAudio){navigator.mediaDevices?.addEventListener('devicechange',refreshAlertOutputs);refreshAlertOutputs();}

let invasionAccount='',invasionSeen=new Set(),invasionPopup=null;
function observeInvasionAlerts(s){
 if(invasionAccount!==s.email){invasionAccount=s.email;invasionSeen.clear();invasionPopup?.remove();invasionPopup=null}
 const alerts=[...(s.events||[]),...(s.critical_events||[])].filter(e=>e.detector==='ssh-login-burst'&&e.classification?.critical!==false&&e.review?.status!=='false_positive'&&Date.parse(e.time)>Date.now()-120000).sort((a,b)=>Date.parse(a.time)-Date.parse(b.time));
 for(const e of alerts){if(!e.id||invasionSeen.has(e.id))continue;invasionSeen.add(e.id);showInvasionAlert(e)}
 if(invasionSeen.size>1000)invasionSeen=new Set([...invasionSeen].slice(-500));
}
function showInvasionAlert(event){
 invasionPopup?.remove();const popup=el('section',undefined,'invasion-alert'),heading=el('h2','POSSIVEL TENTATIVA DE INVASAO'),buttons=el('div',undefined,'toolbar');invasionPopup=popup;
 popup.setAttribute('role','alertdialog');popup.setAttribute('aria-modal','false');popup.setAttribute('aria-label','POSSIVEL TENTATIVA DE INVASAO');
 popup.append(el('div','ALERTA GLOBAL · SSH','invasion-eyebrow'),heading,el('p','Detectadas 10 falhas de autenticação do mesmo IP em menos de 1 minuto.'),el('strong','IP de origem: '+(event.source_ip||'—')),el('p','Último dispositivo: '+event.device+' · '+date(event.time)),el('small','Tentativas repetidas não comprovam invasão. Investigue os registros e acessos bem-sucedidos relacionados.'));
 const status=el('p',undefined,'invasion-audio-status'),view=el('button','Ver eventos'),stop=el('button','Parar sirene','secondary'),enable=el('button','Habilitar sirene','secondary'),close=el('button','Fechar aviso','secondary');
 view.onclick=()=>{openEventFocus(event.id);popup.remove();invasionPopup=null;stopAlertSound()};stop.onclick=()=>{stopAlertSound();status.textContent='Sirene interrompida.'};close.onclick=()=>{popup.remove();invasionPopup=null;stopAlertSound()};
 enable.onclick=async()=>{alertSoundSettings.enabled=true;$('#alert-sound-enabled').checked=true;saveAlertSoundSettings();await playAlertSound('siren');status.textContent=alertSoundReady?'Sirene habilitada.':'O navegador bloqueou o áudio; confira as permissões.'};
 buttons.append(view,stop,enable,close);popup.append(status,buttons);document.body.append(popup);
 if(event.classification?.sound!==false&&alertSoundSettings.enabled&&alertSoundReady){playAlertSound(event.classification?.sound_type||'siren');status.textContent='Sirene de alerta acionada.'}else status.textContent='Para ouvir a sirene, habilite o áudio neste navegador.';
}
