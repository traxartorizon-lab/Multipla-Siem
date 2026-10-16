'use strict';
let isolationPlayer=null,isolationBusy=false,isolationEpoch=0;
function stopIsolationSound(){isolationEpoch++;if(isolationPlayer){isolationPlayer.pause();isolationPlayer=null}}
async function releaseIsolatedDevice(event){if(!confirm('Liberar a comunicação deste dispositivo no firewall do SIEM? Ler o alerta não remove o isolamento.'))return;try{const result=await api('/api/isolation/release','POST',{id:event.id,ip:event.source_ip});toast(result.message)}catch(error){toast(error.message)}}
async function observeIsolationNotifications(){
 if(!snapshot||isolationBusy)return;isolationBusy=true;const account=alertSoundAccount;
 try{
  const data=await api('/api/notifications');if(account!==alertSoundAccount)return;const urgent=data.notifications.some(n=>n.sound===true&&n.continuous&&n.isolation_ip&&n.focus?.detector==='direct-siem-isolation'&&!n.read&&Date.parse(n.time)>Date.parse(data.cleared));$('#host-health-button').classList.toggle('isolation-pending',urgent);
  if(!urgent||!alertSoundSettings.enabled||isNativeAudioHost()){stopIsolationSound();return}
  if(!isolationPlayer&&alertSoundReady){const epoch=++isolationEpoch,player=new Audio(alertSoundFiles.siren);isolationPlayer=player;player.loop=true;player.volume=alertSoundSettings.volume/100;if(alertOutputDevice){if(typeof player.setSinkId!=='function')throw Error('Saída não suportada');await player.setSinkId(alertOutputDevice)}if(epoch!==isolationEpoch||!alertSoundSettings.enabled)return;await player.play();if(epoch!==isolationEpoch||!alertSoundSettings.enabled){player.pause();return}}
  if(!alertSoundReady)alertSoundStatus('Dispositivo isolado. Clique em Testar e habilitar áudio para permitir a sirene contínua. Marque a notificação como lida para encerrá-la.');
 }catch(error){stopIsolationSound()}finally{isolationBusy=false}
}
setInterval(()=>observeIsolationNotifications(),3000);
window.addEventListener('pagehide',stopIsolationSound);
