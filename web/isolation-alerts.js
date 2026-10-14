'use strict';
let isolationPlayer=null,isolationBusy=false;
async function releaseIsolatedDevice(event){if(!confirm('Liberar a comunicação deste dispositivo no firewall do SIEM? Ler o alerta não remove o isolamento.'))return;try{const result=await api('/api/isolation/release','POST',{id:event.id,ip:event.source_ip});toast(result.message)}catch(error){toast(error.message)}}
async function observeIsolationNotifications(){
 if(!snapshot||isolationBusy)return;isolationBusy=true;
 try{
  const data=await api('/api/notifications'),urgent=data.notifications.some(n=>n.continuous&&!n.read&&Date.parse(n.time)>Date.parse(data.cleared));$('#host-health-button').classList.toggle('isolation-pending',urgent);
  if(!urgent){if(isolationPlayer){isolationPlayer.pause();isolationPlayer=null}return}
  if(!window.multiplaNativeAudio&&!isolationPlayer&&alertSoundReady){const player=new Audio(alertSoundFiles.siren);player.loop=true;player.volume=alertSoundSettings.volume/100;if(alertOutputDevice){if(typeof player.setSinkId!=='function')throw Error('Saída não suportada');await player.setSinkId(alertOutputDevice)}await player.play();isolationPlayer=player}
  if(!alertSoundReady)alertSoundStatus('Dispositivo isolado. Clique em Testar e habilitar áudio para permitir a sirene contínua. Marque a notificação como lida para encerrá-la.');
 }catch(error){if(isolationPlayer){isolationPlayer.pause();isolationPlayer=null}}finally{isolationBusy=false}
}
setInterval(()=>observeIsolationNotifications(),3000);
window.addEventListener('pagehide',()=>{isolationPlayer?.pause();isolationPlayer=null});
