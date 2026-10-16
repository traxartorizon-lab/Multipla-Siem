'use strict';
if(isNativeAudioHost()){
 let connected=false;
 window.multiplaNativeAudioConfirmed=false;
 const native=window.chrome.webview;
 const send=(action,extra={})=>native.postMessage({type:'multipla.audio.request',action,...extra});
 const retry=()=>send('outputs');
 const configure=()=>{alertSoundSettings.enabled=$('#alert-sound-enabled').checked;if(!alertSoundSettings.enabled)stopAlertSound();if(typeof syncEventSoundButton==='function')syncEventSoundButton();send('configure',{enabled:$('#alert-sound-enabled').checked,volume:Number($('#alert-sound-volume').value),sound:$('#alert-sound-choice').value})};
 alertOutputChoose.disabled=false;alertOutputChoose.textContent='Escolher saída no Windows';alertOutputHelp.textContent='Saídas do Windows para os alertas do aplicativo, incluindo os recebidos na bandeja. Não requer acesso ao microfone. O som desta página é reproduzido pelo app.';
 alertOutputChoose.onclick=()=>{if(connected)send('choose');else{retry();alertSoundStatus('Tentando conectar ao áudio do aplicativo…');}};alertOutputSelect.disabled=false;alertOutputSelect.onchange=()=>send('select',{device:alertOutputSelect.value});
 $('#alert-sound-enabled').onchange=configure;$('#alert-sound-choice').onchange=configure;$('#alert-sound-volume').onchange=configure;
 $('#alert-sound-test').onclick=()=>send('test');$('#alert-sound-stop').onclick=()=>send('stop');
 native.addEventListener('message',event=>{const data=event.data;if(data?.type!=='multipla.audio.state'||!Array.isArray(data.outputs))return;connected=true;window.multiplaNativeAudioConfirmed=true;alertOutputChoose.textContent='Escolher saída no Windows';alertOutputSelect.disabled=false;alertOutputSelect.replaceChildren();for(const output of data.outputs){const option=el('option',output.label);option.value=output.id;alertOutputSelect.append(option)}alertOutputSelect.value=data.selected;alertSoundSettings.enabled=data.enabled===true;alertSoundSettings.sound=data.sound;alertSoundSettings.volume=data.volume;$('#alert-sound-enabled').checked=data.enabled;if(!data.enabled)stopAlertSound();$('#alert-sound-volume').value=data.volume;$('#alert-sound-choice').value=data.sound;alertSoundStatus(data.error||'Áudio do aplicativo configurado. Use Testar e habilitar áudio para conferir a saída.');});
 retry();setTimeout(()=>{if(!connected)retry()},350);setTimeout(()=>{if(!connected)retry()},1100);
 setTimeout(()=>{if(connected)return;alertOutputSelect.disabled=true;alertOutputChoose.textContent='Reconectar áudio do aplicativo';alertSoundStatus('A ponte de áudio do app não respondeu. Atualize e reinicie o aplicativo. Como alternativa, use Servidor, vínculo e áudio → Saída da sirene do app. Nenhuma permissão de microfone é necessária.');},3000);
}
