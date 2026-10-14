'use strict';
if(window.multiplaNativeAudio===true&&window.chrome?.webview){
 const native=window.chrome.webview;
 const send=(action,extra={})=>native.postMessage({type:'multipla.audio.request',action,...extra});
 const configure=()=>send('configure',{enabled:$('#alert-sound-enabled').checked,volume:Number($('#alert-sound-volume').value),sound:$('#alert-sound-choice').value});
 alertOutputChoose.disabled=false;alertOutputChoose.textContent='Escolher saída no Windows';alertOutputHelp.textContent='Saídas do Windows para os alertas do aplicativo, incluindo os recebidos na bandeja. Não requer acesso ao microfone. O som desta página é reproduzido pelo app.';
 alertOutputChoose.onclick=()=>send('choose');alertOutputSelect.disabled=false;alertOutputSelect.onchange=()=>send('select',{device:alertOutputSelect.value});
 $('#alert-sound-enabled').onchange=configure;$('#alert-sound-choice').onchange=configure;$('#alert-sound-volume').onchange=configure;
 $('#alert-sound-test').onclick=()=>send('test');$('#alert-sound-stop').onclick=()=>send('stop');
 native.addEventListener('message',event=>{const data=event.data;if(data?.type!=='multipla.audio.state'||!Array.isArray(data.outputs))return;alertOutputSelect.replaceChildren();for(const output of data.outputs){const option=el('option',output.label);option.value=output.id;alertOutputSelect.append(option)}alertOutputSelect.value=data.selected;$('#alert-sound-enabled').checked=data.enabled;$('#alert-sound-volume').value=data.volume;$('#alert-sound-choice').value=data.sound;alertSoundStatus(data.error||'Áudio do aplicativo configurado. Use Testar e habilitar áudio para conferir a saída.');});
 send('outputs');
}
