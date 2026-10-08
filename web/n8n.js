'use strict';
let n8nLoaded=false,n8nDirty=false,n8nBusy=false,n8nData=null;
const n8nForm=document.querySelector('#n8n-form');
function n8nModeUI(){
 const own=n8nForm.elements.mode.value==='self_hosted';
 document.querySelector('#n8n-private-field').hidden=!own;
 if(!own)n8nForm.elements.allowed_ip.value='';
}
function n8nButtons(){
 document.querySelector('#n8n-test').disabled=n8nBusy||n8nDirty||!n8nData?.has_token;
 document.querySelector('#n8n-enable').disabled=n8nBusy||n8nDirty||!n8nData?.tested||!!n8nData?.settings.enabled;
 document.querySelector('#n8n-disable').disabled=n8nBusy||!n8nData?.settings.enabled;
 document.querySelector('#n8n-save').disabled=n8nBusy;
 document.querySelector('#n8n-generate').disabled=n8nBusy;
}
async function renderN8N(){
 const data=await api('/api/integrations/n8n');n8nData=data;
 if(!n8nDirty&&!n8nBusy){
  const s=data.settings;
  n8nForm.elements.mode.value=s.mode||'cloud';
  n8nForm.elements.url.value=s.url||'';
  n8nForm.elements.allowed_ip.value=s.allowed_ip||'';
  n8nForm.elements.min_level.value=s.min_level||12;
  n8nLoaded=true;n8nModeUI();
 }
 const s=data.settings;
 document.querySelector('#n8n-status').textContent=(s.enabled?'Ativa':'Desativada')+' · '+(s.status||'Configure para conectar')+' · '+data.pending+' na fila · '+s.delivered+' confirmados · '+s.failed+' não entregues';
 document.querySelector('#n8n-last-success').textContent=s.last_success&&!s.last_success.startsWith('0001')?'Último alerta confirmado: '+date(s.last_success):'Nenhum alerta confirmado';
 document.querySelector('#n8n-token-hint').textContent=data.has_token?'Credencial salva. Deixe o campo vazio para preservá-la.':'Gere um token e cadastre-o no n8n.';
 n8nButtons();
}
n8nForm.addEventListener('input',()=>{n8nDirty=true;n8nButtons()});
n8nForm.elements.mode.addEventListener('change',()=>{n8nModeUI();n8nDirty=true;n8nButtons()});
document.querySelector('#n8n-generate').onclick=()=>{
 const bytes=crypto.getRandomValues(new Uint8Array(32));
 const value=btoa(String.fromCharCode(...bytes)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
 n8nForm.elements.token.value=value;n8nDirty=true;n8nButtons();
 document.querySelector('#n8n-result').textContent='Token gerado. Copie para a credencial Header Auth do n8n e salve a configuração. Gerar um novo token exige atualizar os dois lados.';
};
document.querySelector('#n8n-copy').onclick=async()=>{
 try{const value=n8nForm.elements.token.value;if(!value)throw Error('Gere um token primeiro. O token salvo não pode ser recuperado.');await navigator.clipboard.writeText(value);document.querySelector('#n8n-result').textContent='Token copiado. No n8n, use Name: X-Multipla-Token e Value: o token copiado.'}catch(e){document.querySelector('#n8n-result').textContent=e.message}
};
document.querySelector('#n8n-show').onchange=e=>n8nForm.elements.token.type=e.target.checked?'text':'password';
function n8nInput(enabled){return {mode:n8nForm.elements.mode.value,url:n8nForm.elements.url.value.trim(),allowed_ip:n8nForm.elements.allowed_ip.value.trim(),min_level:Number(n8nForm.elements.min_level.value),enabled,token:n8nForm.elements.token.value}}
async function n8nOperation(task){
 if(n8nBusy)return;n8nBusy=true;n8nButtons();n8nForm.querySelector('fieldset').disabled=true;
 document.querySelector('#n8n-result').textContent='Aguarde…';
 try{await task();document.querySelector('#n8n-result').textContent='Operação concluída.'}catch(e){document.querySelector('#n8n-result').textContent=e.message}
 finally{n8nBusy=false;n8nForm.querySelector('fieldset').disabled=false;await renderN8N().catch(()=>{});n8nButtons()}
}
n8nForm.onsubmit=e=>{e.preventDefault();n8nOperation(async()=>{
 await api('/api/integrations/n8n','PUT',n8nInput(false));
 n8nForm.elements.token.value='';n8nForm.elements.token.type='password';document.querySelector('#n8n-show').checked=false;n8nDirty=false;
})};
document.querySelector('#n8n-test').onclick=()=>n8nOperation(()=>api('/api/integrations/n8n/test','POST',{}));
document.querySelector('#n8n-enable').onclick=()=>n8nOperation(()=>api('/api/integrations/n8n','PUT',n8nInput(true)));
document.querySelector('#n8n-disable').onclick=()=>n8nOperation(async()=>{
 const s=n8nData.settings;
 await api('/api/integrations/n8n','PUT',{mode:s.mode,url:s.url,allowed_ip:s.allowed_ip||'',min_level:s.min_level,enabled:false,token:''});
});
document.querySelector('#n8n-workflow').onclick=async()=>{
 try{const workflow=await api('/api/integrations/n8n/workflow');const blob=new Blob([JSON.stringify(workflow,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='multipla-siem-n8n.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}catch(e){document.querySelector('#n8n-result').textContent=e.message}
};
