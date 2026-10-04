'use strict';
let receiverSources=[],receiverEditing=-1;
async function renderReceivers(force=false){
 const data=await api('/api/receivers'),settings=data.settings;
 const host=new URL(snapshot.config.public_url).hostname;$('#syslog-address').textContent='Destino nos equipamentos: '+host+' · porta '+data.syslog_address.split(':').pop()+' · TCP e UDP';
 $('#snmp-address').textContent='Destino dos traps: '+host+' · porta '+data.snmp_address.split(':').pop()+' · UDP';
 $('#snmp-status').textContent=data.snmp_status||'Receptor iniciando';
 $('#webhook-url').textContent='Entrada: '+location.origin+'/api/events/webhook';
 $('#webhook-status').textContent='Último envio: '+(data.outbound_status||'sem tentativas');
 if(force||(!$('#snmp-source-form').contains(document.activeElement)&&document.activeElement!==$('#snmp-enabled'))){
  receiverSources=settings.snmp_sources||[];
  $('#snmp-enabled').checked=settings.snmp_enabled;
  table('#snmp-source-list',['NOME','IP','MODO','ENGINE ID','ÚLTIMO EVENTO','AÇÃO'],receiverSources.map((source,i)=>[source.name,source.ip,source.version,source.engine_id||'—',snapshot.last_seen["SNMP · "+source.name]?date(snapshot.last_seen["SNMP · "+source.name]):'Aguardando',sourceActions(source,i)]));
 }
 const form=$('#webhook-form');
 if(!form.contains(document.activeElement)){
  ['inbound_enabled','outbound_enabled'].forEach(key=>form.elements[key].checked=settings[key]);
  ['outbound_url','outbound_allowed_ip'].forEach(key=>form.elements[key].value=settings[key]||'');
  form.elements.inbound_ips.value=(settings.inbound_ips||[]).join('\n');
  form.elements.outbound_min_level.value=settings.outbound_min_level||10;
 }
}
async function saveSNMP(sources){
 await api('/api/receivers/snmp','PUT',{enabled:$('#snmp-enabled').checked,sources});
 await renderReceivers(true);toast('Origens SNMP salvas');
}
$('#snmp-save').onclick=()=>run(()=>saveSNMP(receiverSources));
$('#snmp-source-form').onsubmit=async event=>{
 event.preventDefault();const form=event.target,data=Object.fromEntries(new FormData(form));
 try{const sources=receiverSources.slice();if(receiverEditing>=0)sources[receiverEditing]=data;else sources.push(data);await saveSNMP(sources);receiverEditing=-1;form.reset();await renderReceivers(true)}catch(error){toast(error.message)}
};
$('#webhook-form').onsubmit=async event=>{
 event.preventDefault();const form=event.target;
 try{
  const result=await api('/api/receivers/webhook','PUT',{
   inbound_enabled:form.elements.inbound_enabled.checked,
   inbound_ips:form.elements.inbound_ips.value.split('\n').map(value=>value.trim()).filter(Boolean),
   rotate_token:form.elements.rotate_token.checked,
   outbound_enabled:form.elements.outbound_enabled.checked,
   outbound_url:form.elements.outbound_url.value,
   outbound_allowed_ip:form.elements.outbound_allowed_ip.value.trim(),
   outbound_min_level:Number(form.elements.outbound_min_level.value),
   outbound_secret:form.elements.outbound_secret.value
  });
  form.elements.outbound_secret.value='';form.elements.rotate_token.checked=false;
  if(result.token)$('#webhook-generated-token').textContent='Guarde este token de entrada; ele não será exibido novamente:\n'+result.token;
  await renderReceivers(true);toast('Webhooks salvos');
 }catch(error){toast(error.message)}
};

function sourceActions(source,index){const buttons=el('div');buttons.append(action('Editar',()=>{receiverEditing=index;const form=$('#snmp-source-form');form.reset();for(const key of ['name','ip','version','user','engine_id'])form.elements[key].value=source[key]||'';form.elements.name.focus();toast('Informe apenas os segredos que deseja alterar. Deixe todos vazios para preservar as credenciais.')}),action('Remover',()=>run(async()=>{await saveSNMP(receiverSources.filter((_,i)=>i!==index));receiverEditing=-1})));return buttons}
