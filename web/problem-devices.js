'use strict';
let problemBusy=false,problemDialog=null;
async function hideProblemEvent(e){
 const answer=prompt('Por quantos dias ocultar esta descrição deste dispositivo e cliente? Digite permanente para ocultar sem prazo. Os alertas continuarão ativos.','7');if(answer===null)return;
 const permanent=answer.trim().toLowerCase()==='permanente',days=Number(answer);if(!permanent&&(!Number.isInteger(days)||days<1||days>3650)){toast('Informe de 1 a 3650 dias ou permanente.');return}
 try{await api('/api/events/'+encodeURIComponent(e.id)+'/hide','POST',{days:permanent?0:days,permanent});await refresh();await refreshProblemDevices()}catch(error){toast(error.message)}
}
async function refreshProblemDevices(){
 // Compact, on-demand entry. No problem panel is mounted on the overview.
 if(!snapshot)return;$('#problem-devices-panel')?.remove();
 let button=$('#problem-devices-open');if(!button){button=el('button','Dispositivos com problema','secondary');button.id='problem-devices-open';button.type='button';$('#events .page-heading').append(button);button.onclick=()=>openProblemDevices()}
 if(!problemDialog?.open||problemBusy)return;problemBusy=true;
 try{const data=await api('/api/problem-devices'),body=problemDialog.querySelector('.problem-groups');body.replaceChildren(el('p','Dia UTC: recebimentos 1–19 permanecem no histórico global; do 20º em diante, este grupo guarda somente os últimos 20 recebimentos. Derivações não somam ocorrências. Detecção, notificações e ações de segurança continuam ativas. A janela exportada pode conter recebimentos que também constam no arquivo global anterior.'));
  if(snapshot.group==='superadmin'&&!snapshot.scoped){const label=el('label',undefined,'check'),check=el('input');check.type='checkbox';check.checked=data.automatic;label.append(check,document.createTextNode('Agrupar automaticamente a partir do 20º recebimento diário (UTC)'));check.onchange=async()=>{try{await api('/api/problem-devices/settings','PUT',{automatic:check.checked})}catch(error){check.checked=!check.checked;toast(error.message)}};body.append(label)}
  if(!data.groups.length)body.append(el('p','Nenhum grupo ativo.'));
  for(const g of data.groups){const row=el('article',undefined,'notification-item');row.append(el('strong',(g.tenant||'Sem cliente')+' · '+g.device),el('p',g.description),el('small',g.count+' recebimentos · '+(g.suppressed||0)+' fora do global · dia UTC '+(g.day||'anterior')),el('small','Primeiro: '+date(g.first)+' · último: '+date(g.last)),el('small',g.permanent?'Oculto permanentemente':g.automatic?'Agrupamento automático':'Oculto até '+date(g.until)));
   const view=el('button','Ver últimos 20','secondary');view.onclick=()=>viewProblemGroup(g);row.append(view);
   if(snapshot.role!=='viewer'){const undo=el('button','Voltar a exibir','secondary');undo.onclick=async()=>{try{await api('/api/problem-devices/'+encodeURIComponent(g.key),'DELETE');await refreshProblemDevices();await refresh()}catch(error){toast(error.message)}};row.append(undo)}body.append(row)}
 }catch(error){problemDialog?.querySelector('.problem-groups')?.replaceChildren(el('p',error.message))}finally{problemBusy=false}
}
async function openProblemDevices(){if(problemDialog?.open){problemDialog.focus();return}problemDialog=el('dialog',undefined,'notification-dialog problem-devices-dialog');const close=el('button','Fechar','secondary'),body=el('div',undefined,'problem-groups');problemDialog.append(el('h2','Dispositivos com problema'),close,body);close.onclick=()=>problemDialog.close();problemDialog.onclose=()=>{problemDialog.remove();problemDialog=null};document.body.append(problemDialog);problemDialog.showModal();await refreshProblemDevices()}
async function viewProblemGroup(group){try{const records=await api('/api/problem-devices/events?group='+encodeURIComponent(group.key));const dialog=el('dialog',undefined,'notification-dialog'),close=el('button','Fechar','secondary'),link=el('a','Exportar janela JSONL');link.href='/api/problem-devices/events?group='+encodeURIComponent(group.key)+'&export=1';dialog.append(el('h2',group.device+' · últimos 20 recebimentos'),close,link);close.onclick=()=>dialog.close();for(const e of records.events)dialog.append(el('p',date(e.time)+' · '+(e.rule||e.message)));if(!records.events.length)dialog.append(el('p','Nenhum recebimento nesta janela.'));document.body.append(dialog);dialog.onclose=()=>dialog.remove();dialog.showModal()}catch(error){toast(error.message)}}
setInterval(()=>{if(document.visibilityState==='visible')refreshProblemDevices()},5000);
refreshProblemDevices();
