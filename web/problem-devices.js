'use strict';
let problemBusy=false;
async function hideProblemEvent(e){
 const answer=prompt('Por quantos dias ocultar esta descrição deste dispositivo e cliente? Digite permanente para ocultar sem prazo. Os alertas continuarão ativos.','7');if(answer===null)return;
 const permanent=answer.trim().toLowerCase()==='permanente',days=Number(answer);if(!permanent&&(!Number.isInteger(days)||days<1||days>3650)){toast('Informe de 1 a 3650 dias ou permanente.');return}
 try{await api('/api/events/'+encodeURIComponent(e.id)+'/hide','POST',{days:permanent?0:days,permanent});await refresh();await refreshProblemDevices()}catch(error){toast(error.message)}
}
async function refreshProblemDevices(){
 if(!snapshot||problemBusy||page!=='overview')return;problemBusy=true;
 try{
  let panel=$('#problem-devices-panel');if(!panel){panel=el('article',undefined,'panel');panel.id='problem-devices-panel';$('#dashboard-grid').before(panel)}
  const data=await api('/api/problem-devices');panel.replaceChildren(el('h2','Dispositivos com problema'),el('p','Repetições e eventos ocultados ficam em uma área separada. A coleta e as notificações críticas continuam ativas.'));
  if(snapshot.group==='superadmin'&&!snapshot.scoped){const label=el('label',undefined,'check'),check=el('input');check.type='checkbox';check.checked=data.automatic;label.append(check,document.createTextNode('Agrupar automaticamente após três repetições em um minuto'));check.onchange=async()=>{try{await api('/api/problem-devices/settings','PUT',{automatic:check.checked})}catch(error){check.checked=!check.checked;toast(error.message)}};panel.append(label)}
  if(!data.groups.length)panel.append(el('p','Nenhum dispositivo agrupado.'));
  for(const group of data.groups){const row=el('article',undefined,'notification-item');row.append(el('strong',group.device+' · '+(group.tenant||'Sem cliente')),el('p',group.description),el('small',group.count+' ocorrências · '+date(group.last)+' · '+(group.permanent?'Oculto permanentemente':group.automatic?'Agrupamento automático':'Oculto até '+date(group.until))));const view=el('button','Ver eventos','secondary');view.onclick=async()=>{try{const records=await api('/api/problem-devices/events?group='+encodeURIComponent(group.key));const dialog=el('dialog',undefined,'notification-dialog'),close=el('button','Fechar','secondary');dialog.append(el('h2',group.device),close);close.onclick=()=>dialog.close();for(const e of records.events)dialog.append(el('p',date(e.time)+' · '+(e.rule||e.message)));if(!records.events.length)dialog.append(el('p','Nenhum registro nas últimas 24 horas. Os primeiros registros anteriores ao agrupamento permanecem no histórico original.'));document.body.append(dialog);dialog.onclose=()=>dialog.remove();dialog.showModal()}catch(error){toast(error.message)}};row.append(view);if(snapshot.role!=='viewer'){const undo=el('button','Encerrar agrupamento / voltar a exibir','secondary');undo.onclick=async()=>{try{await api('/api/problem-devices/'+encodeURIComponent(group.key),'DELETE');await refreshProblemDevices();await refresh()}catch(error){toast(error.message)}};row.append(undo)}panel.append(row)}
 }catch(error){const panel=$('#problem-devices-panel');if(panel)panel.replaceChildren(el('h2','Dispositivos com problema'),el('p',error.message))}finally{problemBusy=false}
}
setInterval(()=>{if(document.visibilityState==='visible')refreshProblemDevices()},5000);
