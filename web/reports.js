'use strict';
let currentReport=null,currentReportQuery='';
const reportSeverityLabels={critical:'Crítico',high:'Alto',medium:'Médio',low:'Baixo',log:'Log sem nível'};
function renderReportDevices(){
 const select=$('#report-device'),selected=select.value;select.replaceChildren(new Option('Todos os dispositivos',''));
 const names=[...new Set([...(snapshot?.config?.devices||[]),...(snapshot?.snmp_devices||[])].map(d=>d.name))];names.sort().forEach(name=>select.append(new Option(name,name)));select.value=names.includes(selected)?selected:'';
 const form=$('#report-form'),today=new Date().toISOString().slice(0,10);if(!form.elements.start.value)form.elements.start.value=today;if(!form.elements.end.value)form.elements.end.value=today;
}
$('#report-form').onsubmit=async e=>{
 e.preventDefault();const f=new FormData(e.target),q=new URLSearchParams();
 ['start','end','type','severity','kind','source_ip'].forEach(k=>q.set(k,String(f.get(k)||'').trim()));q.set('device',String(f.get('historical_device')||f.get('device')||'').trim());
 $('#report-generate').disabled=true;$('#report-status').textContent='Consultando o histórico armazenado…';
 try{const report=await api('/api/reports?'+q.toString());currentReport=report;currentReportQuery=q.toString();renderEventReport(report);['pdf','json','csv'].forEach(k=>$('#report-'+k).disabled=false)}
 catch(error){$('#report-status').textContent='Não foi possível gerar o relatório. Os resultados anteriores, se houver, continuam com seus filtros originais.';toast(error.message)}
 finally{$('#report-generate').disabled=false}
};
function renderEventReport(r){
 $('#report-document').classList.remove('hidden');const f=r.filter;
 $('#report-filter-summary').textContent='Período UTC: '+f.start+' a '+f.end+' · Dispositivo: '+(f.device||'Todos')+' · Nível: '+(reportSeverityLabels[f.severity]||'Todos')+' · Registros: '+(f.type==='alerts'?'Alertas':f.type==='logs'?'Logs originais':'Logs e alertas')+' · Origem: '+({infrastructure:'pfSense e Proxmox',pfsense:'pfSense',proxmox:'Proxmox',snmp:'SNMP',webhook:'Webhook',wazuh:'Wazuh'}[f.kind]||f.kind||'Todas')+' · IP de origem: '+(f.source_ip||'Todos')+' · Gerado em '+new Date(r.generated).toLocaleString('pt-BR');
 $('#report-summary').textContent=r.matched+' registros selecionados · '+r.originals+' logs originais · '+r.alerts+' alertas · '+r.critical+' críticos';
 const notes=[];if(r.partial)notes.push('RELATÓRIO PARCIAL: limite de leitura de 64 MiB ou 20 segundos atingido. Reduza o período.');if(r.missing_days?.length)notes.push('Sem arquivo disponível nestas datas: '+r.missing_days.join(', ')+'. Isso pode indicar retenção vencida ou ausência de coleta.');if(r.invalid)notes.push(r.invalid+' linhas inválidas ignoradas.');
 notes.push('Os totais representam os registros lidos. A tabela, o CSV e o PDF exibem até 1.000 registros, em ordem cronológica por arquivo. Logs originais e alertas derivados são contados separadamente.');
 $('#report-limits').textContent=notes.join(' ');$('#report-status').textContent=r.partial?'Relatório parcial gerado; consulte a indicação de limites.':'Relatório gerado: '+r.scanned+' registros consultados.';
 table('#report-by-device',['DISPOSITIVO','REGISTROS'],Object.entries(r.by_device).sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0])));
 table('#report-by-severity',['NÍVEL','REGISTROS'],Object.entries(r.by_severity).map(([key,count])=>[reportSeverityLabels[key]||key,count]));
 $('#report-origin-help').textContent=r.critical_without_ip+' registros críticos sem IP de origem identificável. IP do evento é diferente do endereço do dispositivo remetente.';table('#report-by-source-ip',['IP DE ORIGEM','REGISTROS CRÍTICOS'],Object.entries(r.critical_by_source_ip||{}).sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0])));
 table('#report-events',['HORÁRIO UTC','DISPOSITIVO','IP DE ORIGEM','TIPO / NÍVEL','EVENTO'],r.events.map(event=>[new Date(event.time).toISOString().replace('T',' '),event.device,event.source_ip||'Não identificado',(event.alert?'Alerta':'Log')+' · '+event.level,event.message]));
}
$('#report-json').onclick=()=>{if(currentReport)location.href='/api/reports?'+currentReportQuery+'&format=json'};
$('#report-csv').onclick=()=>{if(currentReport)location.href='/api/reports?'+currentReportQuery+'&format=csv'};
$('#report-pdf').onclick=()=>{if(!currentReport)return;document.body.classList.add('printing-report');window.print()};
window.addEventListener('afterprint',()=>document.body.classList.remove('printing-report'));

$('#report-security-preset').onclick=()=>{const f=$('#report-form');f.elements.kind.value='infrastructure';f.elements.severity.value='critical';f.elements.type.value='';$('#report-status').textContent='Filtros de segurança aplicados. Escolha o período e clique em Gerar relatório.'};
