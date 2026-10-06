'use strict';
const temporaryReportsPanel=el('article',undefined,'panel form-panel');temporaryReportsPanel.id='temporary-test-reports';temporaryReportsPanel.setAttribute('data-admin-only','');
const temporaryReportsList=el('div'),temporaryReportsDocument=el('div'),temporaryReportsStatus=el('p'),temporaryRefresh=el('button','Atualizar relatórios','secondary'),temporaryPDF=el('button','Exportar relatório para PDF');
temporaryReportsDocument.id='temporary-test-report-document';temporaryRefresh.type=temporaryPDF.type='button';temporaryPDF.disabled=true;
temporaryReportsPanel.append(el('h2','Relatórios temporários de testes'),el('p','Resultados de consultas DHCP, ping, traceroute e portas adicionados por você. Retenção de 72 horas a partir do teste; limpeza automática. A interpretação do Ollama é uma hipótese para revisão.'),temporaryRefresh,temporaryPDF,temporaryReportsStatus,temporaryReportsList,temporaryReportsDocument);$('#reports').append(temporaryReportsPanel);
async function saveTemporaryTest(body){await api('/api/test-reports','POST',body);toast('Resultado adicionado ao relatório temporário por até três dias.');await refreshTemporaryReports();}
async function refreshTemporaryReports(){
 const data=await api('/api/test-reports');temporaryReportsList.replaceChildren();temporaryReportsDocument.replaceChildren();temporaryPDF.disabled=!data.reports.length;
 temporaryReportsDocument.append(el('h2','Multipla SIEM · Resultados de testes'),el('p','Gerado em '+new Date().toLocaleString('pt-BR')+'. Resultados observados, sujeitos à revisão humana.'));
 if(!data.reports.length)temporaryReportsStatus.textContent='Nenhum resultado temporário armazenado.';else temporaryReportsStatus.textContent=data.reports.length+' resultados disponíveis. Os arquivos PDF que você salvar não são apagados pelo SIEM.';
 for(const item of data.reports){
  const row=el('div',undefined,'temporary-report-entry'),equipment=item.equipment,label=equipment.client+' / '+equipment.unit+' · '+equipment.name+' · '+(item.mode==='dhcp'?'Servidores DHCP':networkNames[item.mode]||item.mode);
  row.append(el('span',label+' · expira em '+date(item.expires)),action('Excluir',async()=>{await api('/api/test-reports/'+encodeURIComponent(item.id),'DELETE');await refreshTemporaryReports()}));temporaryReportsList.append(row);
  const card=el('article',undefined,'temporary-report-document-entry');card.append(el('h3',label),el('p','Teste em '+date(item.created)+' · disponível até '+date(item.expires)),el('p',item.analysis_status));
  if(item.mode==='dhcp'){const result=el('div');renderDHCPResult(result,{status:'completed',message:'Você decide quais servidores são autorizados. Nenhum bloqueio foi aplicado.',servers:item.servers});card.append(result)}else card.append(el('pre',item.output||'Nenhuma saída registrada.','network-output'));
  if(item.diagnosis){const diagnosis=diagnosisPanel(item.diagnosis,true,'temporary-'+item.id);diagnosis.open=true;card.append(diagnosis)}temporaryReportsDocument.append(card);
 }
}
temporaryRefresh.onclick=()=>run(refreshTemporaryReports);
temporaryPDF.onclick=()=>{document.body.classList.add('printing-tests');window.print()};window.addEventListener('afterprint',()=>document.body.classList.remove('printing-tests'));
document.querySelector('[data-page="reports"]').addEventListener('click',()=>{if(snapshot?.role==='admin')run(refreshTemporaryReports)});
setInterval(()=>{if(page==='reports'&&snapshot?.role==='admin'&&!document.body.classList.contains('printing-tests'))refreshTemporaryReports().catch(error=>{temporaryReportsStatus.textContent=error.message})},10000);
