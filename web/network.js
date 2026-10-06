'use strict';
let networkData={devices:[],tests:[]},networkMode='inventory',networkEditing=null,networkSelections=new Set();
const networkNames={quick:'Ping rápido',continuous:'Ping contínuo',trace:'Traceroute',inventory:'Cadastros',ports:'Testes de portas TCP'};
const networkKinds={switch:'Switch',router:'Roteador',firewall:'Firewall','access-point':'Access point',server:'Servidor',pfsense:'pfSense',proxmox:'Proxmox'};
const networkStatuses={running:'Em execução',completed:'Concluído',failed:'Falhou ou não houve resposta',stopped:'Interrompido',simulated:'Demonstração'};
function networkFilteredDevices(){return networkData.devices.filter(d=>(!$('#network-client').value||d.client===$('#network-client').value)&&(!$('#network-unit').value||d.unit===$('#network-unit').value))}
function setNetworkOptions(select,values,label){const selected=select.value;select.replaceChildren(new Option(label,''));[...new Set(values)].sort().forEach(value=>select.append(new Option(value,value)));select.value=values.includes(selected)?selected:''}
async function renderNetwork(){
 const data=await api('/api/network');networkData={devices:data.devices||[],tests:data.tests||[]};
 setNetworkOptions($('#network-client'),networkData.devices.map(d=>d.client),'Todos os clientes');
 setNetworkOptions($('#network-unit'),networkData.devices.filter(d=>!$('#network-client').value||d.client===$('#network-client').value).map(d=>d.unit),'Todas as unidades');
 $('#network-known-clients').replaceChildren(...[...new Set(networkData.devices.map(d=>d.client))].map(client=>{const option=el('option');option.value=client;return option}));
 const available=new Set(networkData.devices.map(d=>d.id));networkSelections=new Set([...networkSelections].filter(id=>available.has(id)));renderNetworkInventory();renderNetworkSelection();renderNetworkResults();
}
function renderNetworkInventory(){
 const viewer=snapshot?.role==='viewer';table('#network-equipment-list',['CLIENTE / UNIDADE','EQUIPAMENTO','IP','TIPO','AÇÕES'],networkFilteredDevices().map(d=>{
  const controls=el('div');if(!viewer)controls.append(action('Editar',()=>{networkEditing=d.id;const f=$('#network-equipment-form');['name','ip','kind','client','unit','ssh_user','ssh_port'].forEach(key=>f.elements[key].value=d[key]||(key==='ssh_port'?22:''));$('#network-form-title').textContent='Editar equipamento';$('#network-edit-cancel').hidden=false;f.elements.name.focus()}),action('Remover',async()=>{if(!confirm('Remover '+d.name+' do cadastro de '+d.client+' / '+d.unit+'?'))return;await api('/api/network/equipment/'+encodeURIComponent(d.id),'DELETE');if(networkEditing===d.id)cancelNetworkEdit();await renderNetwork()}));
  return[d.client+' / '+d.unit,d.name,d.ip,networkKinds[d.kind]||d.kind,controls];
 }));
}
function renderNetworkSelection(){
 const box=$('#network-device-options');box.replaceChildren();const devices=networkFilteredDevices();
 if(!devices.length){box.append(el('p','Nenhum equipamento cadastrado para estes filtros.'));return}
 devices.forEach(d=>{const label=el('label',undefined,'check'),input=el('input');input.type='checkbox';input.checked=networkSelections.has(d.id);input.onchange=()=>{if(input.checked)networkSelections.add(d.id);else networkSelections.delete(d.id);renderNetworkSelectionStatus()};label.append(input,el('span',d.client+' / '+d.unit+' · '+d.name+' · '+d.ip));box.append(label)});renderNetworkSelectionStatus();
}
function renderNetworkSelectionStatus(){const filtered=new Set(networkFilteredDevices().map(d=>d.id));const count=[...networkSelections].filter(id=>filtered.has(id)).length;$('#network-selection-status').textContent=count+' equipamentos selecionados nos filtros atuais.';$('#network-start').disabled=count<1||count>8;}
function renderNetworkResults(){
 const root=$('#network-test-results');root.replaceChildren();const client=$('#network-client').value,unit=$('#network-unit').value;
 networkData.tests.filter(job=>(!client||job.equipment.client===client)&&(!unit||job.equipment.unit===unit)).sort((a,b)=>b.started.localeCompare(a.started)).forEach(job=>{
  const card=el('article',undefined,'panel form-panel'),heading=el('div',undefined,'panel-heading');heading.append(el('h2',job.equipment.client+' / '+job.equipment.unit+' · '+job.equipment.name+' · '+networkNames[job.mode]));
  if(job.status!=='running'&&snapshot?.role!=='viewer')heading.append(action('Adicionar ao relatório temporário',()=>saveTemporaryTest({type:'network',id:job.id})));
  if(job.status==='running'&&snapshot?.role!=='viewer')heading.append(action('Interromper',async()=>{await api('/api/network/tests/'+encodeURIComponent(job.id)+'/stop','POST',{});await renderNetwork()}));
  card.append(heading,el('p',networkStatuses[job.status]+' · '+job.equipment.ip+' · iniciado '+date(job.started)),el('pre',(job.output||[]).join('\n')||'Aguardando resposta…','network-output'));root.append(card);
 });
 if(!root.children.length)root.append(el('div','Nenhum teste executado nesta sessão do servidor.','empty'));
}
function cancelNetworkEdit(){networkEditing=null;$('#network-equipment-form').reset();$('#network-form-title').textContent='Cadastrar equipamento';$('#network-edit-cancel').hidden=true}
$('#network-edit-cancel').onclick=cancelNetworkEdit;
$('#network-equipment-form').onsubmit=e=>{e.preventDefault();run(async()=>{const f=new FormData(e.target),body={id:networkEditing||''};['name','ip','kind','client','unit'].forEach(key=>body[key]=String(f.get(key)||'').trim());body.ssh_user=String(f.get('ssh_user')||'').trim();body.ssh_port=Number(f.get('ssh_port')||22);await api('/api/network/equipment','PUT',body);cancelNetworkEdit();await renderNetwork()})};
document.querySelectorAll('[data-network-tab]').forEach(button=>button.onclick=()=>{
 networkMode=button.dataset.networkTab;$('#network-port-fields').hidden=networkMode!=='ports';$('#network-inventory').hidden=networkMode!=='inventory';$('#network-diagnostics').hidden=networkMode==='inventory';$('#network-test-title').textContent=networkNames[networkMode];$('#network-test-help').textContent=networkMode==='ports'?'Scan TCP connect do Nmap, a partir do SIEM, com limite de 120 segundos por equipamento. Resultados agrupados pelo Nmap também aparecem na saída.':networkMode==='continuous'?'Ping contínuo: um pacote por segundo, com interrupção manual ou automática após 30 minutos. São exibidas as últimas 200 linhas.':networkMode==='trace'?'Traceroute: até 20 saltos, sem resolução DNS. Alguns roteadores não respondem; um salto sem resposta não confirma interrupção do caminho.':'Ping rápido: quatro pacotes por equipamento. Selecione até oito equipamentos.';renderNetworkSelection();
});
$('#network-client').onchange=()=>{setNetworkOptions($('#network-unit'),networkData.devices.filter(d=>!$('#network-client').value||d.client===$('#network-client').value).map(d=>d.unit),'Todas as unidades');renderNetworkInventory();renderNetworkSelection();renderNetworkResults()};
$('#network-unit').onchange=()=>{renderNetworkInventory();renderNetworkSelection();renderNetworkResults()};
$('#network-start').onclick=()=>run(async()=>{const filtered=new Set(networkFilteredDevices().map(d=>d.id)),ids=[...networkSelections].filter(id=>filtered.has(id));await api('/api/network/tests','POST',{ids,mode:networkMode,ports:networkMode==='ports'?$('#network-ports').value.trim():''});await renderNetwork()});
