'use strict';
// Guided capture uses the established SSH trust flow. No credential is persisted.
const dhcpPanel=el('article',undefined,'panel form-panel dhcp-panel');
dhcpPanel.setAttribute('data-admin-only','');
dhcpPanel.append(el('h2','Consulta de servidores DHCP'),el('p','Escolha o pfSense, autentique e selecione a interface LAN. A consulta observa respostas DHCP sem alterar o firewall. Você decide quais servidores são autorizados.'));
const dhcpLaunch=el('button','Consultar servidores DHCP'),dhcpResult=el('div');dhcpLaunch.type='button';dhcpPanel.append(dhcpLaunch,dhcpResult);
$('#ssh-catalog-buttons').closest('article').before(dhcpPanel);
function dhcpField(title,input){const label=el('label',title);label.append(input);return label;}
function renderDHCPResult(root,data){
 root.replaceChildren();root.append(el('p',data.message||({capturing:'Observando respostas DHCP…',analyzing:'Interpretando os dados no Ollama local…'}[data.status]||data.status),'dhcp-status'));
 if(data.report_error)root.append(el('p',data.report_error,'dhcp-caution'));else if(data.report_id)root.append(el('p','Resultado salvo automaticamente em Relatórios temporários de testes.'));
 const grid=el('div',undefined,'dhcp-result-grid');root.append(grid);
 for(const server of data.servers||[]){
  const card=el('article',undefined,'dhcp-server-card');card.append(el('h3','Servidor observado · '+server.ip,'dhcp-ip'));
  const facts=el('dl');
  for(const [label,value,color] of [['IP de origem',server.source,'dhcp-ip'],['MAC Ethernet observado',server.mac,'dhcp-mac'],['Possível fabricante (OUI)',server.vendor,'dhcp-mac'],['Rede oferecida',server.network||'Não informada na captura','dhcp-network'],['Respostas',String(server.responses),'']]){facts.append(el('dt',label),el('dd',value,color))}
  card.append(facts,el('p',server.relay?'Possível relay ou origem diferente do Server-ID: este MAC pode não ser o servidor DHCP.':'O MAC identifica a origem Ethernet observada. O fabricante não confirma o modelo nem a autorização.','dhcp-caution'));grid.append(card);
 }
 if(data.diagnosis){const details=el('details',undefined,'dhcp-interpretation');details.open=true;details.append(el('summary','Interpretação local · '+data.diagnosis.model+' · hipótese para revisão'),el('p',data.diagnosis.summary),el('p',data.diagnosis.cause));for(const text of data.diagnosis.checks||[])details.append(el('p','Verificação: '+text));details.append(el('p',data.diagnosis.uncertainty,'dhcp-caution'));root.append(details)}
}
dhcpLaunch.onclick=async()=>{
 let sessionID='',jobID='',credential=null,pollTimer=null,closed=false,busy=false;
 const dialog=el('dialog',undefined,'ssh-trust-dialog dhcp-dialog'),form=el('form',undefined,'form-grid'),equipment=el('select'),username=el('input'),password=el('input'),iface=el('select'),duration=el('select'),status=el('p'),submit=el('button','Conectar e listar interfaces'),cancel=el('button','Cancelar','secondary');
 username.autocomplete='off';username.required=true;password.type='password';password.autocomplete='new-password';password.required=true;
 iface.disabled=true;for(const n of [15,30,60,120])duration.append(new Option(n+' segundos',String(n)));duration.value='30';
 submit.type='submit';cancel.type='button';equipment.required=true;
 form.append(dhcpField('Cliente / unidade / pfSense',equipment),dhcpField('Usuário SSH',username),dhcpField('Senha desta conexão',password),dhcpField('Interface LAN',iface),dhcpField('Duração da observação',duration),submit,cancel);
 dialog.append(el('h2','Consultar servidores DHCP'),el('p','A senha é usada somente nesta conexão HTTPS/SSH. Nenhuma senha será enviada ao Ollama ou salva no cadastro.'),form,status);document.body.append(dialog);dialog.showModal();
 const cleanup=async()=>{closed=true;password.value='';if(credential)credential.password='';if(pollTimer)clearInterval(pollTimer);if(sessionID){try{if(jobID)await api('/api/ssh/sessions/'+sessionID+'/dhcp/'+jobID+'/cancel','POST',{});await api('/api/ssh/sessions/'+sessionID+'/close','POST',{})}catch{}}};
 dialog.addEventListener('cancel',e=>{e.preventDefault();cancel.click()});cancel.onclick=()=>{cleanup();dialog.close();dialog.remove()};
 let devices=[];
 try{const data=await api('/api/network');devices=(data.devices||[]).filter(d=>d.kind==='pfsense');for(const d of devices)equipment.append(new Option(d.client+' / '+d.unit+' · '+d.name+' · '+d.ip,d.id));if(!devices.length)throw Error('Cadastre um pfSense em Equipamentos de rede antes de consultar.');username.value=devices[0].ssh_user||'admin'}catch(error){status.textContent=error.message;submit.disabled=true}
 equipment.onchange=()=>{const d=devices.find(d=>d.id===equipment.value);username.value=d?.ssh_user||'admin'};
 form.onsubmit=async e=>{
  e.preventDefault();if(busy||closed)return;busy=true;submit.disabled=true;
  try{
   if(!sessionID){
    const d=devices.find(d=>d.id===equipment.value);if(!d)throw Error('Selecione um pfSense cadastrado.');credential={user:username.value.trim(),password:password.value};password.value='';
    status.textContent='Verificando identificação SSH…';await sshEnsureTrusted(d);if(closed)return;
    const data=await api('/api/ssh/sessions','POST',{id:d.id,...credential});credential.password='';sessionID=encodeURIComponent(data.id);
    if(closed){await cleanup();return};equipment.disabled=username.disabled=password.disabled=true;status.textContent='Aguardando autenticação SSH…';
    await new Promise((resolve,reject)=>{let attempts=0;const check=async()=>{try{if(closed)throw Error('Consulta cancelada.');const state=await api('/api/ssh/sessions/'+sessionID+'?offset=0');if(state.status==='connected'){resolve();return};if(state.status==='closed')throw Error(state.message||'Conexão rejeitada.');if(++attempts>25)throw Error('Tempo de conexão excedido.');setTimeout(check,500)}catch(error){reject(error)}};check()});
    const result=await api('/api/ssh/sessions/'+sessionID+'/dhcp/interfaces');iface.replaceChildren();for(const name of result.interfaces)iface.append(new Option(name,name));if(!result.interfaces.length)throw Error('Nenhuma interface Ethernet listada.');iface.disabled=false;password.required=false;submit.textContent='Iniciar consulta DHCP';status.textContent='Selecione a interface LAN correta. Não há geração de tráfego DHCP; a captura aguarda respostas de clientes na rede.';
   }else{
    const job=await api('/api/ssh/sessions/'+sessionID+'/dhcp','POST',{interface:iface.value,seconds:Number(duration.value)});jobID=encodeURIComponent(job.id);iface.disabled=duration.disabled=true;submit.hidden=true;cancel.textContent='Interromper consulta';renderDHCPResult(dhcpResult,job);
    let polling=false;pollTimer=setInterval(async()=>{if(polling||closed)return;polling=true;try{const data=await api('/api/ssh/sessions/'+sessionID+'/dhcp/'+jobID);renderDHCPResult(dhcpResult,data);status.textContent=data.status==='capturing'?'Captura em andamento…':data.status==='analyzing'?'Interpretação local em andamento…':data.message;
     if(!['capturing','analyzing'].includes(data.status)){clearInterval(pollTimer);pollTimer=null;if(data.status==='completed'){const terminalID=decodeURIComponent(sessionID),savedJobID=decodeURIComponent(jobID);if(!data.report_id)dhcpResult.append(action('Tentar salvar no relatório temporário',()=>saveTemporaryTest({type:'dhcp',id:savedJobID,terminal_id:terminalID})))}await api('/api/ssh/sessions/'+sessionID+'/close','POST',{});sessionID='';cancel.textContent='Fechar';dhcpResult.scrollIntoView({behavior:'smooth',block:'start'})}
    }catch(error){status.textContent=error.message;await cleanup();cancel.textContent='Fechar'}finally{polling=false}},1000);
   }
  }catch(error){status.textContent=error.message;await cleanup();cancel.textContent='Fechar'}finally{if(credential)credential.password='';password.value='';busy=false;submit.disabled=closed||!!jobID}
 };
};
