'use strict';
const SSH_QUICK_TESTS=[{"name": "Consultar MACs da rede (ARP)", "command": "arp -an | grep -F '192.168.253.'", "help": "Consulta a tabela ARP existente, sem alterar a configuração. Edite o prefixo para a rede investigada. A ausência de entrada não prova que o equipamento esteja desconectado; a tabela pode não ter uma associação recente."},{"name": "Consultar MAC de um IP (exemplo .4)", "command": "arp -an | grep -F '(192.168.253.4)'", "help": "Consulta a associação IP/MAC já presente na tabela ARP. Edite o IP conforme necessário. O filtro inclui parênteses para evitar correspondências com outros IPs."},{"name": "Consultar MAC de um IP (exemplo .101)", "command": "arp -an | grep -F '(192.168.253.101)'", "help": "Consulta a associação IP/MAC já presente na tabela ARP. Edite o IP conforme necessário. Uma entrada pode estar desatualizada; confirme com a captura quando necessário."},{"name": "Capturar DHCP dos servidores investigados", "command": "tcpdump -eni em0 'udp port 67 and (src host 192.168.253.4 or src host 192.168.253.101)'", "help": "Edite em0 para a interface da rede e substitua os dois IPs investigados. -e exibe os MACs no cabeçalho Ethernet. A captura observa pacotes sem alterar a configuração; use Ctrl+C para encerrar. Em tráfego roteado ou com relay, o MAC observado pode ser do próximo salto, e não do servidor DHCP. O fabricante/OUI é uma pista, não uma identificação definitiva. Requer tcpdump e permissão de captura."},{name:'Identificar servidores DHCP (Server-ID)',command:"tcpdump -lni igb1 -vvv 'udp and (port 67 or port 68)' | grep --line-buffered \"Server-ID\"",help:'Troque igb1 pela interface LAN. Deixe a captura rodar e compare cada Server-ID (opção 54) com os IPs dos servidores DHCP autorizados. Um IP desconhecido é um indício de DHCP não autorizado; servidores adicionais ou relay podem ser legítimos. A ausência de saída não comprova ausência de outro servidor. -l mantém a saída do tcpdump fluindo pelo pipe. Se grep não aceitar --line-buffered, remova essa opção. Requer permissão de captura. Use Ctrl+C para encerrar.'},{name:'Inspecionar DHCP e MACs de origem',command:"tcpdump -eni igb1 -vvv -n 'udp and (port 67 or port 68)'",help:'Mostra os cabeçalhos Ethernet, incluindo MACs de origem e destino, e detalhes das mensagens DHCP. Ajuste igb1 para a interface da rede investigada. O MAC Ethernet de origem pode pertencer a um relay; confira também o endereço do cliente nos detalhes DHCP. Requer tcpdump instalado e permissão de captura. Use Ctrl+C no terminal para encerrar.'},{name:'Monitorar tráfego ARP e DHCP',command:'tcpdump -i br0 arp or port 67 or port 68',help:'Captura ARP e DHCP para investigar possíveis MACs duplicados, loops, excesso de solicitações DHCP e ausência de respostas ARP. Ajuste br0 para a interface do equipamento; a captura fornece indícios para investigação. Requer tcpdump instalado e permissão de captura. Use Ctrl+C no terminal para encerrar.'}];
SSH_QUICK_TESTS.push(
 {name:'Listar interfaces e endereços',command:'ifconfig -a',kinds:['pfsense'],help:'pfSense: lista interfaces, endereços IP, MACs e estado do link. Use para descobrir a interface correta antes de uma captura. Consulta sem alterar a configuração.'},
 {name:'Consultar tabela de rotas',command:'netstat -rn',kinds:['pfsense'],help:'pfSense: mostra destinos, gateways e interfaces das rotas, sem resolver nomes. Ajuda a verificar o caminho configurado para uma rede. Consulta sem alterar rotas.'},
 {name:'Listar interfaces e endereços',command:'ip -br address show',kinds:['proxmox'],help:'Proxmox/Linux: resumo das interfaces, estado e endereços IP. Use para identificar bridges e interfaces antes de capturar tráfego. Consulta sem alterar a configuração.'},
 {name:'Consultar tabela de rotas',command:'ip route show',kinds:['proxmox'],help:'Proxmox/Linux: exibe rotas IPv4 e gateway padrão. Consulta sem alterar as rotas.'},
 {name:'Consultar vizinhos e MACs',command:'ip neigh show',kinds:['proxmox'],help:'Proxmox/Linux: lista associações de vizinhos IP/MAC e seus estados. Entradas FAILED ou INCOMPLETE ajudam a investigar falta de resposta. A ausência de entrada não comprova desconexão.'}
);
let sshKind='pfsense',sshInventory=[],sshClients=new Set(),sshUnits=new Set(),sshSelected=new Set(),sshIdentities=new Map(),sshViews=new Map();
function sshUnitKey(d){return d.client+' / '+d.unit}
function sshAvailable(){return sshInventory.filter(d=>d.kind===sshKind&&(!sshClients.size||sshClients.has(d.client))&&(!sshUnits.size||sshUnits.has(sshUnitKey(d))))}
function sshChosen(){return sshAvailable().filter(d=>sshSelected.has(d.id))}
function sshCheckboxes(box,items,selected,onchange){box.replaceChildren();items.forEach(([value,label])=>{const row=el('label',undefined,'check'),check=el('input');check.type='checkbox';check.checked=selected.has(value);check.onchange=()=>{if(check.checked)selected.add(value);else selected.delete(value);onchange()};row.append(check,el('span',label));box.append(row)});if(!items.length)box.append(el('p','Nenhum cadastro disponível.'))}
async function renderSSHInventory(){
 if(snapshot?.role==='viewer')return;
 const data=await api('/api/network');sshInventory=(data.devices||[]).filter(d=>d.kind==='pfsense'||d.kind==='proxmox');renderSSHSelectors();
}
function renderSSHSelectors(){
 const devices=sshInventory.filter(d=>d.kind===sshKind),clients=[...new Set(devices.map(d=>d.client))].sort();sshClients=new Set([...sshClients].filter(c=>clients.includes(c)));
 sshCheckboxes($('#ssh-client-options'),clients.map(c=>[c,c]),sshClients,()=>{sshUnits.clear();renderSSHSelectors()});
 const units=[...new Set(devices.filter(d=>!sshClients.size||sshClients.has(d.client)).map(sshUnitKey))].sort();sshUnits=new Set([...sshUnits].filter(u=>units.includes(u)));sshCheckboxes($('#ssh-unit-options'),units.map(u=>[u,u]),sshUnits,renderSSHSelectors);
 sshCheckboxes($('#ssh-device-options'),sshAvailable().map(d=>[d.id,d.client+' / '+d.unit+' · '+d.name+' · '+(d.ssh_user||(d.kind==='pfsense'?'admin':'root'))+'@'+d.ip+':'+(d.ssh_port||22)]),sshSelected,renderSSHSelectionStatus);
 $('#ssh-selection-title').textContent='Selecionar '+(sshKind==='pfsense'?'pfSense':'Proxmox')+' cadastrados';renderSSHSelectionStatus();renderSSHQuickCatalog();
}
function renderSSHSelectionStatus(){const count=sshChosen().length;$('#ssh-selection-status').textContent=count+' equipamentos selecionados. Até quatro terminais simultâneos.';$('#ssh-check-identities').disabled=count<1||count>4}
document.querySelectorAll('[data-ssh-kind]').forEach(button=>button.onclick=()=>{sshKind=button.dataset.sshKind;sshClients.clear();sshUnits.clear();renderSSHSelectors()});
$('#ssh-check-identities').onclick=()=>run(async()=>{
 const selected=sshChosen();if(!selected.length||selected.length>4)throw Error('Selecione de um a quatro equipamentos.');const failures=[];const root=$('#ssh-host-identities');root.replaceChildren();
 for(const d of selected){
  const card=el('div',undefined,'ssh-host-identity');card.append(el('h3',d.client+' / '+d.unit+' · '+d.name));root.append(card);
  try{const data=await api('/api/ssh/identity','POST',{id:d.id});sshIdentities.set(d.id,data);card.append(el('p',data.identity.fingerprint));
   if(data.trusted)card.append(el('p','Identificação já confirmada.'));
   else{if(data.previous_fingerprint)card.append(el('p','ATENÇÃO: identificação anterior diferente: '+data.previous_fingerprint));card.append(el('p','Compare esta identificação com a obtida diretamente no equipamento, por um canal confiável.'));
    card.append(action('Confirmar identificação',async()=>{if(!confirm('Você conferiu a identificação SSH de '+d.name+' por um canal confiável?\n'+data.identity.fingerprint))return;await api('/api/ssh/trust','POST',{id:d.id,key:data.identity.key});data.trusted=true;card.append(el('p','Identificação confirmada e salva.'))}));
   }
  }catch(e){failures.push(d.name+': '+e.message);card.append(el('p',e.message))}
 }
 if(failures.length)throw Error(failures.join(' · '));
});
async function sshConfirmServer(d,data){
 const dialog=el('dialog',undefined,'ssh-trust-dialog'),title=el('h2','Confirmar identificação do servidor SSH'),cancel=el('button','Cancelar','secondary'),accept=el('button','Confirmar e conectar');cancel.type=accept.type='button';
 dialog.append(title,el('p',d.client+' / '+d.unit+' · '+d.name+' · '+d.ip+':'+(d.ssh_port||22)),el('p','Confira esta impressão digital por um canal confiável antes de enviar sua senha.'),el('pre',data.identity.fingerprint));
 if(data.previous_fingerprint)dialog.append(el('p','A identificação mudou. Confirme a alteração com o responsável pelo equipamento antes de continuar.'),el('pre','Anterior: '+data.previous_fingerprint));
 const controls=el('div',undefined,'toolbar');controls.append(cancel,accept);dialog.append(controls);document.body.append(dialog);
 return await new Promise(resolve=>{let done=false;const finish=value=>{if(done)return;done=true;dialog.close();dialog.remove();resolve(value)};cancel.onclick=()=>finish(false);accept.onclick=()=>finish(true);dialog.oncancel=e=>{e.preventDefault();finish(false)};dialog.showModal();cancel.focus()});
}
async function sshEnsureTrusted(d){const data=await api('/api/ssh/identity','POST',{id:d.id});sshIdentities.set(d.id,data);if(data.trusted)return;if(!await sshConfirmServer(d,data))throw Error('Conexão cancelada: identificação não confirmada.');await api('/api/ssh/trust','POST',{id:d.id,key:data.identity.key});}
function sshEncode(bytes){return btoa(String.fromCharCode(...bytes))}
function sshDecode(text){return Uint8Array.from(atob(text),c=>c.charCodeAt(0))}
let sshActiveTooltip=null;
function hideSSHTooltip(){if(!sshActiveTooltip)return;const {tip,home}=sshActiveTooltip;tip.hidden=true;tip.classList.remove('ssh-floating-tooltip');home.append(tip);sshActiveTooltip=null;}
function attachSSHInfoTooltip(home,info,tip){
 tip.hidden=true;
 const show=()=>{hideSSHTooltip();sshActiveTooltip={tip,home};document.body.append(tip);tip.classList.add('ssh-floating-tooltip');tip.hidden=false;
 const rect=info.getBoundingClientRect(),width=document.documentElement.clientWidth,height=window.innerHeight;
 tip.style.width=Math.min(360,Math.max(100,width-24))+'px';tip.style.maxHeight=Math.max(80,height-24)+'px';
 const box=tip.getBoundingClientRect();const left=Math.max(12,Math.min(rect.left+rect.width/2-box.width/2,width-box.width-12));
 const above=rect.top-box.height-10;const top=above>=12?above:Math.min(rect.bottom+10,Math.max(12,height-box.height-12));
 tip.style.left=left+'px';tip.style.top=Math.max(12,top)+'px';
 };
 home.addEventListener('pointerenter',show);home.addEventListener('pointerleave',()=>{if(document.activeElement!==info)hideSSHTooltip()});info.addEventListener('focus',show);info.addEventListener('blur',hideSSHTooltip);info.addEventListener('keydown',e=>{if(e.key==='Escape'){hideSSHTooltip();e.stopPropagation()}});
}
window.addEventListener('scroll',hideSSHTooltip,true);window.addEventListener('resize',hideSSHTooltip);
function sshTerminalOptions(){return {cols:100,rows:28,scrollback:2000,cursorBlink:true,cursorStyle:'block',disableStdin:true,fontFamily:'"Cascadia Mono", "Cascadia Code", Consolas, "DejaVu Sans Mono", "Liberation Mono", monospace',fontSize:14,lineHeight:1.2,fontWeight:'400',allowProposedApi:false,theme:{background:'#0d1117',foreground:'#dce5ef',cursor:'#64dfc3',cursorAccent:'#0d1117',selectionBackground:'#35465e',black:'#17212d',red:'#f07883',green:'#83d99e',yellow:'#eccb83',blue:'#83b5f6',magenta:'#cba0ed',cyan:'#73d5dc',white:'#dce5ef',brightBlack:'#7c8b9e',brightRed:'#ff9b9b',brightGreen:'#adf0bd',brightYellow:'#ffe3a0',brightBlue:'#a9cdff',brightMagenta:'#e2bdff',brightCyan:'#a0edf0',brightWhite:'#ffffff'}}}
function sshAppearanceControls(card,terminal){
 const controls=el('div',undefined,'ssh-terminal-appearance'),label=el('label','Fonte'),size=el('select'),expand=el('button','Expandir','secondary');
 size.setAttribute('aria-label','Tamanho da fonte do terminal');for(const n of [12,14,16,18,20]){const option=el('option',n+' px');option.value=n;size.append(option)}size.value='14';label.append(size);size.onchange=()=>{terminal.options.fontSize=Number(size.value);terminal.focus()};expand.type='button';expand.setAttribute('aria-expanded','false');
 const collapse=()=>{card.classList.remove('ssh-terminal-expanded');expand.textContent='Expandir';expand.setAttribute('aria-expanded','false')};
 expand.onclick=()=>{const expanded=card.classList.toggle('ssh-terminal-expanded');expand.textContent=expanded?'Recolher':'Expandir';expand.setAttribute('aria-expanded',String(expanded));terminal.focus()};
 card.addEventListener('keydown',e=>{if(e.key==='Escape'&&card.classList.contains('ssh-terminal-expanded')){e.preventDefault();collapse();expand.focus()}},true);controls.append(label,expand);return controls;
}
function createSSHView(data){
 for(const [id,old] of sshViews){if(old.closed){old.terminal.dispose();old.card.remove();sshViews.delete(id)}}
 const d=data.equipment,card=el('article',undefined,'panel form-panel ssh-terminal-card'),heading=el('div',undefined,'panel-heading'),status=el('p','Conectando…'),screen=el('div',undefined,'ssh-terminal-screen');
 heading.append(el('h3',d.client+' / '+d.unit+' · '+d.name+' · '+(d.kind==='pfsense'?'pfSense':'Proxmox')));card.append(heading,status,screen);$('#ssh-terminals').append(card);
 const terminal=new Terminal(sshTerminalOptions());terminal.open(screen);
 // Remote servers may print terminal escapes; never grant clipboard access through OSC 52.
 terminal.parser.registerOscHandler(52,()=>true);terminal.parser.registerOscHandler(8,()=>true);
 const view={id:data.id,terminal,status,card,offset:0,busy:false,closed:false,input:Promise.resolve()};sshViews.set(view.id,view);
 const focus=el('button','Focar terminal','secondary');focus.type='button';focus.onclick=()=>terminal.focus();heading.append(sshAppearanceControls(card,terminal),focus);screen.addEventListener('pointerdown',()=>terminal.focus());screen.tabIndex=0;screen.setAttribute('aria-label','Terminal SSH interativo. Clique para digitar.');
 const close=action('Encerrar sessão',async()=>{await api('/api/ssh/sessions/'+encodeURIComponent(view.id)+'/close','POST',{});view.closed=true;view.terminal.options.disableStdin=true;status.textContent='Sessão encerrada.'});heading.append(close);
 const form=el('form',undefined,'ssh-command-form'),preset=el('select'),empty=el('option','Selecione um teste rápido');empty.value='';preset.append(empty);
 const availableTests=SSH_QUICK_TESTS.filter(item=>!item.kinds||item.kinds.includes(d.kind));
 for(const item of availableTests){const option=el('option',item.name);option.value=item.command;preset.append(option)}
 const label=el('label','Comando · revise antes de enviar'),command=el('textarea');command.rows=3;command.maxLength=8192;command.spellcheck=false;command.autocomplete='off';label.append(command);
 const help=el('p'),send=el('button','Executar no equipamento');send.type='submit';preset.onchange=()=>{command.value=preset.value;command.focus()};const buttons=el('div',undefined,'ssh-quick-buttons');
 for(const item of availableTests){const wrap=el('span',undefined,'ssh-quick-item'),button=el('button',item.name, 'secondary'),tip=el('span',item.help+'\nComando: '+item.command,'ssh-command-tooltip');button.type='button';tip.id='ssh-tip-'+data.id+'-'+buttons.children.length;tip.setAttribute('role','tooltip');button.onclick=()=>{preset.value=item.command;command.value=item.command;command.focus()};const info=el('button','i','ssh-command-info');info.type='button';info.setAttribute('aria-label','Informações sobre '+item.name);info.setAttribute('aria-describedby',tip.id);const infoWrap=el('span',undefined,'ssh-info-wrap');infoWrap.append(info,tip);attachSSHInfoTooltip(infoWrap,info,tip);wrap.append(button,infoWrap);buttons.append(wrap)}
 form.append(buttons,preset,help,label,send,el('p','Revise o comando e seus efeitos. O envio ocorre somente ao clicar em executar.'));const tools=el('details',undefined,'ssh-terminal-tools');tools.append(el('summary','Comandos de diagnóstico deste terminal'),form);card.append(el('p','Clique no terminal para digitar. No menu do pfSense, digite 8 e Enter para abrir o Shell. Ctrl+C interrompe o comando em execução.'),tools);
 form.onsubmit=event=>{event.preventDefault();run(async()=>{if(view.closed||view.terminal.options.disableStdin)throw Error('Conecte o terminal antes de executar.');const text=command.value.trim();if(!text)throw Error('Informe um comando.');if(/[\x00\x1b]/.test(text))throw Error('Caracteres de controle inválidos.');const bytes=new TextEncoder().encode(text+'\r');for(let i=0;i<bytes.length;i+=4096){const part=bytes.slice(i,i+4096);view.input=view.input.then(()=>api('/api/ssh/sessions/'+encodeURIComponent(view.id)+'/input','POST',{data:sshEncode(part)}));}await view.input;})};
 terminal.onData(text=>{const bytes=new TextEncoder().encode(text);for(let i=0;i<bytes.length;i+=4096){const part=bytes.slice(i,i+4096);view.input=view.input.then(()=>api('/api/ssh/sessions/'+encodeURIComponent(view.id)+'/input','POST',{data:sshEncode(part)})).catch(e=>{status.textContent=e.message})}});
 return view;
}
$('#ssh-connect-form').onsubmit=async e=>{e.preventDefault();const result=$('#ssh-connect-result'),button=e.target.querySelector('button[type="submit"]')||e.target.querySelector('button');button.disabled=true;result.textContent='Verificando solicitação…';let credential;
 try{
 const selected=sshChosen();if(!selected.length||selected.length>4)throw Error('Selecione de um a quatro equipamentos.');
 const f=new FormData(e.target);credential={user:String(f.get('user')||'').trim(),password:String(f.get('password')||''),private_key:String(f.get('private_key')||''),passphrase:String(f.get('passphrase')||'')};
 if(!credential.password&&!credential.private_key)throw Error('Informe a credencial para esta conexão.');
 e.target.elements.password.value='';e.target.elements.private_key.value='';e.target.elements.passphrase.value='';
 const failures=[];let opened=0;
 for(const d of selected){try{result.textContent='Verificando identificação de '+d.name+'…';await sshEnsureTrusted(d);const data=await api('/api/ssh/sessions','POST',{id:d.id,...credential});createSSHView(data);opened++}catch(error){failures.push(d.name+': '+error.message)}}
 result.textContent=(opened?'Solicitadas '+opened+' conexões. Acompanhe o estado nos terminais abaixo. ':'')+failures.join(' · ');if(failures.length)toast(failures.join(' · '));else toast('Conexão solicitada; aguardando autenticação SSH.');
 }catch(error){result.textContent=error.message;toast(error.message)}finally{if(credential){credential.password='';credential.private_key='';credential.passphrase=''}button.disabled=false;renderSSHQuickCatalog()}
};
async function pollSSHTerminal(view){
 if(view.busy||view.closed)return;view.busy=true;
 try{const data=await api('/api/ssh/sessions/'+encodeURIComponent(view.id)+'?offset='+view.offset);if(data.lost)view.terminal.writeln('\r\n[Parte da saída anterior excedeu o limite do buffer.]');if(data.data)view.terminal.write(sshDecode(data.data));view.offset=data.next;view.status.textContent=data.status==='connected'?'Conectado':data.status==='connecting'?'Conectando…':data.message||'Sessão encerrada';view.terminal.options.disableStdin=data.status!=='connected';if(data.status==='connected'&&!view.focused){view.focused=true;view.card.scrollIntoView({behavior:'smooth',block:'start'});view.terminal.focus();}if(data.status==='closed')view.closed=true}
 catch(error){view.status.textContent=error.message;view.closed=true;view.terminal.options.disableStdin=true}
 finally{view.busy=false;renderSSHCatalogTargets()}
}
setInterval(()=>{sshViews.forEach(pollSSHTerminal)},500);

function renderSSHCatalogTargets(){const select=$('#ssh-catalog-target');if(!select)return;const old=select.value;select.replaceChildren(new Option('Selecione um terminal conectado',''));for(const view of sshViews.values()){if(!view.closed&&!view.terminal.options.disableStdin){select.append(new Option(view.card.querySelector('h3').textContent,view.id))}}select.value=[...select.options].some(o=>o.value===old)?old:'';$('#ssh-catalog-execute').disabled=!select.value}
function renderSSHQuickCatalog(){hideSSHTooltip();const root=$('#ssh-catalog-buttons');if(!root)return;root.replaceChildren();for(const item of SSH_QUICK_TESTS.filter(test=>!test.kinds||test.kinds.includes(sshKind))){const wrap=el('span',undefined,'ssh-quick-item'),button=el('button',item.name,'secondary'),tip=el('span',item.help+'\nComando: '+item.command,'ssh-command-tooltip');button.type='button';tip.id='ssh-catalog-tip-'+root.children.length;tip.setAttribute('role','tooltip');button.onclick=()=>{$('#ssh-catalog-command').value=item.command;$('#ssh-catalog-command').focus()};const info=el('button','i','ssh-command-info');info.type='button';info.setAttribute('aria-label','Informações sobre '+item.name);info.setAttribute('aria-describedby',tip.id);const infoWrap=el('span',undefined,'ssh-info-wrap');infoWrap.append(info,tip);attachSSHInfoTooltip(infoWrap,info,tip);wrap.append(button,infoWrap);root.append(wrap)}renderSSHCatalogTargets()}
$('#ssh-catalog-target').onchange=()=>{$('#ssh-catalog-execute').disabled=!$('#ssh-catalog-target').value};
$('#ssh-catalog-execute').onclick=()=>run(async()=>{const view=sshViews.get($('#ssh-catalog-target').value);if(!view||view.closed||view.terminal.options.disableStdin)throw Error('Selecione um terminal conectado.');const command=$('#ssh-catalog-command').value.trim();if(!command||/[\x00\x1b]/.test(command))throw Error('Informe um comando válido.');const bytes=new TextEncoder().encode(command+'\r');for(let i=0;i<bytes.length;i+=4096){const part=bytes.slice(i,i+4096);view.input=view.input.then(()=>api('/api/ssh/sessions/'+encodeURIComponent(view.id)+'/input','POST',{data:sshEncode(part)}))}await view.input});
renderSSHQuickCatalog();
