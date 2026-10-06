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
 $('#ssh-selection-title').textContent='Selecionar '+(sshKind==='pfsense'?'pfSense':'Proxmox')+' cadastrados';renderSSHSelectionStatus();
}
function renderSSHSelectionStatus(){const count=sshChosen().length;$('#ssh-selection-status').textContent=count+' equipamentos selecionados. Até quatro terminais simultâneos.';$('#ssh-check-identities').disabled=count<1||count>4}
document.querySelectorAll('[data-ssh-kind]').forEach(button=>button.onclick=()=>{sshKind=button.dataset.sshKind;sshClients.clear();sshUnits.clear();renderSSHSelectors()});
$('#ssh-check-identities').onclick=()=>run(async()=>{
 const selected=sshChosen();if(!selected.length||selected.length>4)throw Error('Selecione de um a quatro equipamentos.');const root=$('#ssh-host-identities');root.replaceChildren();
 for(const d of selected){
  const card=el('div',undefined,'ssh-host-identity');card.append(el('h3',d.client+' / '+d.unit+' · '+d.name));root.append(card);
  try{const data=await api('/api/ssh/identity','POST',{id:d.id});sshIdentities.set(d.id,data);card.append(el('p',data.identity.fingerprint));
   if(data.trusted)card.append(el('p','Identificação já confirmada.'));
   else{if(data.previous_fingerprint)card.append(el('p','ATENÇÃO: identificação anterior diferente: '+data.previous_fingerprint));card.append(el('p','Compare esta identificação com a obtida diretamente no equipamento, por um canal confiável.'));
    card.append(action('Confirmar identificação',async()=>{if(!confirm('Você conferiu a identificação SSH de '+d.name+' por um canal confiável?\n'+data.identity.fingerprint))return;await api('/api/ssh/trust','POST',{id:d.id,key:data.identity.key});data.trusted=true;card.append(el('p','Identificação confirmada e salva.'))}));
   }
  }catch(e){card.append(el('p',e.message))}
 }
});
function sshEncode(bytes){return btoa(String.fromCharCode(...bytes))}
function sshDecode(text){return Uint8Array.from(atob(text),c=>c.charCodeAt(0))}
function createSSHView(data){
 for(const [id,old] of sshViews){if(old.closed){old.terminal.dispose();old.card.remove();sshViews.delete(id)}}
 const d=data.equipment,card=el('article',undefined,'panel form-panel ssh-terminal-card'),heading=el('div',undefined,'panel-heading'),status=el('p','Conectando…'),screen=el('div',undefined,'ssh-terminal-screen');
 heading.append(el('h3',d.client+' / '+d.unit+' · '+d.name+' · '+(d.kind==='pfsense'?'pfSense':'Proxmox')));card.append(heading,status,screen);$('#ssh-terminals').append(card);
 const terminal=new Terminal({cols:100,rows:24,scrollback:1000,disableStdin:true,theme:{background:'#0b1219',foreground:'#d9e5ef'},fontSize:13,allowProposedApi:false});terminal.open(screen);
 // Remote servers may print terminal escapes; never grant clipboard access through OSC 52.
 terminal.parser.registerOscHandler(52,()=>true);terminal.parser.registerOscHandler(8,()=>true);
 const view={id:data.id,terminal,status,card,offset:0,busy:false,closed:false,input:Promise.resolve()};sshViews.set(view.id,view);
 const close=action('Encerrar sessão',async()=>{await api('/api/ssh/sessions/'+encodeURIComponent(view.id)+'/close','POST',{});view.closed=true;view.terminal.options.disableStdin=true;status.textContent='Sessão encerrada.'});heading.append(close);
 const form=el('form',undefined,'ssh-command-form'),preset=el('select'),empty=el('option','Selecione um teste rápido');empty.value='';preset.append(empty);
 const availableTests=SSH_QUICK_TESTS.filter(item=>!item.kinds||item.kinds.includes(d.kind));
 for(const item of availableTests){const option=el('option',item.name);option.value=item.command;preset.append(option)}
 const label=el('label','Comando · revise antes de enviar'),command=el('textarea');command.rows=3;command.maxLength=8192;command.spellcheck=false;command.autocomplete='off';label.append(command);
 const help=el('p','Selecione um teste para consultar as instruções.'),send=el('button','Executar no equipamento');send.type='submit';preset.onchange=()=>{command.value=preset.value;help.textContent=SSH_QUICK_TESTS.find(item=>item.command===preset.value)?.help||'Selecione um teste para consultar as instruções.';command.focus()};const buttons=el('div',undefined,'ssh-quick-buttons');
 for(const item of availableTests){const wrap=el('span',undefined,'ssh-quick-item'),button=el('button',item.name, 'secondary'),tip=el('span',item.help+'\nComando: '+item.command,'ssh-command-tooltip');button.type='button';tip.id='ssh-tip-'+data.id+'-'+buttons.children.length;tip.setAttribute('role','tooltip');button.setAttribute('aria-describedby',tip.id);button.onclick=()=>{preset.value=item.command;command.value=item.command;help.textContent=item.help;command.focus()};wrap.append(button,tip);buttons.append(wrap)}
 form.append(buttons,preset,help,label,send,el('p','Revise o comando e seus efeitos. O envio ocorre somente ao clicar em executar.'));card.append(form);
 form.onsubmit=event=>{event.preventDefault();run(async()=>{if(view.closed||view.terminal.options.disableStdin)throw Error('Conecte o terminal antes de executar.');const text=command.value.trim();if(!text)throw Error('Informe um comando.');if(/[\x00\x1b]/.test(text))throw Error('Caracteres de controle inválidos.');const bytes=new TextEncoder().encode(text+'\r');for(let i=0;i<bytes.length;i+=4096){const part=bytes.slice(i,i+4096);view.input=view.input.then(()=>api('/api/ssh/sessions/'+encodeURIComponent(view.id)+'/input','POST',{data:sshEncode(part)}));}await view.input;})};
 terminal.onData(text=>{const bytes=new TextEncoder().encode(text);for(let i=0;i<bytes.length;i+=4096){const part=bytes.slice(i,i+4096);view.input=view.input.then(()=>api('/api/ssh/sessions/'+encodeURIComponent(view.id)+'/input','POST',{data:sshEncode(part)})).catch(e=>{status.textContent=e.message})}});
 return view;
}
$('#ssh-connect-form').onsubmit=e=>{e.preventDefault();run(async()=>{
 const selected=sshChosen();if(!selected.length||selected.length>4)throw Error('Selecione de um a quatro equipamentos.');
 const f=new FormData(e.target),credential={password:String(f.get('password')||''),private_key:String(f.get('private_key')||''),passphrase:String(f.get('passphrase')||'')};
 if(!credential.password&&!credential.private_key)throw Error('Informe a credencial para esta conexão.');e.target.reset();
 try{for(const d of selected){try{const data=await api('/api/ssh/sessions','POST',{id:d.id,...credential});createSSHView(data)}catch(error){toast(d.name+': '+error.message)}}}
 finally{credential.password='';credential.private_key='';credential.passphrase=''}
})};
async function pollSSHTerminal(view){
 if(view.busy||view.closed)return;view.busy=true;
 try{const data=await api('/api/ssh/sessions/'+encodeURIComponent(view.id)+'?offset='+view.offset);if(data.lost)view.terminal.writeln('\r\n[Parte da saída anterior excedeu o limite do buffer.]');if(data.data)view.terminal.write(sshDecode(data.data));view.offset=data.next;view.status.textContent=data.status==='connected'?'Conectado':data.status==='connecting'?'Conectando…':data.message||'Sessão encerrada';view.terminal.options.disableStdin=data.status!=='connected';if(data.status==='closed')view.closed=true}
 catch(error){view.status.textContent=error.message;view.closed=true;view.terminal.options.disableStdin=true}
 finally{view.busy=false}
}
setInterval(()=>{sshViews.forEach(pollSSHTerminal)},500);
