'use strict';
$('#server-terminal-toggle').onclick=()=>{const box=$('#server-terminal-access'),open=box.hidden;box.hidden=!open;$('#server-terminal-toggle').setAttribute('aria-expanded',String(open));if(open)$('#server-terminal-form').elements.user.focus()};
$('#server-terminal-key-file').onchange=async event=>{const file=event.target.files[0];if(!file)return;try{if(file.size>32768)throw Error('A chave deve ter até 32 KiB.');const text=await file.text();if(text.startsWith('PuTTY-User-Key-File-'))throw Error('Exporte a chave no formato OpenSSH pelo PuTTYgen (Conversions → Export OpenSSH key). O arquivo .ppk não é aceito diretamente.');$('#server-terminal-form').elements.private_key.value=text;$('#server-terminal-result').textContent='Chave carregada somente para esta conexão.'}catch(error){$('#server-terminal-result').textContent=error.message}finally{event.target.value=''}};
$('#server-terminal-form').onsubmit=async event=>{
 event.preventDefault();const form=event.target,button=form.querySelector('button[type="submit"]'),result=$('#server-terminal-result');button.disabled=true;let credential;
 try{
  const values=new FormData(form);credential={user:String(values.get('user')||'').trim(),password:String(values.get('password')||''),private_key:String(values.get('private_key')||''),passphrase:String(values.get('passphrase')||'')};form.elements.password.value='';form.elements.private_key.value='';form.elements.passphrase.value='';
  credential={user:'multipla-ops'};
  result.textContent='Verificando a identificação SSH do servidor local…';const device={id:'__multipla_local_server__',name:'Servidor SIEM',ip:'127.0.0.1',ssh_port:22,client:'Manutenção',unit:'Servidor local'};
  await sshEnsureTrusted(device);const data=await api('/api/ssh/sessions','POST',{id:device.id,...credential});createSSHView(data,'#server-terminal-sessions');result.textContent='Conexão solicitada. Acompanhe a autenticação no terminal abaixo.';
 }catch(error){result.textContent=error.message}finally{if(credential){credential.password='';credential.private_key='';credential.passphrase=''}button.disabled=false}
};
