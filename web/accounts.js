
'use strict';
async function renderAccounts(){
 if(snapshot.group!=='superadmin')return;
 const data=await api('/api/accounts');
 table('#accounts-list',['EMAIL','PERFIL','ACESSO LOCAL','ESTADO','AÇÃO'],data.accounts.map(account=>[
  account.email,({alerts:'Somente alertas',administrative:'Administrativo',superadmin:'Superadmin','legacy-viewer':'Visualização (legado)'})[account.group],account.local_login?'Sim':'Somente Google',account.disabled?'Desativada':'Ativa',account.primary?'Principal':action('Editar',()=>{const f=$('#accounts-form');f.elements.email.value=account.email;f.elements.email.readOnly=true;f.elements.group.value=account.group==='legacy-viewer'?'alerts':account.group;f.elements.disabled.checked=account.disabled;f.elements.password.value='';f.elements.global_access.checked=account.global_access;f.elements.clients.value=(account.clients||[]).join(', ');for(const cap of ['accounts','backup','terminal'])f.elements['cap_'+cap].checked=(account.capabilities||[]).includes(cap);f.scrollIntoView({block:'center'});})
 ]));
}
$('#accounts-cancel').onclick=()=>{const f=$('#accounts-form');f.reset();f.elements.email.readOnly=false;};
form('#accounts-form',async data=>{await api('/api/accounts','PUT',{email:data.get('email'),group:data.get('group'),password:data.get('password'),disabled:data.has('disabled'),global_access:data.has('global_access'),clients:String(data.get('clients')||'').split(',').map(x=>x.trim()).filter(Boolean),capabilities:['accounts','backup','terminal'].filter(cap=>data.has('cap_'+cap))});$('#accounts-cancel').click();});
