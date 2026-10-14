
'use strict';
async function renderAccounts(){
 if(snapshot.group!=='superadmin')return;
 const data=await api('/api/accounts');
 table('#accounts-list',['EMAIL','PERFIL','ACESSO LOCAL','ESTADO','AÇÃO'],data.accounts.map(account=>[
  account.email,({alerts:'Somente alertas',administrative:'Administrativo',superadmin:'Superadmin','legacy-viewer':'Visualização (legado)'})[account.group],account.local_login?'Sim':'Somente Google',account.disabled?'Desativada':'Ativa',account.primary?'Principal':action('Editar',()=>{const f=$('#accounts-form');f.elements.email.value=account.email;f.elements.email.readOnly=true;f.elements.group.value=account.group==='legacy-viewer'?'alerts':account.group;f.elements.disabled.checked=account.disabled;f.elements.password.value='';f.scrollIntoView({block:'center'});})
 ]));
}
$('#accounts-cancel').onclick=()=>{const f=$('#accounts-form');f.reset();f.elements.email.readOnly=false;};
form('#accounts-form',async data=>{await api('/api/accounts','PUT',{email:data.get('email'),group:data.get('group'),password:data.get('password'),disabled:data.has('disabled')});$('#accounts-cancel').click();});
