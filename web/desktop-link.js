'use strict';
async function refreshDesktopLinks(){
 const list=document.getElementById('desktop-grants');list.replaceChildren();
 try{const data=await api('/api/desktop/grants');for(const grant of data.grants||[]){const row=el('div');row.append(el('span',grant.name+' · vence '+date(grant.expires)+' '));const revoke=el('button','Revogar','secondary');revoke.type='button';revoke.onclick=async()=>{try{await api('/api/desktop/grants/'+encodeURIComponent(grant.id),'DELETE');await refreshDesktopLinks()}catch(e){toast(e.message)}};row.append(revoke);list.append(row)}if(!data.grants?.length)list.append(el('p','Nenhum app vinculado.'))}catch(e){list.append(el('p',e.message))}
}
document.getElementById('desktop-grants-refresh').onclick=refreshDesktopLinks;
document.getElementById('desktop-grant-form').onsubmit=async event=>{
 event.preventDefault();const form=event.currentTarget,button=form.querySelector('button');button.disabled=true;
 try{const data=await api('/api/desktop/grants','POST',{name:form.elements.name.value});const field=document.getElementById('desktop-grant-key');field.value=data.key;document.getElementById('desktop-grant-result').textContent='Cole esta chave no app Windows. Ela permite somente notificações e leitura, vence em '+date(data.expires)+'. Não compartilhe. A chave é exibida uma única vez.';setTimeout(()=>{field.value=''},60000);await refreshDesktopLinks()}catch(e){toast(e.message)}finally{button.disabled=false}
};
