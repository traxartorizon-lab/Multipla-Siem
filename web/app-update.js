'use strict';
async function refreshAppUpdate(){
 if(snapshot?.group!=='superadmin')return;
 const text=document.getElementById('app-update-status');
 try{const data=await api('/api/system/update'),s=data.status||{};text.textContent=s.LoadState!=='loaded'?'Atualização pelo app ainda não habilitada no servidor.':s.ActiveState==='activating'?'Atualização em andamento. Aguarde o servidor voltar.':'Versão '+data.version+' · serviço '+s.ActiveState+' · último resultado: '+(s.Result||'—');document.getElementById('app-update-start').disabled=s.LoadState!=='loaded'||['active','activating'].includes(s.ActiveState)}catch(e){text.textContent=e.message}
}
document.getElementById('app-update-status-refresh').onclick=refreshAppUpdate;
document.getElementById('app-update-start').onclick=()=>document.getElementById('app-update-dialog').showModal();
document.getElementById('app-update-cancel').onclick=()=>{document.getElementById('app-update-form').reset();document.getElementById('app-update-dialog').close()};
document.getElementById('app-update-form').onsubmit=async event=>{
 event.preventDefault();const form=event.currentTarget,button=form.querySelector('[type=submit]');button.disabled=true;
 const payload={confirm:form.elements.confirm.value,password:form.elements.password.value};form.elements.password.value='';
 try{const result=await api('/api/system/update','POST',payload);document.getElementById('app-update-dialog').close();form.reset();document.getElementById('app-update-status').textContent=result.message;toast(result.message)}catch(error){document.getElementById('app-update-result').textContent=error.message}finally{payload.password='';button.disabled=false}
};
