'use strict';
fetch('/auth/options').then(r=>r.json()).then(options=>{
 const google=document.querySelector('.google');
 document.querySelector('form[action="/auth/password"]').hidden=!options.local_ready;
 document.querySelector('form[action="/auth/local"]').hidden=options.local_ready;
 if(!options.google_ready){google.removeAttribute('href');google.textContent='Google SSO ainda não configurado';google.setAttribute('aria-disabled','true')}
 if(!options.local_ready){const p=document.createElement('p');p.textContent='Primeiro acesso: use o código exclusivo mostrado no console do servidor para cadastrar sua conta.';document.querySelector('.login-card h1').after(p)}
}).catch(()=>{});

// Keep errors inside the login screen and submit with the browser's real Origin.
for(const form of document.querySelectorAll('form')){
 const status=document.createElement('p');status.setAttribute('role','alert');status.hidden=true;form.append(status);
 form.addEventListener('submit',async event=>{
  event.preventDefault();const button=form.querySelector('button');button.disabled=true;status.hidden=true;
  try{
   const response=await fetch(form.action,{method:'POST',credentials:'same-origin',body:new URLSearchParams(new FormData(form))});
   if(response.ok&&response.redirected){const target=new URL(response.url);if(target.origin===location.origin&&target.pathname==='/'){location.assign('/');return}}
   status.textContent=response.ok?'Não foi possível concluir o acesso.':(await response.text()).trim().slice(0,300);status.hidden=false;
  }catch{status.textContent='Não foi possível conectar ao servidor. Tente novamente.';status.hidden=false}
  finally{button.disabled=false}
 });
}
