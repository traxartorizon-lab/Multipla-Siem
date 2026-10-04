'use strict';
fetch('/auth/options').then(r=>r.json()).then(options=>{
 const google=document.querySelector('.google');
 document.querySelector('form[action="/auth/password"]').hidden=!options.local_ready;
 document.querySelector('form[action="/auth/local"]').hidden=options.local_ready;
 if(!options.google_ready){google.removeAttribute('href');google.textContent='Google SSO ainda não configurado';google.setAttribute('aria-disabled','true')}
 if(!options.local_ready){const p=document.createElement('p');p.textContent='Primeiro acesso: use o código exclusivo mostrado no console do servidor para cadastrar sua conta.';document.querySelector('.login-card h1').after(p)}
}).catch(()=>{});
