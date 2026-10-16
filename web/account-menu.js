'use strict';
// Move existing forms and controls; their CSRF, confirmation and MFA flows stay intact.
const avatar=document.querySelector('header .avatar'),accountRoot=el('div',undefined,'account-dropdown'),accountButton=el('button','M','avatar'),accountMenu=el('div',undefined,'account-menu');
accountButton.type='button';accountButton.id='account-menu-button';accountButton.setAttribute('aria-label','Menu da conta');accountButton.setAttribute('aria-haspopup','menu');accountButton.setAttribute('aria-expanded','false');accountButton.setAttribute('aria-controls','account-menu');accountMenu.id='account-menu';accountMenu.setAttribute('role','menu');accountMenu.hidden=true;avatar.replaceWith(accountRoot);accountRoot.append(accountButton,accountMenu);
const settingsSubmenu=el('div',undefined,'account-settings-submenu');settingsSubmenu.setAttribute('role','menu');settingsSubmenu.id='account-settings-submenu';settingsSubmenu.hidden=true;
function menuAction(label,fn,superOnly=false){const button=el('button',label,'text-button');button.type='button';button.setAttribute('role','menuitem');if(superOnly)button.dataset.superadminOnly='';button.onclick=()=>{closeAccountMenu();fn()};accountMenu.append(button);return button}
const settingsMenuButton=menuAction('Configurações',()=>{});settingsMenuButton.setAttribute('aria-haspopup','menu');settingsMenuButton.setAttribute('aria-expanded','false');settingsMenuButton.setAttribute('aria-controls',settingsSubmenu.id);settingsMenuButton.onclick=()=>{const open=settingsSubmenu.hidden;settingsSubmenu.hidden=!open;settingsMenuButton.setAttribute('aria-expanded',String(open));if(open)settingsSubmenu.querySelector('button')?.focus()};accountMenu.append(settingsSubmenu);
const general=el('button','Configurações gerais','text-button');general.type='button';general.setAttribute('role','menuitem');general.onclick=()=>{closeAccountMenu();goto('settings')};settingsSubmenu.append(general);
const accountsMenuButton=menuAction('Contas',()=>goto('accounts'));
function serverArea(){goto('server-maintenance')}
menuAction('Manutenção do servidor',serverArea,true);
menuAction('Reiniciar servidor',()=>{serverArea();$('#server-reboot').click()},true);
menuAction('Aplicar atualizações',async()=>{serverArea();await refreshAppUpdate();if(!$('#app-update-start').disabled)$('#app-update-start').click()},true);
menuAction('Conectar ao terminal',()=>{serverArea();if($('#server-terminal-access').hidden)$('#server-terminal-toggle').click();$('#server-terminal-access').scrollIntoView({block:'start'})},true);
menuAction('Sair da conta',()=>$('#logout').click());
function newAccountSection(id,title){const section=el('section',undefined,'page hidden');section.id=id;const heading=el('div',undefined,'page-heading');heading.append(el('h1',title));section.append(heading);$('.content').append(section);return section}
const accountsPage=newAccountSection('accounts','Contas'),maintenancePage=newAccountSection('server-maintenance','Manutenção do servidor');
accountsPage.append($('#accounts-form').closest('article'));
maintenancePage.append($('#server-reboot').closest('article'),$('#app-update-status').closest('article'));
document.querySelector('.nav[data-page="settings"]')?.remove();
function visibleAccountItems(){return [...accountMenu.querySelectorAll('[role="menuitem"]')].filter(n=>!n.hidden&&!n.closest('[hidden]'))}
function closeAccountMenu(focus=false){accountMenu.hidden=true;settingsSubmenu.hidden=true;accountButton.setAttribute('aria-expanded','false');settingsMenuButton.setAttribute('aria-expanded','false');if(focus)accountButton.focus()}
accountButton.onclick=()=>{const open=accountMenu.hidden;accountMenu.hidden=!open;accountButton.setAttribute('aria-expanded',String(open));if(open)visibleAccountItems()[0]?.focus()};
accountButton.addEventListener('keydown',event=>{if(event.key==='ArrowDown'||event.key==='ArrowUp'){event.preventDefault();event.stopPropagation();accountMenu.hidden=false;accountButton.setAttribute('aria-expanded','true');const items=visibleAccountItems();(event.key==='ArrowDown'?items[0]:items.at(-1))?.focus()}});
accountRoot.addEventListener('keydown',event=>{if(event.key==='Escape'){event.preventDefault();event.stopPropagation();closeAccountMenu(true);return}const items=visibleAccountItems(),index=items.indexOf(document.activeElement);if(['ArrowDown','ArrowUp','Home','End'].includes(event.key)){event.preventDefault();const next=event.key==='Home'?0:event.key==='End'?items.length-1:(index+(event.key==='ArrowDown'?1:-1)+items.length)%items.length;items[next]?.focus()}if(event.key==='Tab')closeAccountMenu()});
document.addEventListener('pointerdown',event=>{if(!accountRoot.contains(event.target))closeAccountMenu()});
function syncAccountMenu(){const superadmin=snapshot?.group==='superadmin'&&!snapshot?.scoped;accountMenu.querySelectorAll('[data-superadmin-only]').forEach(n=>n.hidden=!superadmin);settingsMenuButton.hidden=!accessPageAllowed('settings')||snapshot?.role==='viewer';accountsMenuButton.hidden=!canManageAccounts();accountButton.title=(snapshot?.email||'Conta')+' · Menu da conta';if(!accessPageAllowed(page))goto('overview')}
