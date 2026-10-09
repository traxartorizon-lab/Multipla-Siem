'use strict';
const dashboardDefaultOrder=['collection','alerts','devices','response','resources','activity','recent-alerts','posture'];
let dashboardCardSettings={},dashboardAppliedKey="";
const resourceTemplate=document.querySelector('[data-dashboard-card="resources"]').cloneNode(true);
let dashboardEditing=false,dashboardSaving=false,dashboardDragged=null;
function normalizeDashboardOrder(order){return [...new Set([...(Array.isArray(order)?order:[]),...dashboardDefaultOrder])].filter(id=>dashboardDefaultOrder.includes(id)||/^resources-[2-8]$/.test(id))}
function dashboardOrder(){return [...$('#dashboard-grid').children].map(n=>n.dataset.dashboardCard)}
function applyDashboardOrder(order){const grid=$('#dashboard-grid');normalizeDashboardOrder(order).forEach(id=>{const card=[...grid.children].find(n=>n.dataset.dashboardCard===id);if(card)grid.append(card)});updateDashboardMoveButtons()}
function syncDashboardLayout(order){
 if(dashboardEditing)return;
 const settings=snapshot?.preferences?.dashboard_cards||{},key=JSON.stringify([order,settings]);if(key===dashboardAppliedKey)return;
 dashboardAppliedKey=key;dashboardCardSettings=structuredClone(settings);reconcileResourceCards(order||[]);applyDashboardOrder(order);applyDashboardSizes();
}
function reconcileResourceCards(order){
 const grid=$('#dashboard-grid'),wanted=new Set(order.filter(id=>/^resources-[2-8]$/.test(id)));
 grid.querySelectorAll('[data-resource-copy]').forEach(card=>{if(!wanted.has(card.dataset.dashboardCard))card.remove()});
 for(const id of wanted){if([...grid.children].some(c=>c.dataset.dashboardCard===id))continue;const card=resourceTemplate.cloneNode(true);card.dataset.dashboardCard=id;card.dataset.resourceCopy='true';card.querySelectorAll('[id]').forEach(n=>{n.dataset.resourceRole=n.id;n.removeAttribute('id')});grid.append(card);setupDashboardCard(card)}
}
function applyDashboardSizes(){for(const card of $('#dashboard-grid').children){const c=dashboardCardSettings[card.dataset.dashboardCard]||{};const ratio=c.width_basis_points || (c.width ? c.width*2500 : 0);card.style.setProperty('--card-basis',ratio?'calc('+ratio/100+'% - '+(12*(1-ratio/10000)).toFixed(3)+'px)':'');card.style.minHeight=c.height?c.height+'px':'';card.classList.toggle('custom-width',!!ratio)}}
function setupDashboardResize(card){
 for(const edge of ['right','bottom','corner']){
  const handle=el('button');handle.type='button';handle.className='dashboard-resize dashboard-resize-'+edge;
  handle.setAttribute('aria-label',edge==='right'?'Redimensionar largura':edge==='bottom'?'Redimensionar altura':'Redimensionar largura e altura');
  handle.title='Arraste para redimensionar; use as setas para ajustes';card.append(handle);
  const update=(width,height)=>{const grid=$('#dashboard-grid'),id=card.dataset.dashboardCard,c={...(dashboardCardSettings[id]||{})};
   if(edge!=='bottom'){c.width_basis_points=Math.round(Math.min(1,Math.max(Math.min(240,grid.clientWidth),width)/grid.clientWidth)*10000);delete c.width}
   if(edge!=='right')c.height=Math.round(Math.max(120,Math.min(2400,height)));
   dashboardCardSettings[id]=c;applyDashboardSizes();
  };
  let drag=null;
  const finish=(cancel=false)=>{if(!drag)return;if(cancel){if(drag.previous)dashboardCardSettings[card.dataset.dashboardCard]=drag.previous;else delete dashboardCardSettings[card.dataset.dashboardCard];applyDashboardSizes()}
   const pointer=drag.pointer;drag=null;card.classList.remove('resizing');document.body.classList.remove('dashboard-resizing');if(handle.hasPointerCapture(pointer))handle.releasePointerCapture(pointer);
  };
  handle.addEventListener('pointerdown',e=>{if(!dashboardEditing||dashboardSaving||e.button!==0)return;e.preventDefault();const rect=card.getBoundingClientRect();drag={pointer:e.pointerId,x:e.clientX,y:e.clientY,width:rect.width,height:rect.height,previous:dashboardCardSettings[card.dataset.dashboardCard]?structuredClone(dashboardCardSettings[card.dataset.dashboardCard]):null};handle.setPointerCapture(e.pointerId);card.classList.add('resizing');document.body.classList.add('dashboard-resizing')});
  handle.addEventListener('pointermove',e=>{if(drag&&e.pointerId===drag.pointer)update(drag.width+e.clientX-drag.x,drag.height+e.clientY-drag.y)});
  handle.addEventListener('pointerup',()=>finish());handle.addEventListener('pointercancel',()=>finish(true));handle.addEventListener('lostpointercapture',()=>finish(true));
  handle.addEventListener('keydown',e=>{if(e.key==='Escape'&&drag){e.preventDefault();finish(true);return}if(!dashboardEditing||dashboardSaving||!['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(e.key))return;e.preventDefault();const rect=card.getBoundingClientRect(),step=e.shiftKey?40:10;update(rect.width+(e.key==='ArrowRight'?step:e.key==='ArrowLeft'?-step:0),rect.height+(e.key==='ArrowDown'?step:e.key==='ArrowUp'?-step:0))});
 }
}
function addResourceCard(){if(!dashboardEditing||dashboardSaving)return;const order=dashboardOrder();const id=Array.from({length:7},(_,i)=>'resources-'+(i+2)).find(id=>!order.includes(id));if(!id){toast('Limite de oito cards de recursos.');return}order.push(id);dashboardCardSettings[id]={width:2};reconcileResourceCards(order);applyDashboardOrder(order);applyDashboardSizes();setDashboardEditing(true);renderDashboardResources(snapshot)}
const addResourceButton=el('button','Adicionar monitoramento','secondary');addResourceButton.type='button';addResourceButton.hidden=true;$('#dashboard-edit').after(addResourceButton);addResourceButton.onclick=addResourceCard;
function updateDashboardMoveButtons(){const cards=[...$('#dashboard-grid').children];cards.forEach((card,i)=>{card.querySelector('[data-move="-1"]').disabled=i===0;card.querySelector('[data-move="1"]').disabled=i===cards.length-1})}
function setDashboardEditing(value){dashboardEditing=value;addResourceButton.hidden=!value;$('#dashboard-grid').classList.toggle('organizing',value);document.querySelectorAll('.dashboard-move-controls').forEach(n=>n.hidden=!value);$('#dashboard-edit').hidden=value;['save','cancel','reset'].forEach(id=>$('#dashboard-'+id).hidden=!value);$('#dashboard-layout-status').textContent=value?'Arraste as bordas ou o canto inferior para redimensionar. Use a alça para mover e salve ao terminar.':'';updateDashboardMoveButtons()}
$('#dashboard-edit').onclick=()=>setDashboardEditing(true);
$('#dashboard-cancel').onclick=()=>{if(dashboardSaving)return;setDashboardEditing(false);dashboardAppliedKey="";syncDashboardLayout(snapshot?.preferences?.dashboard_order);renderDashboardResources(snapshot)};
$('#dashboard-reset').onclick=()=>{if(!dashboardSaving){dashboardCardSettings={};reconcileResourceCards([]);applyDashboardOrder(dashboardDefaultOrder);applyDashboardSizes()}};
$('#dashboard-save').onclick=async()=>{
 if(dashboardSaving)return;
 dashboardSaving=true;$('#dashboard-save').disabled=true;$('#dashboard-cancel').disabled=true;$('#dashboard-reset').disabled=true;
 $('#dashboard-layout-status').textContent='Salvando disposição…';
 try{
  const order=dashboardOrder();await api('/api/dashboard/layout','PUT',{order,cards:dashboardCardSettings});
  if(snapshot){snapshot.preferences=snapshot.preferences||{};snapshot.preferences.dashboard_order=order;snapshot.preferences.dashboard_cards=structuredClone(dashboardCardSettings);dashboardAppliedKey=""}
  setDashboardEditing(false);$('#dashboard-layout-status').textContent='Disposição salva para sua conta.';
 }catch(e){$('#dashboard-layout-status').textContent='Não foi possível salvar. Sua disposição continua em edição.';toast(e.message)}
 finally{dashboardSaving=false;$('#dashboard-save').disabled=false;$('#dashboard-cancel').disabled=false;$('#dashboard-reset').disabled=false}
};
function setupDashboardCard(card){
 const tools=card.querySelector('.dashboard-move-controls');setupDashboardResize(card);
 if(card.dataset.resourceCopy){const remove=el('button','Remover','secondary');remove.onclick=()=>{if(dashboardSaving)return;delete dashboardCardSettings[card.dataset.dashboardCard];card.remove();updateDashboardMoveButtons()};tools.append(remove)}

 card.querySelectorAll('[data-move]').forEach(button=>button.onclick=()=>{
  if(!dashboardEditing||dashboardSaving)return;
  const order=dashboardOrder(),i=order.indexOf(card.dataset.dashboardCard),next=i+Number(button.dataset.move);
  if(next<0||next>=order.length)return;
  [order[i],order[next]]=[order[next],order[i]];applyDashboardOrder(order);button.focus();
 });
 const handle=card.querySelector('.dashboard-drag');
 handle.addEventListener('dragstart',e=>{if(!dashboardEditing||dashboardSaving){e.preventDefault();return}dashboardDragged=card.dataset.dashboardCard;e.dataTransfer.effectAllowed='move';e.dataTransfer.setData('text/plain',dashboardDragged);card.classList.add('dragging')});
 handle.addEventListener('dragend',()=>{dashboardDragged=null;document.querySelectorAll('[data-dashboard-card]').forEach(n=>n.classList.remove('dragging','drop-target'))});
 card.addEventListener('dragover',e=>{if(dashboardEditing&&!dashboardSaving&&dashboardDragged&&dashboardDragged!==card.dataset.dashboardCard){e.preventDefault();e.dataTransfer.dropEffect='move';card.classList.add('drop-target')}});
 card.addEventListener('dragleave',e=>{if(!card.contains(e.relatedTarget))card.classList.remove('drop-target')});
 card.addEventListener('drop',e=>{
  if(!dashboardEditing||dashboardSaving||!dashboardDragged)return;e.preventDefault();card.classList.remove('drop-target');
  const order=dashboardOrder().filter(id=>id!==dashboardDragged),i=order.indexOf(card.dataset.dashboardCard);
  if(i<0)return;order.splice(i,0,dashboardDragged);applyDashboardOrder(order);
 });
}
document.querySelectorAll('[data-dashboard-card]').forEach(setupDashboardCard);

function setMobileNavigation(open){
 const toggle=document.getElementById('navigation-toggle'),nav=document.getElementById('main-navigation');
 document.body.classList.toggle('navigation-open',open);toggle.setAttribute('aria-expanded',String(open));toggle.setAttribute('aria-label',open?'Fechar menu':'Abrir menu');document.getElementById('navigation-backdrop').hidden=!open;
 if(open)nav.querySelector('.nav.active')?.focus();else toggle.focus();
}
document.getElementById('navigation-toggle').onclick=()=>setMobileNavigation(!document.body.classList.contains('navigation-open'));
document.getElementById('navigation-backdrop').onclick=()=>setMobileNavigation(false);
document.querySelectorAll('.sidebar .nav').forEach(button=>button.addEventListener('click',()=>{if(document.body.classList.contains('navigation-open'))setMobileNavigation(false)}));
document.addEventListener('keydown',event=>{if(event.key==='Escape'&&document.body.classList.contains('navigation-open'))setMobileNavigation(false);if(event.key==='Tab'&&document.body.classList.contains('navigation-open')){const buttons=[...document.querySelectorAll('.sidebar button:not([hidden]),#navigation-toggle')].filter(x=>x.getClientRects().length);const first=buttons[0],last=buttons[buttons.length-1];if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus()}else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus()}}});
window.matchMedia('(max-width:900px)').addEventListener('change',event=>{if(!event.matches&&document.body.classList.contains('navigation-open'))setMobileNavigation(false)});
