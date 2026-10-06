'use strict';
const dashboardDefaultOrder=['collection','alerts','devices','response','activity','posture','recent-alerts'];
let dashboardEditing=false,dashboardSaving=false,dashboardDragged=null;
function normalizeDashboardOrder(order){return [...new Set([...(Array.isArray(order)?order:[]),...dashboardDefaultOrder])].filter(id=>dashboardDefaultOrder.includes(id))}
function dashboardOrder(){return [...$('#dashboard-grid').children].map(n=>n.dataset.dashboardCard)}
function applyDashboardOrder(order){const grid=$('#dashboard-grid');normalizeDashboardOrder(order).forEach(id=>{const card=[...grid.children].find(n=>n.dataset.dashboardCard===id);if(card)grid.append(card)});updateDashboardMoveButtons()}
function syncDashboardLayout(order){if(!dashboardEditing)applyDashboardOrder(order)}
function updateDashboardMoveButtons(){const cards=[...$('#dashboard-grid').children];cards.forEach((card,i)=>{card.querySelector('[data-move="-1"]').disabled=i===0;card.querySelector('[data-move="1"]').disabled=i===cards.length-1})}
function setDashboardEditing(value){dashboardEditing=value;$('#dashboard-grid').classList.toggle('organizing',value);document.querySelectorAll('.dashboard-move-controls').forEach(n=>n.hidden=!value);$('#dashboard-edit').hidden=value;['save','cancel','reset'].forEach(id=>$('#dashboard-'+id).hidden=!value);$('#dashboard-layout-status').textContent=value?'Arraste pela alça ou use as setas.':'';updateDashboardMoveButtons()}
$('#dashboard-edit').onclick=()=>setDashboardEditing(true);
$('#dashboard-cancel').onclick=()=>{if(dashboardSaving)return;setDashboardEditing(false);applyDashboardOrder(snapshot?.preferences?.dashboard_order)};
$('#dashboard-reset').onclick=()=>{if(!dashboardSaving)applyDashboardOrder(dashboardDefaultOrder)};
$('#dashboard-save').onclick=async()=>{
 if(dashboardSaving)return;
 dashboardSaving=true;$('#dashboard-save').disabled=true;$('#dashboard-cancel').disabled=true;$('#dashboard-reset').disabled=true;
 $('#dashboard-layout-status').textContent='Salvando disposição…';
 try{
  const order=dashboardOrder();await api('/api/dashboard/layout','PUT',{order});
  if(snapshot){snapshot.preferences=snapshot.preferences||{};snapshot.preferences.dashboard_order=order}
  setDashboardEditing(false);$('#dashboard-layout-status').textContent='Disposição salva para sua conta.';
 }catch(e){$('#dashboard-layout-status').textContent='Não foi possível salvar. Sua disposição continua em edição.';toast(e.message)}
 finally{dashboardSaving=false;$('#dashboard-save').disabled=false;$('#dashboard-cancel').disabled=false;$('#dashboard-reset').disabled=false}
};
document.querySelectorAll('[data-dashboard-card]').forEach(card=>{
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
});
