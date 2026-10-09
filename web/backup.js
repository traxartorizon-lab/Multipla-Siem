'use strict';
async function renderBackups(){
 $('#full-backup-command').textContent='/usr/local/bin/multipla-siem -full-backup -backup-drive '+shellQuoteBackupEmail(snapshot.email)+'\n\nAgendar diariamente:\n/usr/local/bin/multipla-siem -full-backup-schedule '+shellQuoteBackupEmail(snapshot.email);
 const p=snapshot.preferences,f=$('#preferences-form');
 if(!f.contains(document.activeElement)){
  ['default_page','refresh_seconds','alert_min_level','backup_time','backup_timezone'].forEach(k=>f.elements[k].value=p[k]);
  ['backup_daily','backup_drive'].forEach(k=>f.elements[k].checked=p[k]);
 }
 f.elements.backup_drive.disabled=!snapshot.drive_connected;
 $('#drive-status').textContent=snapshot.drive_connected?'Drive conectado à conta '+snapshot.email:'Drive não conectado. Entre com Google e autorize o acesso para usar backups na nuvem.';
 $('#drive-connect').disabled=snapshot.demo||snapshot.email==='bootstrap';
 const data=await api('/api/backups');
 $('#backup-status').textContent=data.status?.attempt&&new Date(data.status.attempt).getFullYear()>2000?'Última tentativa: '+date(data.status.attempt)+' · '+data.status.result:'Nenhum backup automático ou manual registrado';
 table('#backup-list',['CÓPIA LOCAL','TAMANHO','AÇÕES'],(data.files||[]).map(b=>{
  const actions=el('div');
  actions.append(action('Baixar',()=>{location.href='/api/backups/'+encodeURIComponent(b.id)}),action('Restaurar',async()=>{if(confirmRestore())await api('/api/backups/'+encodeURIComponent(b.id)+'/restore','POST',{})}));
  return[date(b.created),b.size+' bytes',actions];
 }));
}
function confirmRestore(){return confirm('Restaurar esta configuração e suas regras? As credenciais e o endereço deste servidor serão preservados. Publicação de bloqueios e agendamentos serão pausados para revisão.')}
form('#preferences-form',f=>api('/api/preferences','PUT',{
 dashboard_order:snapshot.preferences?.dashboard_order||[],dashboard_cards:snapshot.preferences?.dashboard_cards||{},default_page:f.get('default_page'),refresh_seconds:Number(f.get('refresh_seconds')),alert_min_level:Number(f.get('alert_min_level')),
 backup_daily:f.has('backup_daily'),backup_time:f.get('backup_time'),backup_timezone:f.get('backup_timezone'),backup_drive:f.has('backup_drive')
}));
$('#backup-export').onclick=()=>{location.href='/api/backup/export'};
$('#backup-create').onclick=()=>run(()=>api('/api/backup/create','POST',{}));
$('#backup-import').onclick=()=>run(async()=>{
 const file=$('#backup-file').files[0];if(!file)throw Error('Selecione um arquivo JSON');if(file.size>1048576)throw Error('O limite é 1 MiB');
 const data=JSON.parse(await file.text());if(confirmRestore())await api('/api/backup/import','POST',data);
});
$('#drive-connect').onclick=()=>run(async()=>{const data=await api('/api/drive/connect','POST',{});location.href=data.url});
$('#drive-disconnect').onclick=()=>run(()=>api('/api/drive/disconnect','POST',{}));
$('#drive-list').onclick=()=>run(async()=>{
 const data=await api('/api/drive/backups');
 table('#drive-backup-list',['BACKUP NO DRIVE','CRIADO','AÇÃO'],(data.files||[]).map(b=>[
  b.name,date(b.createdTime),action('Restaurar',async()=>{if(confirmRestore())await api('/api/drive/backups/'+encodeURIComponent(b.id)+'/restore','POST',{})})
 ]));
});

function shellQuoteBackupEmail(email){return "'"+String(email).replaceAll("'","'\\''")+"'";}
