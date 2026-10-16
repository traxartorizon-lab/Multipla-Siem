namespace Multipla.Siem.Desktop;

// Only explicit isolated test construction supplies these delegates. Production
// always uses the native dialog and the signed update runtime.
internal sealed record DesktopUpdateUiFixture(DesktopUpdateState Cache,Func<Task<DesktopUpdateCandidate?>> Check,Func<DesktopUpdateCandidate,bool,Task> Apply,Func<string,bool> Confirm,Action Ready);
internal partial class PanelWindow
{
    readonly System.Windows.Forms.Timer updateTimer=new(){Interval=60000};
    readonly ToolStripMenuItem appUpdateMenu=new("Atualizar aplicativo Windows · verificar agora");
    DesktopUpdateCandidate? appUpdateCandidate;
    DateTimeOffset nextAppUpdateCheck;
    bool appUpdateBusy;
    int appUpdateFailures;
    DesktopUpdateUiFixture? updateFixture;
    void InitializeAppUpdates(ContextMenuStrip menu,bool isolated,DesktopUpdateUiFixture? fixture)
    {
        if(isolated&&fixture==null)return;
        if(!isolated&&fixture!=null)throw new InvalidOperationException("Fixture de atualização exige modo isolado.");updateFixture=fixture;
        menu.Items.Add(appUpdateMenu);appUpdateMenu.Click+=async(_,_)=>await CheckAppUpdate(true);
        nextAppUpdateCheck=DateTimeOffset.UtcNow.AddSeconds(Random.Shared.Next(30,91));
        updateTimer.Tick+=async(_,_)=>{if(DateTimeOffset.UtcNow>=nextAppUpdateCheck)await CheckAppUpdate(false);};
        Shown+=(_,_)=>
        {
            try{if(updateFixture!=null)updateFixture.Ready();else DesktopUpdateRuntime.Production().Ready();}catch{appUpdateMenu.Text="Atualização do aplicativo · falha ao confirmar inicialização";}
            updateTimer.Start();
        };
    }
    async Task CheckAppUpdate(bool manual)
    {
        if(appUpdateBusy||exiting)return;
        if(appUpdateCandidate!=null){if(manual)await ConfirmAppUpdate();return;}
        appUpdateBusy=true;appUpdateMenu.Enabled=false;
        try
        {
            var cache=updateFixture?.Cache??DesktopUpdateState.Production();DateTimeOffset last;
            using(var operation=cache.Exclusive())
            {
                var selected=cache.Read();last=selected.LastCheck;
                var minimum=manual?TimeSpan.FromMinutes(1):TimeSpan.FromHours(6);
                if(last+minimum>DateTimeOffset.UtcNow){nextAppUpdateCheck=last+minimum;if(manual)MessageBox.Show(this,"Verificação recente. Aguarde um minuto antes de tentar novamente.","Atualização do aplicativo Windows");return;}
                cache.Write(selected with{LastCheck=DateTimeOffset.UtcNow});
            }
            appUpdateMenu.Text="Aplicativo Windows · verificando atualização…";
            // Parsing, hashing and disk I/O run away from the UI thread. Only a
            // non-executable archive is staged before the native confirmation.
            if(updateFixture!=null)appUpdateCandidate=await updateFixture.Check();
            else{using var client=new DesktopUpdateClient(cache);appUpdateCandidate=await Task.Run(()=>client.Check(DesktopUpdateRuntime.CurrentVersion,lifetime.Token),lifetime.Token);}
            appUpdateFailures=0;nextAppUpdateCheck=DateTimeOffset.UtcNow.AddHours(6).AddMinutes(Random.Shared.Next(0,31));
            if(appUpdateCandidate==null){appUpdateMenu.Text="Aplicativo Windows atualizado · verificar agora";if(manual)MessageBox.Show(this,"O aplicativo Windows "+DesktopUpdateRuntime.CurrentVersion+" está atualizado no canal estável.","Atualização do aplicativo Windows");}
            else
            {
                appUpdateMenu.Text="Aplicativo Windows "+appUpdateCandidate.Manifest.Version+" pronto · reiniciar para atualizar";
                if(updateFixture==null)tray.ShowBalloonTip(6000,Branding.AppName,"Nova versão do aplicativo Windows pronta. Use o menu da bandeja para revisar e reiniciar quando desejar.",ToolTipIcon.Info);
                if(manual)await ConfirmAppUpdate();
            }
        }
        catch(OperationCanceledException) when(exiting||lifetime.IsCancellationRequested){}
        catch
        {
            appUpdateFailures=Math.Min(appUpdateFailures+1,4);nextAppUpdateCheck=DateTimeOffset.UtcNow.AddMinutes(Math.Min(360,15*(1<<appUpdateFailures))+Random.Shared.Next(0,11));
            appUpdateMenu.Text="Aplicativo Windows · atualização indisponível, tentar novamente";
            if(manual)MessageBox.Show(this,"Não foi possível obter e validar a atualização. A instalação atual foi preservada. Tente novamente mais tarde.","Atualização do aplicativo Windows",MessageBoxButtons.OK,MessageBoxIcon.Warning);
        }
        finally{appUpdateBusy=false;if(!resourcesDisposed)appUpdateMenu.Enabled=true;}
    }
    async Task ConfirmAppUpdate()
    {
        var candidate=appUpdateCandidate;if(candidate==null||exiting)return;
        var prompt="Atualizar somente o aplicativo Windows deste usuário?\n\nVersão instalada: "+DesktopUpdateRuntime.CurrentVersion+"\nNova versão: "+candidate.Manifest.Version+"\n\nO aplicativo será fechado e reaberto. O vínculo e as preferências serão preservados. Isto não atualiza nem reinicia o servidor SIEM.";
        if(!(updateFixture?.Confirm(prompt)??(MessageBox.Show(this,prompt,"Atualização do aplicativo Windows",MessageBoxButtons.YesNo,MessageBoxIcon.Question,MessageBoxDefaultButton.Button2)==DialogResult.Yes)))return;
        appUpdateMenu.Enabled=false;
        try
        {
            if(updateFixture!=null)await updateFixture.Apply(candidate,true);
            else await Task.Run(()=>DesktopUpdateRuntime.Production().Apply(candidate,true),lifetime.Token);
            exiting=true;Close();
        }
        catch
        {
            appUpdateCandidate=null;appUpdateMenu.Text="Aplicativo Windows · falha na aplicação, versão atual preservada";
            MessageBox.Show(this,"A atualização não pôde ser concluída. A versão atual continua disponível. Abra o lançador instalado para recuperar a seleção anterior se necessário.","Atualização do aplicativo Windows",MessageBoxButtons.OK,MessageBoxIcon.Warning);
        }
        finally{if(!resourcesDisposed)appUpdateMenu.Enabled=true;}
    }
    internal Task CheckIsolatedAppUpdate()=>updateFixture!=null?CheckAppUpdate(true):throw new InvalidOperationException("Fixture ausente.");
    internal Task ConfirmIsolatedAppUpdate()=>updateFixture!=null?ConfirmAppUpdate():throw new InvalidOperationException("Fixture ausente.");
    internal bool UpdateIsExiting=>exiting;
}
