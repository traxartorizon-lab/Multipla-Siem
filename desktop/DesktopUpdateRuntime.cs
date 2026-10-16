using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Web.WebView2.Core;

namespace Multipla.Siem.Desktop;

internal interface IDesktopUpdateProcess
{
    bool Health(string executable,TimeSpan timeout);
    void Launch(string executable,string argument);
}
internal sealed class DesktopUpdateProcess:IDesktopUpdateProcess
{
    public bool Health(string executable,TimeSpan timeout)
    {
        using var process=Process.Start(new ProcessStartInfo(executable,"--update-health-check"){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=Path.GetDirectoryName(executable)!})??throw new IOException("Não foi possível validar a nova versão.");
        if(!process.WaitForExit((int)timeout.TotalMilliseconds)){try{process.Kill(true);process.WaitForExit(5000);}catch{}return false;}return process.ExitCode==0;
    }
    public void Launch(string executable,string argument)
    {
        using var process=Process.Start(new ProcessStartInfo(executable,argument){UseShellExecute=false,WorkingDirectory=Path.GetDirectoryName(executable)!})??throw new IOException("Não foi possível abrir a versão verificada.");
    }
}
internal sealed class DesktopUpdateRuntime
{
    readonly DesktopUpdateState state;
    readonly IDesktopUpdateProcess process;
    readonly string executable,version;
    internal DesktopUpdateRuntime(DesktopUpdateState state,IDesktopUpdateProcess process,string executable,string version)
    {this.state=state;this.process=process;this.executable=Path.GetFullPath(executable);this.version=version;DesktopUpdatePolicy.ParseVersion(version);}
    internal static string CurrentVersion=>System.Reflection.Assembly.GetExecutingAssembly().GetName().Version!.ToString(3);
    internal static DesktopUpdateRuntime Production()=>new(DesktopUpdateState.Production(),new DesktopUpdateProcess(),Environment.ProcessPath!,CurrentVersion);
    internal bool CanRecoverSelection=>state.CurrentPayloadVersion(executable)==null;
    internal void RecoverSelection(bool consent)
    {
        if(!consent||!CanRecoverSelection)throw new InvalidOperationException("Recuperação exige confirmação na cópia base.");
        using var operation=state.Exclusive();DesktopUpdatePolicy.NoReparse(executable);
        var source=DesktopUpdatePolicy.Inside(state.Root,"selection.dpapi");var backup=DesktopUpdatePolicy.Inside(state.Root,"selection.invalid.backup");
        if(File.Exists(source))File.Move(source,backup,true);
        state.Write(new(Launcher:executable,LauncherVersion:version,Highest:version));
    }
    static DesktopUpdateTicket Ticket(string version,string purpose)=>new(version,Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+','-').Replace('/','_'),DateTimeOffset.UtcNow.AddMinutes(2),false,purpose);
    internal string LauncherPath
    {
        get{using var operation=state.Exclusive();var selected=state.Read();return selected.Launcher??(state.CurrentPayloadVersion(executable)==null?executable:throw new InvalidDataException("Lançador original indisponível."));}
    }
    DesktopUpdateRecord Rollback(DesktopUpdateRecord selected)
    {
        var failed=selected.Active??selected.Ticket?.Version;
        var restored=selected with{Active=selected.Previous,Previous=null,Ticket=null,Rollback=selected.Previous,Failed=failed};state.Write(restored);return restored;
    }
    // Called while holding the single-instance mutex. A cache payload cannot
    // select itself merely because a command-line switch was supplied.
    internal bool Select(bool tray)
    {
        using var operation=state.Exclusive();var selected=state.Read();var own=state.CurrentPayloadVersion(executable);
        if(own==null)
        {
            var highest=selected.Highest;
            if((selected.Active==null||DesktopUpdatePolicy.ParseVersion(selected.Active)>=DesktopUpdatePolicy.ParseVersion(version))&&(highest==null||DesktopUpdatePolicy.ParseVersion(version)>DesktopUpdatePolicy.ParseVersion(highest)))highest=version;
            selected=selected with{Launcher=executable,LauncherVersion=version,Highest=highest};state.Write(selected);
        }
        if(selected.Ticket!=null)
        {
            if(selected.Ticket.Purpose=="health")
            {selected=selected with{Ticket=null,Failed=selected.Ticket.Version};state.Write(selected);}
            else if(selected.Ticket.Expires<=DateTimeOffset.UtcNow||selected.Ticket.Used)selected=Rollback(selected);
            else throw new InvalidOperationException("Uma atualização do aplicativo ainda está sendo concluída. Aguarde e tente novamente.");
        }
        if(own==null&&selected.Active!=null&&DesktopUpdatePolicy.ParseVersion(version)>DesktopUpdatePolicy.ParseVersion(selected.Active))
        {
            var highest=selected.Highest==null||DesktopUpdatePolicy.ParseVersion(version)>DesktopUpdatePolicy.ParseVersion(selected.Highest)?version:selected.Highest;
            selected=selected with{Active=null,Previous=null,Rollback=null,Highest=highest};state.Write(selected);return false;
        }
        if(selected.Active==null)
        {
            if(own!=null)throw new InvalidDataException("Esta cópia em cache não é a versão ativa. Abra o lançador instalado.");return false;
        }
        if(own!=null&&own!=selected.Active)throw new InvalidDataException("Versão em cache inativa recusada.");
        for(var attempt=0;attempt<2;attempt++)
        {
            var target=selected.Active;if(target==null)break;
            try
            {
                var manifest=DesktopUpdatePolicy.ReadPayload(state.PayloadPath(target),target);using var lease=DesktopUpdatePolicy.LockValidatedPayload(state.PayloadPath(target),manifest);
                if(own==target)return false;
                if(own!=null)throw new InvalidDataException("Versão em cache inativa recusada.");
                process.Launch(state.PayloadExecutable(target),tray?"--update-selected --tray":"--update-selected");return true;
            }
            catch(Exception error) when(error is IOException or CryptographicException or UnauthorizedAccessException)
            {selected=Rollback(selected);}
        }
        if(own!=null)throw new InvalidDataException("Abra o lançador original para recuperar o aplicativo.");return false;
    }
    internal void ConsumeTicket(string purpose,Action? healthCheck=null)
    {
        using var operation=state.Exclusive();var selected=state.Read();var ticket=selected.Ticket;
        if(ticket==null||ticket.Purpose!=purpose||ticket.Used||ticket.Expires<=DateTimeOffset.UtcNow||ticket.Version!=version||!state.IsPayloadExecutable(executable,version))throw new InvalidDataException("Ticket expirado, reutilizado ou fora do aplicativo autorizado.");
        if(purpose=="handoff"&&selected.Active!=version)throw new InvalidDataException("Handoff fora da seleção ativa.");
        var manifest=DesktopUpdatePolicy.ReadPayload(state.PayloadPath(version),version);using var lease=DesktopUpdatePolicy.LockValidatedPayload(state.PayloadPath(version),manifest);
        state.Write(selected with{Ticket=ticket with{Used=true}});healthCheck?.Invoke();
    }
    internal void HealthCheck()=>ConsumeTicket("health",()=>
    {
        var available=CoreWebView2Environment.GetAvailableBrowserVersionString();if(string.IsNullOrWhiteSpace(available))throw new InvalidOperationException("WebView2 indisponível.");
    });
    internal void Ready()
    {
        using var operation=state.Exclusive();var selected=state.Read();if(selected.Active==version&&selected.Ticket is {Purpose:"handoff",Used:true} ticket&&ticket.Version==version)state.Write(selected with{Ticket=null,Rollback=null});
    }
    internal void Apply(DesktopUpdateCandidate candidate,bool consent)
    {
        if(!consent)throw new InvalidOperationException("Atualização local não autorizada.");
        var manifest=DesktopUpdatePolicy.VerifyManifest(candidate.Manifest.Raw,candidate.Manifest.Signature,candidate.Manifest.Version);var next=DesktopUpdatePolicy.ParseVersion(manifest.Version);
        // Reverify all signed metadata and bytes at the point of consent.
        using(var operation=state.Exclusive())
        {
            var selected=state.Read();var floor=DesktopUpdatePolicy.ParseVersion(version);if(selected.Highest!=null&&DesktopUpdatePolicy.ParseVersion(selected.Highest)>floor)floor=DesktopUpdatePolicy.ParseVersion(selected.Highest);
            if(next<=floor||selected.Ticket!=null)throw new InvalidDataException("Versão inferior ou outra transação em andamento.");
            if(!string.Equals(candidate.Archive,DesktopUpdatePolicy.Inside(state.DownloadPath(manifest.Version),"package.download"),StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Arquivo fora do staging fixo.");
            DesktopUpdatePolicy.ValidateArchive(candidate.Archive,manifest);state.Collect(selected.Active,selected.Previous,manifest.Version);state.CheckAvailableSpace(manifest.ExpandedBytes);
            var destination=state.PayloadPath(manifest.Version);var pending=DesktopUpdatePolicy.Inside(state.Payloads,manifest.Version+".pending");
            if(Directory.Exists(pending))state.DeleteTree(pending);if(Directory.Exists(destination))state.DeleteTree(destination);
            try{DesktopUpdatePolicy.Extract(candidate.Archive,pending,manifest);Directory.Move(pending,destination);state.Write(selected with{Ticket=Ticket(manifest.Version,"health")});}
            catch{if(Directory.Exists(pending))state.DeleteTree(pending);throw;}
        }
        bool healthy;
        try{using var lease=DesktopUpdatePolicy.LockValidatedPayload(state.PayloadPath(manifest.Version),manifest);healthy=process.Health(state.PayloadExecutable(manifest.Version),TimeSpan.FromSeconds(15));}
        catch
        {
            using var operation=state.Exclusive();var interrupted=state.Read();
            if(interrupted.Ticket is {Purpose:"health"} failed&&failed.Version==manifest.Version)state.Write(interrupted with{Ticket=null,Failed=manifest.Version});
            throw;
        }
        using(var operation=state.Exclusive())
        {
            var selected=state.Read();
            if(selected.Ticket is not {Purpose:"health",Used:true} ticket||ticket.Version!=manifest.Version||ticket.Expires<=DateTimeOffset.UtcNow)healthy=false;
            if(!healthy){state.Write(selected with{Ticket=null,Failed=manifest.Version});throw new IOException("A nova versão não passou na verificação de inicialização; a versão atual foi preservada.");}
            state.Write(selected with{Previous=selected.Active,Active=manifest.Version,Highest=manifest.Version,Rollback=null,Ticket=Ticket(manifest.Version,"handoff")});
        }
        try{using var lease=DesktopUpdatePolicy.LockValidatedPayload(state.PayloadPath(manifest.Version),manifest);process.Launch(state.PayloadExecutable(manifest.Version),"--update-handoff");}
        catch{using var operation=state.Exclusive();Rollback(state.Read());throw;}
    }
}
