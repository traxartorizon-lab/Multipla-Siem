using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace Multipla.Siem.Desktop;

internal record DesktopUpdateTicket(string Version,string Token,DateTimeOffset Expires,bool Used=false,string Purpose="health");
internal record DesktopUpdateRecord(string? Active=null,string? Previous=null,string? Highest=null,DesktopUpdateTicket? Ticket=null,string? Rollback=null,DateTimeOffset LastCheck=default,string? Failed=null,string? Launcher=null,string? LauncherVersion=null);
internal sealed class DesktopUpdateState
{
    internal string Root{get;}
    internal string Payloads=>Path.Combine(Root,"payloads");
    internal string Downloads=>Path.Combine(Root,"downloads");
    static readonly byte[] Entropy=Encoding.UTF8.GetBytes("Multipla SIEM authenticated Windows updates v1");
    readonly bool test;
    DesktopUpdateState(string root,bool test){Root=Path.GetFullPath(root);this.test=test;}
    internal static DesktopUpdateState Production()=>new(Path.Combine(SecureStore.DirectoryPath,"updates"),false);
    internal static DesktopUpdateState ForTests(string root)
    {
        if(!Path.GetFullPath(root).StartsWith(Path.GetFullPath(Path.GetTempPath()),StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Cache de testes deve ficar no TEMP.");return new(root,true);
    }
    internal void Ensure()
    {
        DesktopUpdatePolicy.NoReparse(Root);Directory.CreateDirectory(Root);DesktopUpdatePolicy.NoReparse(Root);
        if(!test)
        {
            var sid=WindowsIdentity.GetCurrent().User??throw new InvalidOperationException("Usuário Windows indisponível.");
            var security=new DirectorySecurity();security.SetAccessRuleProtection(true,false);
            foreach(var owner in new[]{sid,new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null)})security.AddAccessRule(new FileSystemAccessRule(owner,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
            new DirectoryInfo(Root).SetAccessControl(security);
        }
        Directory.CreateDirectory(Payloads);Directory.CreateDirectory(Downloads);DesktopUpdatePolicy.NoReparse(Payloads);DesktopUpdatePolicy.NoReparse(Downloads);
    }
    internal FileStream Exclusive()
    {
        Ensure();var path=DesktopUpdatePolicy.Inside(Root,"operation.lock");return new FileStream(path,FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
    }
    internal DesktopUpdateRecord Read()
    {
        var path=DesktopUpdatePolicy.Inside(Root,"selection.dpapi");if(!File.Exists(path))return new();var cipher=DesktopUpdatePolicy.ReadBounded(path,128<<10);
        var plain=ProtectedData.Unprotect(cipher,Entropy,DataProtectionScope.CurrentUser);
        try{var value=JsonSerializer.Deserialize<DesktopUpdateRecord>(plain)??throw new InvalidDataException("Seleção de atualização vazia.");Validate(value);return value;}finally{CryptographicOperations.ZeroMemory(plain);}
    }
    void Validate(DesktopUpdateRecord state)
    {
        foreach(var value in new[]{state.Active,state.Previous,state.Highest,state.Rollback,state.Failed,state.Ticket?.Version,state.LauncherVersion})if(value!=null)DesktopUpdatePolicy.ParseVersion(value);
        if(state.Launcher!=null){var path=Path.GetFullPath(state.Launcher);if(path!=state.Launcher||Path.GetFileName(path)!="Multipla.Siem.exe"||path.StartsWith(Path.GetFullPath(Root)+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Lançador local inválido.");DesktopUpdatePolicy.NoReparse(path);}
        if(state.Active!=null&&state.Highest!=null&&DesktopUpdatePolicy.ParseVersion(state.Active)<DesktopUpdatePolicy.ParseVersion(state.Highest)&&state.Rollback!=state.Active)throw new InvalidDataException("Ponteiro de versão inferior recusado.");
        if(state.Ticket!=null&&(!System.Text.RegularExpressions.Regex.IsMatch(state.Ticket.Token,"^[A-Za-z0-9_-]{43}$")||state.Ticket.Expires>DateTimeOffset.UtcNow.AddMinutes(6)))throw new InvalidDataException("Ticket de atualização inválido.");
        if(state.Ticket!=null&&state.Ticket.Purpose is not ("health" or "handoff"))throw new InvalidDataException("Finalidade de ticket inválida.");
    }
    internal void Write(DesktopUpdateRecord state)
    {
        Validate(state);Ensure();var path=DesktopUpdatePolicy.Inside(Root,"selection.dpapi");var temporary=DesktopUpdatePolicy.Inside(Root,"selection.new-"+Guid.NewGuid().ToString("N"));
        var plain=JsonSerializer.SerializeToUtf8Bytes(state);
        try{var cipher=ProtectedData.Protect(plain,Entropy,DataProtectionScope.CurrentUser);using(var stream=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None)){stream.Write(cipher);stream.Flush(true);}File.Move(temporary,path,true);}finally{CryptographicOperations.ZeroMemory(plain);if(File.Exists(temporary))File.Delete(temporary);}
    }
    internal string PayloadPath(string version){DesktopUpdatePolicy.ParseVersion(version);return DesktopUpdatePolicy.Inside(Payloads,version);}
    internal string DownloadPath(string version){DesktopUpdatePolicy.ParseVersion(version);return DesktopUpdatePolicy.Inside(Downloads,version);}
    internal string PayloadExecutable(string version)=>DesktopUpdatePolicy.Inside(PayloadPath(version),"Multipla.Siem.exe");
    internal bool IsPayloadExecutable(string path,string version)=>string.Equals(Path.GetFullPath(path),PayloadExecutable(version),StringComparison.OrdinalIgnoreCase);
    internal string? CurrentPayloadVersion(string executable)
    {
        var dir=Path.GetDirectoryName(Path.GetFullPath(executable))!;if(!dir.StartsWith(Path.GetFullPath(Payloads)+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))return null;
        var version=Path.GetFileName(dir);DesktopUpdatePolicy.ParseVersion(version);if(!IsPayloadExecutable(executable,version))throw new InvalidDataException("Executável fora da seleção permitida.");return version;
    }
    internal void CheckAvailableSpace(long additional)
    {
        Ensure();long bytes=0;var entries=0;var pending=new Stack<DirectoryInfo>();pending.Push(new(Root));
        while(pending.TryPop(out var dir))foreach(var item in dir.EnumerateFileSystemInfos())
        {
            if(++entries>8192||(item.Attributes&FileAttributes.ReparsePoint)!=0)throw new InvalidDataException("Cache contém links ou excesso de entradas.");
            if(item is DirectoryInfo child)pending.Push(child);else bytes=checked(bytes+((FileInfo)item).Length);
        }
        if(bytes+additional>DesktopUpdatePolicy.MaxCache)throw new IOException("Cache de atualização atingiu o limite de1GiB; mantenha espaço livre para a versão ativa e anterior.");
    }
    internal void DeleteTree(string path)
    {
        var full=Path.GetFullPath(path);if(!full.StartsWith(Path.GetFullPath(Payloads)+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)&&!full.StartsWith(Path.GetFullPath(Downloads)+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Limpeza fora do cache recusada.");
        DesktopUpdatePolicy.NoReparse(full);if(!Directory.Exists(full))return;var files=new List<string>();var dirs=new List<string>();var stack=new Stack<string>();stack.Push(full);
        while(stack.TryPop(out var dir)){dirs.Add(dir);foreach(var item in new DirectoryInfo(dir).EnumerateFileSystemInfos()){if(files.Count+dirs.Count>8192||(item.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Limpeza recusou links ou excesso de entradas.");if(item is DirectoryInfo)stack.Push(item.FullName);else files.Add(item.FullName);}}
        foreach(var file in files){DesktopUpdatePolicy.NoReparse(file);File.Delete(file);}foreach(var dir in dirs.OrderByDescending(x=>x.Length)){DesktopUpdatePolicy.NoReparse(dir);Directory.Delete(dir,false);}
    }
    internal void Collect(string? active,string? previous,string? candidate)
    {
        Ensure();foreach(var dir in new DirectoryInfo(Payloads).EnumerateDirectories())
        {
            if(dir.Name==active||dir.Name==previous||dir.Name==candidate||dir.Name==candidate+".pending")continue;
            // Only known version directory names are eligible; no arbitrary path
            // supplied by a ticket or command line is ever deleted.
            var version=dir.Name.EndsWith(".pending",StringComparison.Ordinal)?dir.Name[..^8]:dir.Name;
            try{DesktopUpdatePolicy.ParseVersion(version);DeleteTree(dir.FullName);}catch(InvalidDataException){throw new IOException("Diretório desconhecido no cache; limpeza automática recusada.");}
        }
        foreach(var dir in new DirectoryInfo(Downloads).EnumerateDirectories())if(dir.Name!=candidate){DesktopUpdatePolicy.ParseVersion(dir.Name);DeleteTree(dir.FullName);}
    }
}
