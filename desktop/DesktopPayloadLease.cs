using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Multipla.Siem.Desktop;

// Hold signed files read-only, and directories without delete sharing, across
// validation and Process.Start. This is not a sandbox against the Windows user
// who owns the application and can already execute arbitrary code.
internal sealed class DesktopPayloadLease : IDisposable
{
    readonly List<IDisposable> handles=[];
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle file,out FileInformation info);
    [StructLayout(LayoutKind.Sequential)]
    struct FileInformation {public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
    internal static DesktopPayloadLease Acquire(string root,WindowsUpdateManifest manifest)
    {
        var lease=new DesktopPayloadLease();try{lease.LockTree(root,manifest);return lease;}catch{lease.Dispose();throw;}
    }
    void LockTree(string root,WindowsUpdateManifest manifest)
    {
        DesktopUpdatePolicy.NoReparse(root);var ancestors=new Stack<string>();for(var dir=new DirectoryInfo(root);dir!=null;dir=dir.Parent)ancestors.Push(dir.FullName);
        while(ancestors.TryPop(out var ancestor))LockDirectory(ancestor);
        var folders=new Stack<string>();folders.Push(root);var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);var total=0;
        while(folders.TryPop(out var dir))foreach(var item in new DirectoryInfo(dir).EnumerateFileSystemInfos())
        {
            if(++total>DesktopUpdatePolicy.MaxEntries+256||(item.Attributes&FileAttributes.ReparsePoint)!=0)throw new InvalidDataException("Links ou excesso de arquivos no payload.");
            if(item is DirectoryInfo){LockDirectory(item.FullName);folders.Push(item.FullName);continue;}
            var name=Path.GetRelativePath(root,item.FullName).Replace('\\','/');DesktopUpdatePolicy.SafeRelative(name);
            if(!manifest.Files.ContainsKey(name)&&name is not("windows-manifest.json" or "windows-manifest.sig"))throw new InvalidDataException("Arquivo adicional não assinado no payload.");
            if(!names.Add(name))throw new InvalidDataException("Arquivo duplicado no payload.");
            handles.Add(new FileStream(item.FullName,FileMode.Open,FileAccess.Read,FileShare.Read));
        }
        if(manifest.Files.Keys.Any(name=>!names.Contains(name)))throw new InvalidDataException("Payload incompleto.");
        if(!DesktopUpdatePolicy.ReadBounded(DesktopUpdatePolicy.Inside(root,"windows-manifest.json"),DesktopUpdatePolicy.MaxManifest).AsSpan().SequenceEqual(manifest.Raw)||!DesktopUpdatePolicy.ReadBounded(DesktopUpdatePolicy.Inside(root,"windows-manifest.sig"),64).AsSpan().SequenceEqual(manifest.Signature))throw new InvalidDataException("Metadados locais divergiram após validação.");
    }
    void LockDirectory(string path)
    {
        var handle=CreateFile(path,0x80,3,IntPtr.Zero,3,0x02000000|0x00200000,IntPtr.Zero);
        if(handle.IsInvalid){handle.Dispose();throw new IOException("Não foi possível proteger o diretório do aplicativo.");}
        if(!GetFileInformationByHandle(handle,out var info)||(info.Attributes&0x400)!=0){handle.Dispose();throw new InvalidDataException("Diretório foi redirecionado.");}handles.Add(handle);
    }
    public void Dispose(){for(var i=handles.Count-1;i>=0;i--)handles[i].Dispose();handles.Clear();}
}
