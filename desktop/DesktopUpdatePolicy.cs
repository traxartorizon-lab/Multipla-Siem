using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Multipla.Siem.Desktop;

internal sealed record UpdateFile(string Sha256,long Size);
internal sealed record WindowsUpdateManifest(string Version,Dictionary<string,UpdateFile> Files,byte[] Raw,byte[] Signature)
{
    public long ExpandedBytes=>Files.Values.Sum(f=>f.Size);
}
internal static class DesktopUpdatePolicy
{
    internal const string Repository="traxartorizon-lab/Multipla-Siem";
    internal const long MaxDownload=192L<<20,MaxExpanded=512L<<20,MaxCache=1024L<<20;
    internal const int MaxEntries=1024,MaxManifest=256<<10;
    internal static readonly byte[] PublicKey=Convert.FromBase64String("sAMAsxkPlps6yyq2RHPRWpXfqDeCzA6n/58Z28ShzvI=");
    static readonly HashSet<string> Metadata=new(StringComparer.Ordinal){"windows-manifest.json","windows-manifest.sig","trusted-release-public.pem","verify-package.py"};
    internal static Version ParseVersion(string value)
    {
        if(!Regex.IsMatch(value,@"^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,5})$"))throw new InvalidDataException("Versão de atualização inválida.");
        return Version.Parse(value);
    }
    internal static void VerifySignature(byte[] raw,byte[] signature)
    {
        if(raw.Length is 0 or >MaxManifest||signature.Length!=64)throw new InvalidDataException("Manifesto/assinatura fora do limite.");
        var signer=new Ed25519Signer();signer.Init(false,new Ed25519PublicKeyParameters(PublicKey,0));signer.BlockUpdate(raw,0,raw.Length);
        if(!signer.VerifySignature(signature))throw new CryptographicException("Assinatura Ed25519 da atualização inválida.");
    }
    internal static WindowsUpdateManifest VerifyManifest(byte[] raw,byte[] signature,string version)
    {
        VerifySignature(raw,signature);ParseVersion(version);
        using var document=JsonDocument.Parse(raw,new JsonDocumentOptions{MaxDepth=8});var root=document.RootElement;
        ExactProperties(root,"product","version","schema","files");
        if(root.GetProperty("product").GetString()!="Multipla SIEM"||root.GetProperty("schema").GetInt32()!=1||root.GetProperty("version").GetString()!=version)throw new InvalidDataException("Manifesto de outro produto ou versão.");
        var files=new Dictionary<string,UpdateFile>(StringComparer.OrdinalIgnoreCase);long total=0;
        foreach(var property in root.GetProperty("files").EnumerateObject())
        {
            SafeRelative(property.Name);ExactProperties(property.Value,"sha256","size");
            var hash=property.Value.GetProperty("sha256").GetString()??"";var size=property.Value.GetProperty("size").GetInt64();
            if(!Regex.IsMatch(hash,"^[a-f0-9]{64}$")||size<0||size>64L<<20||files.Count>=MaxEntries||!files.TryAdd(property.Name,new(hash,size)))throw new InvalidDataException("Arquivo de atualização inválido ou duplicado.");
            total=checked(total+size);if(total>MaxExpanded)throw new InvalidDataException("Atualização expandida excede o limite.");
        }
        foreach(var required in new[]{"Multipla.Siem.exe","Multipla.Siem.dll","Multipla.Siem.runtimeconfig.json","runtimes/win-x64/native/WebView2Loader.dll"})if(!files.ContainsKey(required))throw new InvalidDataException("Pacote Windows x64 incompleto.");
        return new(version,files,raw,signature);
    }
    static void ExactProperties(JsonElement value,params string[] expected)
    {
        if(value.ValueKind!=JsonValueKind.Object)throw new InvalidDataException("Objeto de manifesto inválido.");var names=value.EnumerateObject().Select(x=>x.Name).ToArray();
        if(names.Length!=expected.Length||names.Distinct(StringComparer.Ordinal).Count()!=names.Length||expected.Except(names,StringComparer.Ordinal).Any())throw new InvalidDataException("Campos do manifesto inválidos.");
    }
    internal static string SafeRelative(string name)
    {
        if(name.Length is 0 or >220||name.Contains('\\')||name.StartsWith('/')||name.Contains(':'))throw new InvalidDataException("Caminho de pacote inválido.");
        foreach(var part in name.Split('/'))
        {
            if(part is "" or "." or ".."||part.EndsWith('.')||part.EndsWith(' ')||part.IndexOfAny(Path.GetInvalidFileNameChars())>=0||Regex.IsMatch(part.Split('.')[0],"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$",RegexOptions.IgnoreCase))throw new InvalidDataException("Nome de arquivo Windows inválido.");
        }
        return name;
    }
    internal static void NoReparse(string path)
    {
        var full=Path.GetFullPath(path);for(var current=new DirectoryInfo(full);current!=null;current=current.Parent)if(current.Exists&&(current.Attributes&FileAttributes.ReparsePoint)!=0)throw new InvalidDataException("Links e junctions não são aceitos para atualizações.");
        if(File.Exists(full)&&(File.GetAttributes(full)&FileAttributes.ReparsePoint)!=0)throw new InvalidDataException("Arquivo com redirecionamento recusado.");
    }
    internal static string Inside(string root,string relative)
    {
        SafeRelative(relative);var parent=Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar)+Path.DirectorySeparatorChar;var result=Path.GetFullPath(Path.Combine(parent,relative.Replace('/',Path.DirectorySeparatorChar)));
        if(!result.StartsWith(parent,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Caminho fora do cache.");NoReparse(result);return result;
    }
    internal static void ValidatePayload(string root,WindowsUpdateManifest manifest)
    {
        using var lease=DesktopPayloadLease.Acquire(root,manifest);ValidatePayloadContents(root,manifest);
    }
    internal static IDisposable LockValidatedPayload(string root,WindowsUpdateManifest manifest)
    {
        var lease=DesktopPayloadLease.Acquire(root,manifest);try{ValidatePayloadContents(root,manifest);return lease;}catch{lease.Dispose();throw;}
    }
    static void ValidatePayloadContents(string root,WindowsUpdateManifest manifest)
    {
        NoReparse(root);foreach(var file in manifest.Files)
        {
            var path=Inside(root,file.Key);using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
            if(stream.Length!=file.Value.Size||!CryptographicOperations.FixedTimeEquals(SHA256.HashData(stream),Convert.FromHexString(file.Value.Sha256)))throw new CryptographicException("Integridade do aplicativo Windows inválida.");
        }
        using var exe=File.OpenRead(Inside(root,"Multipla.Siem.exe"));using var reader=new BinaryReader(exe);if(reader.ReadUInt16()!=0x5a4d)throw new InvalidDataException("Executável inválido.");exe.Position=0x3c;var offset=reader.ReadInt32();if(offset<64||offset>exe.Length-6)throw new InvalidDataException("Cabeçalho PE inválido.");exe.Position=offset;if(reader.ReadUInt32()!=0x4550||reader.ReadUInt16()!=0x8664)throw new InvalidDataException("A atualização não é Windows x64.");
    }
    internal static void Extract(string archive,string destination,WindowsUpdateManifest manifest)
    {
        NoReparse(destination);if(Directory.Exists(destination))throw new InvalidDataException("Destino da atualização já existe.");
        PreflightZip(archive);
        using var zip=ZipFile.OpenRead(archive);if(zip.Entries.Count>MaxEntries+128)throw new InvalidDataException("Entradas ZIP excedidas.");
        var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);long expanded=0;
        // Validate all central-directory entries before creating any executable files.
        foreach(var entry in zip.Entries)
        {
            if((entry.ExternalAttributes&0x400)!=0||((entry.ExternalAttributes>>16)&0xf000)==0xa000)throw new InvalidDataException("Link ZIP recusado.");
            if(entry.FullName.EndsWith('/')){SafeRelative(entry.FullName.TrimEnd('/'));if(!seen.Add(entry.FullName))throw new InvalidDataException("Diretório ZIP duplicado.");continue;}
            var name=SafeRelative(entry.FullName);if(!seen.Add(name)||(entry.ExternalAttributes&0x400)!=0||((entry.ExternalAttributes>>16)&0xf000)==0xa000)throw new InvalidDataException("ZIP contém link ou arquivo duplicado.");
            if(Metadata.Contains(name))continue;
            if(!manifest.Files.TryGetValue(name,out var expected)||!manifest.Files.Keys.Contains(name,StringComparer.Ordinal)||entry.Length!=expected.Size)throw new InvalidDataException("ZIP não corresponde ao manifesto assinado.");
            expanded=checked(expanded+entry.Length);if(expanded>MaxExpanded||entry.Length>0&&entry.CompressedLength==0||entry.CompressedLength>0&&entry.Length/entry.CompressedLength>1000)throw new InvalidDataException("Descompressão ZIP excede o limite.");
        }
        if(manifest.Files.Keys.Any(name=>!seen.Contains(name)))throw new InvalidDataException("ZIP incompleto.");
        Directory.CreateDirectory(destination);
        foreach(var entry in zip.Entries)
        {
            if(entry.FullName.EndsWith('/')||Metadata.Contains(entry.FullName))continue;var path=Inside(destination,entry.FullName);Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            using var input=entry.Open();using var output=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None);var buffer=new byte[65536];long count=0;int n;
            while((n=input.Read(buffer))>0){count=checked(count+n);if(count>manifest.Files[entry.FullName].Size)throw new InvalidDataException("Entrada ZIP maior que o tamanho assinado.");output.Write(buffer,0,n);}if(count!=manifest.Files[entry.FullName].Size)throw new InvalidDataException("Entrada ZIP truncada.");output.Flush(true);
        }
        File.WriteAllBytes(Inside(destination,"windows-manifest.json"),manifest.Raw);File.WriteAllBytes(Inside(destination,"windows-manifest.sig"),manifest.Signature);ValidatePayload(destination,manifest);
    }
    // Background verification streams bytes only: no executable payload is
    // materialized until the user explicitly accepts the native restart prompt.
    internal static void ValidateArchive(string archive,WindowsUpdateManifest manifest)
    {
        PreflightZip(archive);using var zip=ZipFile.OpenRead(archive);var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);long total=0;
        foreach(var entry in zip.Entries)
        {
            if((entry.ExternalAttributes&0x400)!=0||((entry.ExternalAttributes>>16)&0xf000)==0xa000)throw new InvalidDataException("Link ZIP recusado.");
            var directory=entry.FullName.EndsWith('/');var name=SafeRelative(directory?entry.FullName.TrimEnd('/'):entry.FullName);
            if(!seen.Add(directory?name+"/":name))throw new InvalidDataException("Entrada ZIP duplicada.");if(directory)continue;
            if(Metadata.Contains(name))continue;
            if(!manifest.Files.TryGetValue(name,out var expected)||!manifest.Files.Keys.Contains(name,StringComparer.Ordinal)||entry.Length!=expected.Size||entry.Length>0&&entry.CompressedLength==0||entry.CompressedLength>0&&entry.Length/entry.CompressedLength>1000)throw new InvalidDataException("ZIP não corresponde ao manifesto.");
            total=checked(total+entry.Length);if(total>MaxExpanded)throw new InvalidDataException("ZIP excede o limite expandido.");
            using var input=entry.Open();using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);var buffer=new byte[65536];long length=0;int count;
            while((count=input.Read(buffer))>0){length=checked(length+count);if(length>expected.Size)throw new InvalidDataException("Entrada ZIP excedida.");hash.AppendData(buffer,0,count);}
            if(length!=expected.Size||!CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(),Convert.FromHexString(expected.Sha256)))throw new CryptographicException("Arquivo ZIP corrompido.");
        }
        if(manifest.Files.Keys.Any(name=>!seen.Contains(name)))throw new InvalidDataException("ZIP incompleto.");
    }
    internal static byte[] ReadBounded(string path,int maximum)
    {
        NoReparse(path);using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);if(file.Length<0||file.Length>maximum)throw new InvalidDataException("Arquivo local excede o limite.");var bytes=new byte[(int)file.Length];file.ReadExactly(bytes);return bytes;
    }
    internal static WindowsUpdateManifest ReadPayload(string root,string version)=>VerifyManifest(ReadBounded(Inside(root,"windows-manifest.json"),MaxManifest),ReadBounded(Inside(root,"windows-manifest.sig"),64),version);
    static void PreflightZip(string path)
    {
        using var file=File.OpenRead(path);if(file.Length<22||file.Length>MaxDownload)throw new InvalidDataException("Tamanho ZIP inválido.");
        var tail=new byte[(int)Math.Min(file.Length,65557)];file.Position=file.Length-tail.Length;file.ReadExactly(tail);var end=-1;
        for(var i=tail.Length-22;i>=0;i--)if(System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(tail.AsSpan(i,4))==0x06054b50&&i+22+System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(tail.AsSpan(i+20,2))==tail.Length){end=i;break;}
        if(end<0)throw new InvalidDataException("Diretório ZIP ausente.");var record=tail.AsSpan(end);
        int U16(int at)=>System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(tail.AsSpan(end+at,2));
        uint U32(int at)=>System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(tail.AsSpan(end+at,4));
        var count=U16(10);var size=U32(12);var offset=U32(16);var endPosition=file.Length-tail.Length+end;
        if(U16(4)!=0||U16(6)!=0||U16(8)!=count||count>MaxEntries+128||count==65535||size>2<<20||offset==uint.MaxValue||(long)offset+size!=endPosition)throw new InvalidDataException("ZIP64, múltiplos discos ou diretório excessivo recusados.");
        file.Position=offset;var header=new byte[46];
        for(var i=0;i<count;i++)
        {
            if(file.Position+46>(long)offset+size)throw new InvalidDataException("Diretório ZIP truncado.");file.ReadExactly(header);
            if(System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(header)!=0x02014b50)throw new InvalidDataException("Entrada central ZIP inválida.");
            var skip=System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(28,2))+System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(30,2))+System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(32,2));
            if(file.Position+skip>(long)offset+size)throw new InvalidDataException("Entrada central ZIP excessiva.");file.Position+=skip;
        }
        if(file.Position!=(long)offset+size)throw new InvalidDataException("Contagem central ZIP divergente.");
    }
}
