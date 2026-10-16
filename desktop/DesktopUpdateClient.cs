using System.Net;
using System.Text.Json;

namespace Multipla.Siem.Desktop;

internal sealed record DesktopUpdateCandidate(WindowsUpdateManifest Manifest,string Archive);
internal sealed class DesktopUpdateClient:IDisposable
{
    readonly HttpClient http;
    readonly DesktopUpdateState state;
    internal DesktopUpdateClient(DesktopUpdateState state,HttpMessageHandler? handler=null)
    {
        this.state=state;
        http=new HttpClient(handler??new HttpClientHandler{AllowAutoRedirect=false,UseCookies=false,AutomaticDecompression=DecompressionMethods.None}){Timeout=Timeout.InfiniteTimeSpan,MaxResponseContentBufferSize=DesktopUpdatePolicy.MaxManifest};
        http.DefaultRequestHeaders.UserAgent.ParseAdd("Multipla-SIEM-Windows-Updater/1");
    }
    static Uri Asset(string suffix)=>new("https://github.com/"+DesktopUpdatePolicy.Repository+"/releases/"+suffix);
    internal static void ValidateAddress(Uri address)
    {
        if(address.Scheme!="https"||address.Port!=443||address.UserInfo.Length!=0||address.Fragment.Length!=0)throw new InvalidDataException("Origem da atualização recusada.");
        if(address.IdnHost=="github.com")
        {
            if(!address.AbsolutePath.StartsWith("/"+DesktopUpdatePolicy.Repository+"/releases/",StringComparison.Ordinal))throw new InvalidDataException("Repositório da atualização recusado.");
        }
        else if(address.IdnHost!="release-assets.githubusercontent.com"&&address.IdnHost!="objects.githubusercontent.com")throw new InvalidDataException("Destino de download recusado.");
    }
    async Task<HttpResponseMessage> Open(Uri address,CancellationToken cancellation)
    {
        for(var redirect=0;redirect<=4;redirect++)
        {
            ValidateAddress(address);using var request=new HttpRequestMessage(HttpMethod.Get,address);
            var response=await http.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,cancellation);
            if((int)response.StatusCode is 301 or 302 or 303 or 307 or 308)
            {
                var location=response.Headers.Location;response.Dispose();if(location==null||redirect==4)throw new HttpRequestException("Redirecionamento excessivo ou inválido.");address=new Uri(address,location);continue;
            }
            try{response.EnsureSuccessStatusCode();return response;}catch{response.Dispose();throw;}
        }
        throw new HttpRequestException("Download indisponível.");
    }
    async Task Download(Uri address,Stream output,long maximum,CancellationToken cancellation)
    {
        using var response=await Open(address,cancellation);if(response.Content.Headers.ContentLength is long declared&&(declared<0||declared>maximum))throw new InvalidDataException("Download excede o limite.");
        await using var input=await response.Content.ReadAsStreamAsync(cancellation);var buffer=new byte[65536];long count=0;int read;
        while((read=await input.ReadAsync(buffer,cancellation))>0){count=checked(count+read);if(count>maximum)throw new InvalidDataException("Download excede o limite.");await output.WriteAsync(buffer.AsMemory(0,read),cancellation);}
    }
    async Task<byte[]> Bytes(string suffix,int maximum,CancellationToken cancellation)
    {
        using var output=new MemoryStream();await Download(Asset(suffix),output,maximum,cancellation);return output.ToArray();
    }
    internal async Task<DesktopUpdateCandidate?> Check(string currentVersion,CancellationToken cancellation)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancellation);deadline.CancelAfter(TimeSpan.FromMinutes(6));var token=deadline.Token;
        // No web-page supplied URL, SIEM credential or GitHub personal token is used.
        var raw=await Bytes("latest/download/windows-manifest.json",DesktopUpdatePolicy.MaxManifest,token);
        var signature=await Bytes("latest/download/windows-manifest.sig",64,token);DesktopUpdatePolicy.VerifySignature(raw,signature);
        using var json=JsonDocument.Parse(raw);var version=json.RootElement.GetProperty("version").GetString()??"";var parsed=DesktopUpdatePolicy.ParseVersion(version);
        var manifest=DesktopUpdatePolicy.VerifyManifest(raw,signature,version);
        using var operation=state.Exclusive();var selection=state.Read();var floor=DesktopUpdatePolicy.ParseVersion(currentVersion);
        if(selection.Highest!=null&&DesktopUpdatePolicy.ParseVersion(selection.Highest)>floor)floor=DesktopUpdatePolicy.ParseVersion(selection.Highest);
        state.Write(selection with{LastCheck=DateTimeOffset.UtcNow});
        if(parsed<=floor||selection.Failed==version)return null;
        state.Collect(selection.Active,selection.Previous,version);state.CheckAvailableSpace(DesktopUpdatePolicy.MaxDownload+manifest.ExpandedBytes);
        var folder=state.DownloadPath(version);Directory.CreateDirectory(folder);DesktopUpdatePolicy.NoReparse(folder);
        var archive=DesktopUpdatePolicy.Inside(folder,"package.download");var partial=DesktopUpdatePolicy.Inside(folder,"package.part");
        if(File.Exists(archive))
        {
            try{DesktopUpdatePolicy.ValidateArchive(archive,manifest);return new(manifest,archive);}catch(InvalidDataException){File.Delete(archive);}catch(System.Security.Cryptography.CryptographicException){File.Delete(archive);}
        }
        try
        {
            if(File.Exists(partial))File.Delete(partial);
            await using(var file=new FileStream(partial,FileMode.CreateNew,FileAccess.Write,FileShare.None,65536,FileOptions.Asynchronous))
            {await Download(Asset("download/v"+version+"/Multipla-SIEM-Windows-"+version+"-x64.zip"),file,DesktopUpdatePolicy.MaxDownload,token);file.Flush(true);}
            DesktopUpdatePolicy.ValidateArchive(partial,manifest);File.Move(partial,archive,true);return new(manifest,archive);
        }
        finally{if(File.Exists(partial))File.Delete(partial);}
    }
    public void Dispose()=>http.Dispose();
}
