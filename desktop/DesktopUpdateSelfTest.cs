using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Multipla.Siem.Desktop;

internal static class DesktopUpdateSelfTest
{
    sealed class Transport(Func<HttpRequestMessage,HttpResponseMessage> respond):HttpMessageHandler
    {protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token){token.ThrowIfCancellationRequested();return Task.FromResult(respond(request));}}
    sealed class NoProcess:IDesktopUpdateProcess
    {public int Calls;public bool Health(string path,TimeSpan timeout){Calls++;throw new Exception("Synthetic payload execution forbidden.");}public void Launch(string path,string argument){Calls++;throw new Exception("Synthetic payload execution forbidden.");}}
    internal static void Run(string repository)
    {
        var root=Path.Combine(Path.GetTempPath(),"multipla-update-self-test-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);var checks=0;
        void Check(bool value){if(!value)throw new Exception("Update assertion "+checks+" failed.");checks++;}
        void Reject(Action action){try{action();}catch(Exception error) when(error is InvalidDataException or CryptographicException or IOException or HttpRequestException or OperationCanceledException or InvalidOperationException){checks++;return;}throw new Exception("Unsafe update accepted at "+checks);}
        try
        {
            var raw=File.ReadAllBytes(Path.Combine(repository,"release","windows-manifest.json"));var sig=File.ReadAllBytes(Path.Combine(repository,"release","windows-manifest.sig"));
            using var json=System.Text.Json.JsonDocument.Parse(raw);var released=json.RootElement.GetProperty("version").GetString()!;
            var manifest=DesktopUpdatePolicy.VerifyManifest(raw,sig,released);Check(manifest.Files.Count>0);
            var damaged=(byte[])raw.Clone();damaged[0]^=1;Reject(()=>DesktopUpdatePolicy.VerifyManifest(damaged,sig,released));
            foreach(var bad in new[]{"https://evil.invalid/file","http://github.com/"+DesktopUpdatePolicy.Repository+"/releases/latest","https://github.com/another/repo/releases/latest","https://github.com:444/"+DesktopUpdatePolicy.Repository+"/releases/latest","https://u@github.com/"+DesktopUpdatePolicy.Repository+"/releases/latest"})Reject(()=>DesktopUpdateClient.ValidateAddress(new(bad)));
            foreach(var bad in new[]{"../x","a\\b","C:/x","CON.txt","x:stream","a/../b","a. ","/x"})Reject(()=>DesktopUpdatePolicy.SafeRelative(bad));
            var state=DesktopUpdateState.ForTests(Path.Combine(root,"cache"));using(var operation=state.Exclusive())state.Write(new(Highest:released));Check(state.Read().Highest==released);
            using(var operation=state.Exclusive())Reject(()=>{using var other=state.Exclusive();});
            Reject(()=>state.Write(new(Active:"1.0.0",Highest:"2.0.0")));Reject(()=>state.Write(new(Ticket:new("1.0.0",new string('x',43),DateTimeOffset.UtcNow.AddHours(1)))));
            Directory.CreateDirectory(DesktopUpdatePolicy.Inside(state.Payloads,"1.0.0.pending"));state.Collect(null,null,null);Check(!Directory.Exists(Path.Combine(state.Payloads,"1.0.0.pending")));
            var external=Path.Combine(root,"must-remain");Directory.CreateDirectory(external);Reject(()=>state.DeleteTree(external));Check(Directory.Exists(external));
            var requests=0;
            using(var client=new DesktopUpdateClient(state,new Transport(request=>
            {
                requests++;Check(request.Headers.Authorization==null&&request.Headers.Count(h=>h.Key.Contains("key",StringComparison.OrdinalIgnoreCase))==0);
                return new(HttpStatusCode.OK){Content=new ByteArrayContent(request.RequestUri!.AbsolutePath.EndsWith(".sig")?sig:raw)};
            })))Check(client.Check(released,CancellationToken.None).GetAwaiter().GetResult()==null);
            Check(requests==2);
            using(var client=new DesktopUpdateClient(state,new Transport(_=>new(HttpStatusCode.Redirect){Headers={Location=new Uri("https://evil.invalid/archive")}})))Reject(()=>client.Check(released,CancellationToken.None).GetAwaiter().GetResult());
            var fake=new NoProcess();var stable=Path.Combine(root,"stable","Multipla.Siem.exe");Directory.CreateDirectory(Path.GetDirectoryName(stable)!);
            var runtime=new DesktopUpdateRuntime(state,fake,stable,released);
            state.Write(new(Active:"1.0.0",Highest:"1.0.0"));Check(!runtime.Select(false));Check(state.Read().Active==null&&state.Read().Highest==released&&fake.Calls==0);
            Reject(()=>runtime.ConsumeTicket("handoff"));
            Reject(()=>runtime.Apply(new(manifest,Path.Combine(root,"arbitrary.zip")),false));Check(fake.Calls==0);
            // Corruption cannot turn into an empty/default authenticated selection.
            File.WriteAllBytes(Path.Combine(state.Root,"selection.dpapi"),Encoding.UTF8.GetBytes("corrupt"));Reject(()=>state.Read());
            Reject(()=>runtime.RecoverSelection(false));runtime.RecoverSelection(true);Check(state.Read().Launcher==stable&&File.Exists(Path.Combine(state.Root,"selection.invalid.backup")));
            var cached=new DesktopUpdateRuntime(state,fake,state.PayloadExecutable(released),released);Reject(()=>cached.RecoverSelection(true));Check(fake.Calls==0);
            checks+=UiAndMutex(root,manifest);
            Console.WriteLine("PASS: "+checks+" isolated update checks; no payload executed, no production preferences accessed.");
        }
        finally{Directory.Delete(root,true);}
    }
    static int UiAndMutex(string root,WindowsUpdateManifest manifest)
    {
        var identity=Guid.NewGuid();using var release=new ManualResetEventSlim();using var waiting=new ManualResetEventSlim();
        var owner=DesktopInstanceGate.ForTests(identity,TimeSpan.Zero);if(!owner.Acquired)throw new Exception("Fixture mutex unavailable.");
        var contender=Task.Run(()=>
        {
            using(var immediate=DesktopInstanceGate.ForTests(identity,TimeSpan.Zero))if(immediate.Acquired)throw new Exception("Concurrent update instance admitted.");
            waiting.Set();release.Wait();using var next=DesktopInstanceGate.ForTests(identity,TimeSpan.FromSeconds(2));if(!next.Acquired)throw new Exception("Handoff mutex not acquired.");
        });
        if(!waiting.Wait(3000))throw new Exception("Mutex test timed out.");owner.Dispose();release.Set();contender.GetAwaiter().GetResult();
        var ready=0;var checks=0;var applies=0;var allow=false;Exception? failure=null;
        var cache=DesktopUpdateState.ForTests(Path.Combine(root,"ui-cache"));
        var fixture=new DesktopUpdateUiFixture(cache,()=>Task.FromResult<DesktopUpdateCandidate?>(new(manifest,"unused-fixture.download")),(candidate,consent)=>
        {if(!consent)throw new Exception("Apply without consent.");applies++;return Task.CompletedTask;},prompt=>
        {if(!prompt.Contains("Versão instalada: "+DesktopUpdateRuntime.CurrentVersion)||!prompt.Contains("Nova versão: "+manifest.Version)||!prompt.Contains("não atualiza nem reinicia o servidor SIEM"))throw new Exception("Ambiguous app/server prompt.");checks++;return allow;},()=>ready++);
        using var panel=new PanelWindow(false,true,_=>throw new Exception("Real preferences save forbidden."),fixture);
        using var timeout=new System.Windows.Forms.Timer{Interval=15000};timeout.Tick+=(_,_)=>{failure=new TimeoutException("Isolated update UI timed out.");panel.Close();};
        panel.Shown+=async(_,_)=>
        {
            try
            {
                timeout.Start();await panel.CheckIsolatedAppUpdate();
                if(ready!=1||applies!=0||panel.UpdateIsExiting||!panel.Visible)throw new Exception("Cancel did not preserve running app.");checks++;
                allow=true;await panel.ConfirmIsolatedAppUpdate();
                if(applies!=1||!panel.UpdateIsExiting)throw new Exception("Successful update did not close app.");checks++;
            }
            catch(Exception error){failure=error;panel.Close();}
        };
        Application.Run(panel);timeout.Stop();if(failure!=null)throw failure;if(applies!=1||ready!=1)throw new Exception("Update UI did not complete.");return checks+3;
    }
}
