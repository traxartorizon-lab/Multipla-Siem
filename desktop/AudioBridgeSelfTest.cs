using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace Multipla.Siem.Desktop;

// Isolated WebView integration fixture. It never loads SIEM credentials, changes
// OS permissions, uses the microphone or plays audio. The production handler's
// origin validation is exercised by the production handler against both virtual hosts.

internal partial class PanelWindow
{
 internal async Task PrepareAudioFixture(string root,string userProfile)
 {
  origin=SecurityPolicy.Origin("https://audio-fixture.invalid");settings=new Preferences(origin.AbsoluteUri);
  var environment=await CoreWebView2Environment.CreateAsync(null,userProfile);await browser.EnsureCoreWebView2Async(environment);
  browser.CoreWebView2.SetVirtualHostNameToFolderMapping("audio-fixture.invalid",root,CoreWebView2HostResourceAccessKind.DenyCors);
  browser.CoreWebView2.SetVirtualHostNameToFolderMapping("foreign-fixture.invalid",root,CoreWebView2HostResourceAccessKind.DenyCors);
  browser.CoreWebView2.Settings.IsWebMessageEnabled=true;browser.CoreWebView2.Settings.AreHostObjectsAllowed=false;browser.CoreWebView2.IsMuted=true;
  browser.CoreWebView2.WebMessageReceived+=NativeAudioMessage;
  browser.CoreWebView2.PermissionRequested+=(_,e)=>{e.State=CoreWebView2PermissionState.Deny;throw new InvalidOperationException("Unexpected permission request");};
 }
 internal void NavigateAudioFixture(string host)=>browser.CoreWebView2.Navigate("https://"+host+"/index.html");
 internal Task<string> AudioFixtureJS(string js)=>browser.CoreWebView2.ExecuteScriptAsync(js);
 internal Preferences AudioFixturePreferences=>settings;
}
internal static class AudioBridgeSelfTest
{
 public static void Run(string frontend)
 {
  var root=Path.GetFullPath(frontend);var test=Path.Combine(Path.GetTempPath(),"multipla-real-audio-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(test);
  foreach(var name in new[]{"alert-sounds.js","native-audio.js"})File.Copy(Path.Combine(root,name),Path.Combine(test,name));
  var helpers="const $=s=>document.querySelector(s);function el(t,text,cls){const n=document.createElement(t);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n}window.chrome.webview.addEventListener('message',e=>window.testAudioState=e.data);";
  var html="<!doctype html><html><body><label><select id='alert-sound-choice'><option value='beep'>beep</option><option value='siren'>siren</option></select></label><input type='checkbox' id='alert-sound-enabled'><input id='alert-sound-volume'><button id='alert-sound-test'></button><button id='alert-sound-stop'></button><p id='alert-sound-status'></p><script>"+helpers+"</script><script src='alert-sounds.js'></script><script src='native-audio.js'></script></body></html>";File.WriteAllText(Path.Combine(test,"index.html"),html);
  var store=Path.Combine(test,"preferences.dpapi");var writes=0;
  void Save(Preferences preferences){File.WriteAllBytes(store,System.Security.Cryptography.ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(preferences),null,System.Security.Cryptography.DataProtectionScope.CurrentUser));writes++;}
  var sounds=new List<string?>();
  using var panel=new PanelWindow(false,true,Save,testAudio:sound=>sounds.Add(sound)){ShowInTaskbar=false,StartPosition=FormStartPosition.Manual,Location=new Point(-16000,-16000)};
  Exception? failure=null;var completed=false;var stage="starting isolated WebView";var check=0;
  panel.Shown+=async(_,_)=>
  {
   try
   {
    await panel.PrepareAudioFixture(test,Path.Combine(test,"webview-profile"));panel.NavigateAudioFixture("audio-fixture.invalid");
    async Task Wait(string expression){stage=(++check)+": "+expression;File.AppendAllText(Path.Combine(test,"progress.txt"),stage+Environment.NewLine);for(var i=0;i<80;i++){await Task.Delay(100);if(await panel.AudioFixtureJS(expression)=="true")return;}throw new Exception("Audio fixture condition timed out: "+stage);}
    await Wait("window.multiplaNativeAudio===undefined&&window.multiplaNativeAudioConfirmed===true&&window.testAudioState?.type==='multipla.audio.state'");
    var selection=await panel.AudioFixtureJS("window.testAudioState.outputs.find(x=>x.id!=='')?.id||''");
    var id=JsonSerializer.Deserialize<string>(selection)??"";
    await panel.AudioFixtureJS("window.chrome.webview.postMessage({type:'multipla.audio.request',action:'select',device:"+JsonSerializer.Serialize(id)+"});window.chrome.webview.postMessage({type:'multipla.audio.request',action:'configure',enabled:false,volume:31,sound:'beep'});");
    await Wait("window.testAudioState?.volume===31&&window.testAudioState?.sound==='beep'");
    if(writes<2)throw new Exception("Production audio handler did not persist select/configure burst");
    var recovered=JsonSerializer.Deserialize<Preferences>(System.Security.Cryptography.ProtectedData.Unprotect(File.ReadAllBytes(store),null,System.Security.Cryptography.DataProtectionScope.CurrentUser));
    if(recovered?.AudioDevice!=id||recovered.Volume!=31||recovered.SoundType!="beep"||recovered.Key!="")throw new Exception("Isolated DPAPI preference roundtrip failed");
    panel.NavigateAudioFixture("audio-fixture.invalid");await Wait("window.multiplaNativeAudioConfirmed===true&&window.testAudioState?.volume===31");
    var capacity=new Notification("capacity",DateTimeOffset.UtcNow,"Capacidade da coleta","limite de grupos","critical",false,true);
    panel.AudioFixtureNotifications([capacity],true);
    await panel.AudioFixtureJS("document.querySelector('#alert-sound-enabled').checked=true;document.querySelector('#alert-sound-enabled').dispatchEvent(new Event('change'));");
    await Wait("window.testAudioState?.enabled===true");if(sounds.Count!=0)throw new Exception("Operational capacity warning played audio");
    var isolated=new Notification("isolated",DateTimeOffset.UtcNow,"Isolamento direto","teste fictício","critical",false,true,true,"siren","event-isolated","100.86.221.98");
    panel.AudioFixtureNotifications([isolated]);if(sounds.LastOrDefault()!="siren")throw new Exception("Authorized isolation did not start sink fixture");
    await panel.AudioFixtureJS("document.querySelector('#alert-sound-enabled').checked=false;document.querySelector('#alert-sound-enabled').dispatchEvent(new Event('change'));");
    await Wait("window.testAudioState?.enabled===false");if(sounds.LastOrDefault()!=null)throw new Exception("Master off did not stop pending isolation");
    var count=sounds.Count;panel.AudioFixtureNotifications([isolated,capacity],true);if(sounds.Count!=count||isolated.Read)throw new Exception("Muted snapshot restarted sound or marked read");
    await panel.AudioFixtureJS("document.querySelector('#alert-sound-enabled').checked=true;document.querySelector('#alert-sound-enabled').dispatchEvent(new Event('change'));");await Wait("window.testAudioState?.enabled===true");
    if(sounds.LastOrDefault()!="siren")throw new Exception("Explicit re-enable lost pending isolation policy");
    await panel.AudioFixtureJS("for(let i=0;i<20;i++)window.chrome.webview.postMessage({type:'multipla.audio.request',action:'outputs'});document.querySelector('#alert-sound-stop').click();");
    await Wait("window.testAudioState?.enabled===false");if(sounds.LastOrDefault()!=null)throw new Exception("Rate budget discarded explicit stop");
    panel.AudioFixtureNotifications([isolated],true);if(sounds.LastOrDefault()!=null)throw new Exception("Stop did not persist mute across ticks");
    await Task.Delay(1100);
    await panel.AudioFixtureJS("document.querySelector('#alert-sound-enabled').checked=true;document.querySelector('#alert-sound-enabled').dispatchEvent(new Event('change'));");await Wait("window.testAudioState?.enabled===true");
    panel.AudioFixtureNotifications([isolated with{Read=true}]);if(sounds.LastOrDefault()!=null)throw new Exception("Read isolation did not stop");
    var configured=new Notification("configured",DateTimeOffset.UtcNow,"Regra com áudio","teste fictício","critical",false,false,true,"beep","event-configured");
    panel.AudioFixtureNotifications([configured],true);if(sounds.LastOrDefault()!="beep")throw new Exception("Individual sound type ignored");
    panel.AudioFixtureNotifications([configured with{Sound=false}]);if(sounds.LastOrDefault()!=null)throw new Exception("Removed individual audio kept playing");
    count=sounds.Count;panel.AudioFixtureNotifications([configured]);if(sounds.Count!=count)throw new Exception("Pending notification replayed audio");
    await panel.AudioFixtureJS("document.querySelector('#alert-sound-enabled').checked=false;document.querySelector('#alert-sound-enabled').dispatchEvent(new Event('change'));");await Wait("window.testAudioState?.enabled===false");
    var before=writes;panel.NavigateAudioFixture("foreign-fixture.invalid");await Task.Delay(1600);
    await panel.AudioFixtureJS("window.chrome.webview.postMessage({type:'multipla.audio.request',action:'configure',enabled:true,volume:99,sound:'siren'});");await Task.Delay(400);
    if(writes!=before||panel.AudioFixturePreferences.Volume!=31)throw new Exception("Foreign origin changed native preferences");
    panel.NavigateAudioFixture("audio-fixture.invalid");await Wait("window.testAudioState?.volume===31&&window.multiplaNativeAudioConfirmed===true");completed=true;
   }
   catch(Exception ex){failure=ex;}
   finally{panel.Close();}
  };
  // This integration fixture now includes multiple DPAPI writes and native
  // mute/enable cycles. Each condition retains its own eight-second deadline.
  using var deadline=new System.Windows.Forms.Timer{Interval=60000};deadline.Tick+=(_,_)=>{failure=new TimeoutException("Isolated audio bridge fixture exceeded 60 seconds at "+stage);deadline.Stop();panel.Close();};deadline.Start();
  Application.Run(panel);deadline.Stop();
  File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"audio-bridge-self-test-result.txt"),completed&&failure==null?"PASS real production NativeAudioMessage: WebView2 HTTPS fixture, missing marker, MMDevice outputs, DPAPI persistence, capacity silent, continuous isolation master mute/stop/rate budget, read, individual opt-out/type, pending no-replay, reload and foreign-origin refusal; sink recorder only, no microphone/audio playback":"FAIL "+failure?.Message);
  if(failure!=null)Environment.ExitCode=1;
 }
}
