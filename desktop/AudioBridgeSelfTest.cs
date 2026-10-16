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
  using var panel=new PanelWindow(false,true,Save){ShowInTaskbar=false,StartPosition=FormStartPosition.Manual,Location=new Point(-16000,-16000)};
  Exception? failure=null;var completed=false;
  panel.Shown+=async(_,_)=>
  {
   try
   {
    await panel.PrepareAudioFixture(test,Path.Combine(test,"webview-profile"));panel.NavigateAudioFixture("audio-fixture.invalid");
    async Task Wait(string expression){for(var i=0;i<80;i++){await Task.Delay(100);if(await panel.AudioFixtureJS(expression)=="true")return;}throw new Exception("Audio fixture condition timed out: "+expression);}
    await Wait("window.multiplaNativeAudio===undefined&&window.multiplaNativeAudioConfirmed===true&&window.testAudioState?.type==='multipla.audio.state'");
    var selection=await panel.AudioFixtureJS("window.testAudioState.outputs.find(x=>x.id!=='')?.id||''");
    var id=JsonSerializer.Deserialize<string>(selection)??"";
    await panel.AudioFixtureJS("window.chrome.webview.postMessage({type:'multipla.audio.request',action:'select',device:"+JsonSerializer.Serialize(id)+"});window.chrome.webview.postMessage({type:'multipla.audio.request',action:'configure',enabled:false,volume:31,sound:'beep'});");
    await Wait("window.testAudioState?.volume===31&&window.testAudioState?.sound==='beep'");
    if(writes<2)throw new Exception("Production audio handler did not persist select/configure burst");
    var recovered=JsonSerializer.Deserialize<Preferences>(System.Security.Cryptography.ProtectedData.Unprotect(File.ReadAllBytes(store),null,System.Security.Cryptography.DataProtectionScope.CurrentUser));
    if(recovered?.AudioDevice!=id||recovered.Volume!=31||recovered.SoundType!="beep"||recovered.Key!="")throw new Exception("Isolated DPAPI preference roundtrip failed");
    panel.NavigateAudioFixture("audio-fixture.invalid");await Wait("window.multiplaNativeAudioConfirmed===true&&window.testAudioState?.volume===31");
    var before=writes;panel.NavigateAudioFixture("foreign-fixture.invalid");await Task.Delay(1600);
    await panel.AudioFixtureJS("window.chrome.webview.postMessage({type:'multipla.audio.request',action:'configure',enabled:true,volume:99,sound:'siren'});");await Task.Delay(400);
    if(writes!=before||panel.AudioFixturePreferences.Volume!=31)throw new Exception("Foreign origin changed native preferences");
    panel.NavigateAudioFixture("audio-fixture.invalid");await Wait("window.testAudioState?.volume===31&&window.multiplaNativeAudioConfirmed===true");completed=true;
   }
   catch(Exception ex){failure=ex;}
   finally{panel.Close();}
  };
  using var deadline=new System.Windows.Forms.Timer{Interval=30000};deadline.Tick+=(_,_)=>{failure=new TimeoutException("Isolated audio bridge fixture exceeded 30 seconds");deadline.Stop();panel.Close();};deadline.Start();
  Application.Run(panel);deadline.Stop();
  File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"audio-bridge-self-test-result.txt"),completed&&failure==null?"PASS real production NativeAudioMessage: WebView2 HTTPS fixture, missing marker, MMDevice outputs, select/configure burst, isolated DPAPI persistence, reload, foreign-origin refusal; no microphone/audio playback":"FAIL "+failure?.Message);
  if(failure!=null)Environment.ExitCode=1;
 }
}
