using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using NAudio.CoreAudioApi;

namespace Multipla.Siem.Desktop;

internal sealed class AudioRequestBudget
{
    DateTimeOffset start;
    int count;
    public bool Allow(DateTimeOffset now)
    {
        if(now-start>=TimeSpan.FromSeconds(1)){start=now;count=0;}
        return ++count<=16;
    }
}

internal partial class PanelWindow
{
    readonly AudioRequestBudget audioRequestBudget=new();
    bool audioChoosing;
    List<(string Id,string Name)> AudioOutputs()
    {
        var outputs=new List<(string,string)>{("","Padrão do Windows")};
        using var enumerator=new MMDeviceEnumerator();
        foreach(var device in enumerator.EnumerateAudioEndPoints(DataFlow.Render,DeviceState.Active))
        {using(device)outputs.Add((device.ID,device.FriendlyName));}
        return outputs;
    }
    void SendAudioState(string? error=null)
    {
        if(origin==null||!SecurityPolicy.SameOrigin(origin,browser.Source?.AbsoluteUri??""))return;
        var outputs=AudioOutputs();
        browser.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(new{type="multipla.audio.state",outputs=outputs.Select(d=>new{id=d.Id,label=d.Name}),selected=settings.AudioDevice,enabled=settings.Sound,volume=settings.Volume,sound=settings.SoundType,error}));
    }
    async void NativeAudioMessage(object? sender,CoreWebView2WebMessageReceivedEventArgs e)
    {
        if(origin==null||!SecurityPolicy.SameOrigin(origin,e.Source)||!SecurityPolicy.SameOrigin(origin,browser.Source?.AbsoluteUri??""))return;
        // Permit ordinary outputs→select→configure→test bursts; the former
        // blanket 150ms gate silently discarded legitimate successive actions.
        try
        {
            var raw=e.WebMessageAsJson;if(raw.Length>4096)return;
            using var message=JsonDocument.Parse(raw);var root=message.RootElement;
            if(!root.TryGetProperty("type",out var type)||type.GetString()!="multipla.audio.request")return;
            var action=root.GetProperty("action").GetString();
            var mute=action=="stop"||(action=="configure"&&root.TryGetProperty("enabled",out var enabledValue)&&enabledValue.ValueKind==JsonValueKind.False);
            if(!audioRequestBudget.Allow(DateTimeOffset.UtcNow)&&!mute)return;
            switch(action)
            {
                case "outputs":SendAudioState();return;
                case "choose":
                    if(audioChoosing)return;audioChoosing=true;
                    try
                    {
                        var outputs=AudioOutputs();using var dialog=new Form{Text="Saída de áudio · "+Branding.AppName,Width=600,Height=180,StartPosition=FormStartPosition.CenterParent,Icon=Icon};
                        var list=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Dock=DockStyle.Top};list.Items.AddRange(outputs.Select(d=>(object)d.Name).ToArray());list.SelectedIndex=Math.Max(0,outputs.FindIndex(d=>d.Id==settings.AudioDevice));
                        var save=new Button{Text="Usar esta saída",DialogResult=DialogResult.OK,Dock=DockStyle.Bottom};dialog.Controls.Add(list);dialog.Controls.Add(save);dialog.AcceptButton=save;
                        if(dialog.ShowDialog(this)==DialogResult.OK){settings=settings with{AudioDevice=outputs[list.SelectedIndex].Id};SavePreferences(settings);StopSound();}
                    }finally{audioChoosing=false;}
                    SendAudioState();return;
                case "select":
                    var id=root.GetProperty("device").GetString()??"";
                    if(!AudioOutputs().Any(d=>d.Id==id))throw new InvalidOperationException("Saída indisponível. Selecione novamente.");
                    settings=settings with{AudioDevice=id};SavePreferences(settings);StopSound();SendAudioState();return;
                case "configure":
                    var volume=root.GetProperty("volume").GetInt32();var sound=root.GetProperty("sound").GetString();var enabled=root.GetProperty("enabled").GetBoolean();
                    if(volume<0||volume>100||sound is not ("beep" or "siren"))return;
                    settings=settings with{Volume=volume,SoundType=sound,Sound=enabled};if(!enabled){notificationAudioPlan.Reset();StopSound();}SavePreferences(settings);ReconcileNotificationAudio();SendAudioState();return;
                case "test":
                    settings=settings with{Sound=true};SavePreferences(settings);
                    notificationAudioPlan.Preview(settings.SoundType,DateTimeOffset.UtcNow);ReconcileNotificationAudio();await Task.Delay(4000,lifetime.Token);ReconcileNotificationAudio();SendAudioState();return;
                case "stop":
                    MuteNativeAudio();SendAudioState();return;
            }
        }
        catch(OperationCanceledException){}
        catch{try{SendAudioState("Não foi possível usar a saída escolhida. Confira se ela está conectada ao Windows.");}catch{}}
    }
}
