namespace Multipla.Siem.Desktop;

internal sealed class NotificationAudioPlan
{
    DateTimeOffset until;
    string? eventId;
    string sound="beep";
    internal static bool Isolation(Notification n)=>n.Continuous&&n.Sound&&!n.Read&&!string.IsNullOrEmpty(n.IsolationIP)&&!string.IsNullOrEmpty(n.EventId);
    internal void Reset(){until=default;eventId=null;}
    internal void Preview(string selected,DateTimeOffset now){sound=selected;eventId=null;until=now.AddSeconds(4);}
    internal string? Evaluate(bool enabled,Notification[] current,Notification[] fresh,string fallback,DateTimeOffset now)
    {
        if(!enabled){Reset();return null;}
        if(current.Any(Isolation)){Reset();return "siren";}
        var next=fresh.LastOrDefault(n=>n.Sound&&!n.Read&&!n.Continuous&&!string.IsNullOrEmpty(n.EventId));
        if(next!=null){eventId=next.Id;sound=next.SoundType is "beep" or "siren"?next.SoundType:fallback;until=now.AddSeconds(4);}
        if(eventId!=null)
        {
            var existing=current.FirstOrDefault(n=>n.Id==eventId&&n.Sound&&!n.Read&&!n.Continuous);
            if(existing==null){Reset();return null;}
            sound=existing.SoundType is "beep" or "siren"?existing.SoundType:fallback;
        }
        if(now>=until){Reset();return null;}return sound;
    }
}
internal partial class PanelWindow
{
    readonly NotificationAudioPlan notificationAudioPlan=new();
    readonly System.Windows.Forms.Timer notificationAudioTimer=new(){Interval=250};
    readonly Action<string?>? audioFixture;
    string? playingSound;
    int playingVolume;
    bool notificationAudioPrimed;
    void ReconcileNotificationAudio(Notification[]? fresh=null)
    {
        // Explicit output previews also work before linking notifications.
        if(settings.Key==""&&audioFixture==null)notifications=[];
        var urgent=notifications.Any(NotificationAudioPlan.Isolation);
        if(urgent)isolationBlink.Start();else{isolationBlink.Stop();state.BackColor=SystemColors.Control;state.ForeColor=SystemColors.ControlText;}
        var selected=notificationAudioPlan.Evaluate(settings.Sound,notifications,fresh??[],settings.SoundType,DateTimeOffset.UtcNow);
        if(selected==null)StopSound();else StartSound(selected);
    }
    void MuteNativeAudio()
    {
        settings=settings with{Sound=false};notificationAudioPlan.Reset();StopSound();SavePreferences(settings);
    }
    internal void AudioFixtureNotifications(Notification[] values,bool fresh=false)
    {
        if(audioFixture==null)throw new InvalidOperationException("Isolated audio sink required.");
        notifications=values;ReconcileNotificationAudio(fresh?values:[]);
    }
}
