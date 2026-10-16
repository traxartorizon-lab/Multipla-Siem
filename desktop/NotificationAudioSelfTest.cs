namespace Multipla.Siem.Desktop;

internal static class NotificationAudioSelfTest
{
    internal static void Run()
    {
        var plan=new NotificationAudioPlan();var now=DateTimeOffset.UtcNow;
        var capacity=new Notification("capacity",now,"Capacidade","cota","critical",false,true);
        var rule=new Notification("rule",now,"Regra","fictício","critical",false,false,true,"beep","event-rule");
        var isolation=new Notification("isolation",now,"Isolamento","fictício","critical",false,true,true,"siren","event-isolation","100.86.221.98");
        void Expect(string? value,string label){if(value!=label)throw new Exception("Audio policy failed: "+label);}
        if(plan.Evaluate(true,[capacity],[capacity],"siren",now)!=null)throw new Exception("Capacity severity opted into audio");
        Expect(plan.Evaluate(true,[rule],[rule],"siren",now),"beep");
        if(plan.Evaluate(true,[rule],[],"siren",now.AddSeconds(5))!=null)throw new Exception("Pending critical replayed");
        Expect(plan.Evaluate(true,[rule],[rule],"siren",now),"beep");
        if(plan.Evaluate(true,[rule with{Sound=false}],[],"siren",now)!=null)throw new Exception("Individual mute ignored");
        Expect(plan.Evaluate(true,[isolation],[],"beep",now),"siren");
        if(plan.Evaluate(false,[isolation],[rule],"siren",now)!=null)throw new Exception("Continuous bypassed master mute");
        Expect(plan.Evaluate(true,[isolation],[],"beep",now),"siren");
        if(plan.Evaluate(true,[isolation with{Read=true}],[],"siren",now)!=null)throw new Exception("Read isolation continued");
        plan.Preview("beep",now);Expect(plan.Evaluate(true,[],[],"siren",now),"beep");
        Expect(plan.Evaluate(true,[isolation],[],"beep",now),"siren");
        if(plan.Evaluate(true,[isolation with{Read=true}],[],"siren",now)!=null)throw new Exception("Reading isolation resumed a stale preview");
        if(plan.Evaluate(true,[capacity with{Sound=true}],[],"siren",now)!=null)throw new Exception("Legacy malformed continuous accepted");
        plan.Preview("beep",now);if(plan.Evaluate(false,[],[],"siren",now)!=null)throw new Exception("Mute did not cancel preview");
        if(plan.Evaluate(true,[],[],"siren",now)!=null)throw new Exception("Enabling replayed cancelled preview");
    }
}
