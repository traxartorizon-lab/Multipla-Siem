namespace Multipla.Siem.Desktop;

internal sealed class DesktopInstanceGate:IDisposable
{
    readonly Mutex mutex;
    bool disposed;
    internal bool Acquired{get;}
    DesktopInstanceGate(string name,TimeSpan wait)
    {
        mutex=new Mutex(true,name,out var first);if(first){Acquired=true;return;}
        if(wait<=TimeSpan.Zero)return;
        try{Acquired=mutex.WaitOne(wait);}catch(AbandonedMutexException){Acquired=true;}
    }
    internal static DesktopInstanceGate Production(bool handoff)=>new(@"Local\Multipla.Siem.Desktop",handoff?TimeSpan.FromSeconds(30):TimeSpan.Zero);
    internal static DesktopInstanceGate ForTests(Guid identity,TimeSpan wait)=>new(@"Local\Multipla.Siem.Update.Test."+identity.ToString("N"),wait);
    public void Dispose(){if(disposed)return;disposed=true;if(Acquired)mutex.ReleaseMutex();mutex.Dispose();}
}
