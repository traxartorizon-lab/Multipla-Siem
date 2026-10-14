using System.Reflection;
using System.Runtime.InteropServices;

namespace Multipla.Siem.Desktop;

internal static class Branding
{
    public static readonly string AppName="Multipla SIEM "+Assembly.GetExecutingAssembly().GetName().Version!.ToString(3);
    public static readonly Icon AppIcon=LoadIcon();
    static Icon LoadIcon()
    {
        var assembly=Assembly.GetExecutingAssembly();
        using var stream=assembly.GetManifestResourceStream(assembly.GetManifestResourceNames().Single(n=>n.EndsWith(".app.ico",StringComparison.Ordinal)))??throw new InvalidOperationException("Ícone Multipla SIEM ausente.");
        using var icon=new Icon(stream);return (Icon)icon.Clone();
    }
    [DllImport("shell32.dll",CharSet=CharSet.Unicode)]
    static extern int SetCurrentProcessExplicitAppUserModelID(string id);
    public static void InitializeTaskbar()=>SetCurrentProcessExplicitAppUserModelID("Multipla.SIEM.Desktop");
}
