using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using Microsoft.Win32;
using NAudio.CoreAudioApi;
using NAudio.Wave;
using NAudio.Wave.SampleProviders;

namespace Multipla.Siem.Desktop;

internal static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        if (args.Length==2 && args[0]=="--audio-bridge-self-test") { ApplicationConfiguration.Initialize(); AudioBridgeSelfTest.Run(args[1]); return; }
        if (args.Length==2 && args[0]=="--update-self-test") { ApplicationConfiguration.Initialize(); DesktopUpdateSelfTest.Run(args[1]); return; }
        if (args.Contains("--self-test")) { SelfTest.Run(); return; }
        var updateRuntime=DesktopUpdateRuntime.Production();
        if(args.Length==1&&args[0]=="--update-health-check")
        {try{updateRuntime.HealthCheck();Environment.ExitCode=0;}catch{Environment.ExitCode=1;}return;}
        var handoff=args.Length==1&&args[0]=="--update-handoff";
        if(handoff){try{updateRuntime.ConsumeTicket("handoff");}catch{Environment.ExitCode=1;return;}}
        using var instance = DesktopInstanceGate.Production(handoff||args.Contains("--update-selected"));
        if (!instance.Acquired) { MessageBox.Show("Já existe uma instância do Multipla SIEM em execução na bandeja. Encerre-a pelo menu Sair antes de abrir esta cópia: "+Branding.AppName+". Uma instância anterior não é substituída ao abrir outro executável.", Branding.AppName, MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
        if(!handoff)
        {
            try{if(updateRuntime.Select(args.Contains("--tray")))return;}
            catch
            {
                try
                {
                    if(!updateRuntime.CanRecoverSelection||MessageBox.Show("O estado das atualizações locais não pôde ser validado. Recuperar somente esse estado e iniciar esta cópia base?\n\nO vínculo, as credenciais e as preferências do SIEM serão preservados. A seleção inválida será guardada como selection.invalid.backup; nenhum executável do cache será iniciado.",Branding.AppName,MessageBoxButtons.YesNo,MessageBoxIcon.Warning,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return;
                    updateRuntime.RecoverSelection(true);
                }
                catch{MessageBox.Show("A recuperação segura não foi possível. Abra a cópia original instalada e verifique permissões ou links no diretório de atualizações.",Branding.AppName);return;}
            }
        }
        ApplicationConfiguration.Initialize();
        Branding.InitializeTaskbar();
        Application.Run(new PanelWindow(args.Contains("--tray")));
    }
}

internal record Preferences(string Origin = "", string Key = "", string AudioDevice = "", bool Sound = false, int Volume = 40, string SoundType = "siren");
internal static class SecurityPolicy
{
    public static Uri Origin(string input)
    {
        if (!Uri.TryCreate(input, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.UserInfo != "" || uri.Query != "" || uri.Fragment != "" || uri.AbsolutePath != "/")
            throw new ArgumentException("Use somente a origem HTTPS do SIEM, sem usuário, caminho ou parâmetros.");
        return new Uri(uri.GetLeftPart(UriPartial.Authority) + "/");
    }
    public static bool SameOrigin(Uri origin, string address) => Uri.TryCreate(address, UriKind.Absolute, out var uri) && uri.Scheme == "https" && uri.UserInfo == "" && uri.Host == origin.Host && uri.Port == origin.Port;
}
internal static class SecureStore
{
    public static readonly string DirectoryPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Multipla", "SIEM");
    static readonly string FilePath = Path.Combine(DirectoryPath, "preferences.dpapi");
    static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Multipla SIEM desktop v1");
    public static Preferences Load()
    {
        if (!File.Exists(FilePath)) return new();
        if (new FileInfo(FilePath).Length > 16384) throw new InvalidDataException("Preferências inválidas.");
        var plain = ProtectedData.Unprotect(File.ReadAllBytes(FilePath), Entropy, DataProtectionScope.CurrentUser);
        try { return JsonSerializer.Deserialize<Preferences>(plain) ?? new(); } finally { CryptographicOperations.ZeroMemory(plain); }
    }
    public static void Save(Preferences settings)
    {
        Directory.CreateDirectory(DirectoryPath);
        var plain = JsonSerializer.SerializeToUtf8Bytes(settings);
        try
        {
            var encrypted = ProtectedData.Protect(plain, Entropy, DataProtectionScope.CurrentUser);
            var temporary = FilePath + ".new";
            File.WriteAllBytes(temporary, encrypted); File.Move(temporary, FilePath, true);
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }
}
internal record Notification(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("time")] DateTimeOffset Time,
    [property: JsonPropertyName("title")] string Title,
    [property: JsonPropertyName("detail")] string Detail,
    [property: JsonPropertyName("severity")] string Severity,
    [property: JsonPropertyName("read")] bool Read,
 [property: JsonPropertyName("continuous")] bool Continuous = false);
internal record NotificationResponse([property: JsonPropertyName("notifications")] Notification[] Notifications);

internal partial class PanelWindow : Form
{
    readonly WebView2 browser = new() { Dock = DockStyle.Fill };
    readonly NotifyIcon tray = new() { Icon = Branding.AppIcon, Text = Branding.AppName, Visible = false };
    readonly Label state = new() { Text = "Configure o servidor e vincule o app para receber alertas.", AutoSize = true, Padding = new Padding(8) };
    readonly System.Windows.Forms.Timer timer = new() { Interval = 5000 };
    readonly HttpClient http = new(new HttpClientHandler { AllowAutoRedirect = false, UseProxy = false }) { Timeout = TimeSpan.FromSeconds(15) };
    readonly CancellationTokenSource lifetime = new();
    readonly HashSet<string> seen = [];
    Preferences settings;
    Uri? origin;
    bool busy, exiting, initialized;
    bool googleLoginBusy;
    CancellationTokenSource? pendingGoogleLogin;
    Form? notificationWindow;
    ListBox? notificationList;
    Label? notificationHint;
    string notificationStatus = "Vínculo de notificações ainda não configurado.";
    MemoryStream? googleProof;
    ulong googleProofNavigationId;
    int failures;
    DateTimeOffset nextPoll;
    Notification[] notifications = [];
    WasapiOut? audio;
    MMDevice? outputDevice;
    readonly System.Windows.Forms.Timer isolationBlink = new(){Interval=500};
 readonly string profile = Path.Combine(SecureStore.DirectoryPath, "sessions", Guid.NewGuid().ToString("N"));

    readonly Action<Preferences> persistPreferences;
    void SavePreferences(Preferences value)=>persistPreferences(value);
    public PanelWindow(bool startHidden, bool isolatedTest=false, Action<Preferences>? testStore=null,DesktopUpdateUiFixture? updateFixture=null)
    {
        persistPreferences=isolatedTest?(testStore??(_=>{})):SecureStore.Save;
        tray.Visible=!isolatedTest;
        isolationBlink.Tick+=(_,_)=>{state.BackColor=state.BackColor==Color.Red?SystemColors.Control:Color.Red;state.ForeColor=state.BackColor==Color.Red?Color.White:SystemColors.ControlText;};
        Icon=Branding.AppIcon;ShowIcon=true;
        Text = Branding.AppName; Width = 1280; Height = 850;
        try { settings = isolatedTest ? new() : SecureStore.Load(); } catch { settings = new(); state.Text = "Não foi possível recuperar o vínculo. Configure novamente."; }
        var strip = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true };
        var configure = new Button { Text = "Servidor, vínculo e áudio", AutoSize = true };
        var alerts = new Button { Text = "Notificações", AutoSize = true };
        var google = new Button { Text = "Entrar com Google", AutoSize = true };
        var cancelGoogle = new Button { Text = "Cancelar login Google", AutoSize = true };
        cancelGoogle.Click += (_, _) => { pendingGoogleLogin?.Cancel(); if(!googleLoginBusy) state.Text="Nenhuma solicitação Google em andamento."; };
        google.Click += async (_, _) => await GoogleLogin();
        configure.Click += async (_, _) => await Configure(); alerts.Click += (_, _) => ShowNotifications();
        strip.Controls.AddRange([configure, google, cancelGoogle, alerts, state]); Controls.Add(browser); Controls.Add(strip);
        var menu = new ContextMenuStrip();
        menu.Items.Add("Abrir painel", null, (_, _) => OpenPanel());
        menu.Items.Add("Notificações / marcar leitura", null, (_, _) => ShowNotifications());
        menu.Items.Add("Configurar", null, async (_, _) => await Configure());
        InitializeAppUpdates(menu,isolatedTest,updateFixture);
        menu.Items.Add("Sobre / versão desta instância",null,(_,_)=>MessageBox.Show(this,Branding.AppName+"\nExecutável: "+Environment.ProcessPath,"Sobre · "+Branding.AppName,MessageBoxButtons.OK,MessageBoxIcon.Information));
        var startup = new ToolStripMenuItem("Iniciar com o Windows") { CheckOnClick = true, Checked = !isolatedTest && StartupEnabled() };
        startup.Click += (_, _) => { try { SetStartup(startup.Checked); } catch { startup.Checked = StartupEnabled(); MessageBox.Show("Não foi possível alterar a inicialização."); } };
        menu.Items.Add(startup);
        menu.Items.Add("Desvincular este app", null, (_, _) => { settings = settings with { Key = "" }; SavePreferences(settings); StopSound(); state.Text = "Desvinculado localmente. Revogue também o vínculo no painel."; });
        menu.Items.Add("Sair", null, (_, _) => { exiting = true; Close(); });
        tray.ContextMenuStrip = menu; tray.DoubleClick += (_, _) => OpenPanel(); tray.BalloonTipClicked += (_, _) => ShowNotifications();
        if(!isolatedTest) FormClosing += (_, eventArgs) => { if (!exiting && eventArgs.CloseReason == CloseReason.UserClosing) { eventArgs.Cancel = true; Hide(); } };
        timer.Tick += async (_, _) => await Poll();
        if(!isolatedTest) Shown += async (_, _) => { if (startHidden) Hide(); await LoadPanel(); timer.Start(); };
    }
    internal bool ValidateIsolatedBranding()=>Text==Branding.AppName&&Icon?.Handle==Branding.AppIcon.Handle&&tray.Icon?.Handle==Branding.AppIcon.Handle&&tray.Text==Branding.AppName&&!tray.Visible&&settings.Origin==""&&settings.Key=="";
    static bool StartupEnabled() { using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"); return key?.GetValue("MultiplaSIEM") is string; }
    static void SetStartup(bool enabled)
    {
        using var key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
        if (enabled) key.SetValue("MultiplaSIEM", "\"" + DesktopUpdateRuntime.Production().LauncherPath + "\" --tray"); else key.DeleteValue("MultiplaSIEM", false);
    }
    void OpenPanel() { Show(); WindowState = FormWindowState.Normal; Activate(); }
    string? audioBootstrapScriptId;
    async Task LoadPanel()
    {
        if (settings.Origin == "") return;
        try
        {
            origin = SecurityPolicy.Origin(settings.Origin);
            if (!initialized)
            {
                var environment = await CoreWebView2Environment.CreateAsync(null, profile);
                await browser.EnsureCoreWebView2Async(environment);
                var web = browser.CoreWebView2;
                web.IsMuted = true;
                web.Settings.AreDevToolsEnabled = false; web.Settings.AreHostObjectsAllowed = false;
                web.NavigationCompleted += (_, e) => { if(googleProof!=null && e.NavigationId==googleProofNavigationId){CryptographicOperations.ZeroMemory(googleProof.GetBuffer());googleProof.Dispose();googleProof=null;} };
                web.Settings.IsWebMessageEnabled = true;
 web.WebMessageReceived+=NativeAudioMessage;
 web.Settings.AreDefaultContextMenusEnabled = false;
                web.Settings.IsGeneralAutofillEnabled = false; web.Settings.IsPasswordAutosaveEnabled = false;
                web.NavigationStarting += (_, e) => {
                    if(googleProof!=null && origin!=null && SecurityPolicy.SameOrigin(origin,e.Uri) && new Uri(e.Uri).AbsolutePath=="/auth/desktop/consume") googleProofNavigationId=e.NavigationId;
                    if (origin != null && SecurityPolicy.SameOrigin(origin,e.Uri) && new Uri(e.Uri).AbsolutePath == "/auth/google") {e.Cancel=true; _ = GoogleLogin(); return;}
                    if (origin == null || !SecurityPolicy.SameOrigin(origin, e.Uri)) { e.Cancel = true; state.Text = "Navegação externa recusada. Use Entrar com Google para autenticação segura."; }
                };
                web.FrameNavigationStarting += (_, e) => { if (origin == null || !SecurityPolicy.SameOrigin(origin, e.Uri)) e.Cancel = true; };
                web.NewWindowRequested += (_, e) => { e.Handled = true; if (origin != null && SecurityPolicy.SameOrigin(origin, e.Uri)) web.Navigate(e.Uri); };
                web.ServerCertificateErrorDetected += (_, e) => { e.Action = CoreWebView2ServerCertificateErrorAction.Cancel; state.Text = "Certificado inválido. Corrija o HTTPS do servidor."; };
                web.PermissionRequested += (_, e) => e.State = CoreWebView2PermissionState.Deny;
                web.DownloadStarting += (_, e) => {
                    var address = e.DownloadOperation.Uri;
                    if (address.StartsWith("blob:", StringComparison.Ordinal)) address = address[5..];
                    if (origin == null || !SecurityPolicy.SameOrigin(origin, address)) { e.Cancel = true; return; }
                    using var save = new SaveFileDialog { FileName = Path.GetFileName(e.ResultFilePath), OverwritePrompt = true };
                    if (save.ShowDialog(this) != DialogResult.OK) { e.Cancel = true; return; }
                    e.ResultFilePath = save.FileName; e.Handled = true;
                };
                initialized = true;
            }
            if(audioBootstrapScriptId!=null)browser.CoreWebView2.RemoveScriptToExecuteOnDocumentCreated(audioBootstrapScriptId);
            audioBootstrapScriptId = await browser.CoreWebView2.AddScriptToExecuteOnDocumentCreatedAsync("if(window===window.top&&location.origin==="+JsonSerializer.Serialize(origin.GetLeftPart(UriPartial.Authority))+"){Object.defineProperty(window,'multiplaNativeAudio',{value:true,writable:false,configurable:false});}");
            browser.CoreWebView2.Navigate(origin.AbsoluteUri);
        }
        catch (Exception) { state.Text = "Não foi possível abrir o painel. Verifique HTTPS e WebView2 Runtime."; }
    }
    async Task Configure()
    {
        using var dialog = new Form { Icon=Branding.AppIcon, Text = "Conexão e alertas · "+Branding.AppName, Width = 620, Height = 460, StartPosition = FormStartPosition.CenterParent };
        var layout = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(16) };
        var url = new TextBox { Text = settings.Origin, Width = 550 };
        var key = new TextBox { Text = settings.Key, Width = 550, UseSystemPasswordChar = true, MaxLength = 43 };
        var devices = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 550 };
        var sound = new CheckBox { Text = "Tocar sirene para notificações críticas pendentes", Checked = settings.Sound, AutoSize = true };
        var outputs = new List<(string Id, string Name)> { ("", "Padrão do Windows") };
        try { using var enumerator = new MMDeviceEnumerator(); foreach (var device in enumerator.EnumerateAudioEndPoints(DataFlow.Render, DeviceState.Active)) { outputs.Add((device.ID, device.FriendlyName)); device.Dispose(); } } catch { }
        devices.Items.AddRange(outputs.Select(x => x.Name).Cast<object>().ToArray()); devices.SelectedIndex = Math.Max(0, outputs.FindIndex(x => x.Id == settings.AudioDevice));
        var save = new Button { Text = "Salvar e conectar", AutoSize = true, DialogResult = DialogResult.OK };
        layout.Controls.AddRange([new Label { Text = "Origem HTTPS do SIEM", AutoSize = true }, url, new Label { Text = "Chave de vínculo gerada no painel (validade: 7 dias)", AutoSize = true }, key, new Label { Text = "Saída da sirene do app", AutoSize = true }, devices, sound, new Label { Text = "A chave permite somente receber notificações e marcar leitura.\nO login do painel é separado. Fechar a janela mantém o app na bandeja.", AutoSize = true }, save]);
        dialog.Controls.Add(layout); dialog.AcceptButton = save;
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            var uri = SecurityPolicy.Origin(url.Text.Trim());
            if (key.Text.Length != 0 && (key.Text.Length != 43 || key.Text.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '_' && c != '-'))) throw new ArgumentException("Chave de vínculo inválida.");
            if (settings.Origin != "" && settings.Origin != uri.AbsoluteUri && initialized) throw new ArgumentException("Para trocar de servidor, saia e abra novamente o app. A sessão do painel não será transferida.");
            settings = new Preferences(uri.AbsoluteUri, key.Text, outputs[devices.SelectedIndex].Id, sound.Checked, settings.Volume, settings.SoundType);
            SavePreferences(settings); StopSound(); seen.Clear(); failures = 0; nextPoll = default;
            await LoadPanel(); await Poll();
        }
        catch (ArgumentException ex) { MessageBox.Show(this, ex.Message); }
        catch { MessageBox.Show(this, "Falha ao salvar configuração segura."); }
        finally { key.Clear(); }
    }
    HttpRequestMessage Request(HttpMethod method, string path)
    {
        if (origin == null) throw new InvalidOperationException();
        var request = new HttpRequestMessage(method, new Uri(origin, path));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", settings.Key); return request;
    }
    async Task Poll()
    {
        if (settings.Key == "") { if(!googleLoginBusy) SetNotificationStatus("Notificações não vinculadas. Gere a chave na Central de notificações do painel e cole em Servidor, vínculo e áudio."); return; }
        if (busy || origin == null || DateTimeOffset.UtcNow < nextPoll || exiting) return;
        busy = true;
        var connection = settings;
        try
        {
            using var request = Request(HttpMethod.Get, "api/desktop/notifications");
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, lifetime.Token);
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound || response.Content.Headers.ContentType?.MediaType != "application/json" && response.IsSuccessStatusCode)
            { StopSound(); SetNotificationStatus("Painel disponível · servidor precisa de atualização para notificações do app."); nextPoll = DateTimeOffset.UtcNow.AddSeconds(60); return; }
            if (response.StatusCode is System.Net.HttpStatusCode.Unauthorized or System.Net.HttpStatusCode.Forbidden)
            { StopSound(); notifications=[]; SetNotificationStatus("Chave de notificações inválida, expirada ou revogada. Gere a chave na Central de notificações; a chave do console não serve para vincular o app."); nextPoll = DateTimeOffset.MaxValue; return; }
            response.EnsureSuccessStatusCode();
            await using var stream = await response.Content.ReadAsStreamAsync(lifetime.Token);
            using var buffer = new MemoryStream(); var bytes = new byte[8192]; int count;
            while ((count = await stream.ReadAsync(bytes, lifetime.Token)) > 0) { if (buffer.Length + count > 1_048_576) throw new InvalidDataException(); buffer.Write(bytes, 0, count); }
            if (connection != settings) return;
            notifications = JsonSerializer.Deserialize<NotificationResponse>(buffer.ToArray())?.Notifications ?? [];
            if (notifications.Length > 200) throw new InvalidDataException();
            var valid = notifications.Select(n => n.Id).ToHashSet(); seen.IntersectWith(valid);
            var fresh = notifications.Where(n => !n.Read && seen.Add(n.Id)).OrderBy(n => n.Time).ToArray();
            if (fresh.Length > 0)
            {
                var n = fresh[^1];
                var detail = fresh.Length > 1 ? fresh.Length + " novas notificações. " + n.Detail : n.Detail;
                tray.ShowBalloonTip(5000, n.Title.Length > 63 ? n.Title[..63] : n.Title, detail.Length > 255 ? detail[..255] : detail, fresh.Any(x => x.Severity == "critical") ? ToolTipIcon.Warning : ToolTipIcon.Info);
            }
            var urgent=notifications.Any(n=>!n.Read&&n.Continuous);if(urgent)isolationBlink.Start();else{isolationBlink.Stop();state.BackColor=SystemColors.Control;state.ForeColor=SystemColors.ControlText;}
 if (urgent || settings.Sound && notifications.Any(n => !n.Read && n.Severity == "critical")) StartSound(); else StopSound();
            failures = 0; nextPoll = default; SetNotificationStatus("Notificações sincronizadas · " + notifications.Count(n => !n.Read) + " pendentes · atualizado " + DateTime.Now.ToString("HH:mm:ss"));
        }
        catch (OperationCanceledException) when (exiting) { }
        catch { failures = Math.Min(failures + 1, 6); nextPoll = DateTimeOffset.UtcNow.AddSeconds(Math.Min(60, Math.Pow(2, failures))); SetNotificationStatus("Notificações sem conexão; nova tentativa em breve. O painel possui conexão separada."); }
        finally { busy = false; }
    }
    async Task GoogleLogin()
    {
        if(googleLoginBusy){state.Text="Login Google em andamento. Use Cancelar login Google antes de tentar novamente.";return;}
        if(origin==null||!initialized){MessageBox.Show(this,"Configure primeiro a origem HTTPS do SIEM.");return;}
        googleLoginBusy=true;
        var server = origin;
        var verifier = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+','-').Replace('/','_');
        var challenge = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))).TrimEnd('=').Replace('+','-').Replace('/','_');
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token); pendingGoogleLogin=timeout; timeout.CancelAfter(TimeSpan.FromMinutes(5));
        try
        {
            using var begin = new HttpRequestMessage(HttpMethod.Post,new Uri(server,"auth/desktop/start")){Content=new StringContent(JsonSerializer.Serialize(new{challenge}),Encoding.UTF8,"application/json")};
            using var response = await http.SendAsync(begin,timeout.Token);
            if (!response.IsSuccessStatusCode || response.Content.Headers.ContentType?.MediaType != "application/json") throw new InvalidOperationException("Início do login recusado (HTTP "+(int)response.StatusCode+"). Confira a versão do servidor e a configuração Google.");
            var text = await response.Content.ReadAsStringAsync(timeout.Token);if(text.Length>4096)throw new InvalidDataException();
            using var data = JsonDocument.Parse(text);
            var id=data.RootElement.GetProperty("id").GetString()!;var code=data.RootElement.GetProperty("code").GetString()!;var url=data.RootElement.GetProperty("url").GetString()!;
            if(!SecurityPolicy.SameOrigin(server,url)||new Uri(url).AbsolutePath!="/auth/desktop/google"||id.Length!=43||code.Length!=9)throw new InvalidDataException();
            state.Text="Login Google · compare o código "+code+" no navegador e confirme somente sua solicitação.";
            Process.Start(new ProcessStartInfo(url){UseShellExecute=true});
            while(!timeout.IsCancellationRequested)
            {
                await Task.Delay(2000,timeout.Token);
                using var poll=new HttpRequestMessage(HttpMethod.Post,new Uri(server,"auth/desktop/status")){Content=new StringContent(JsonSerializer.Serialize(new{id,verifier}),Encoding.UTF8,"application/json")};
                using var status=await http.SendAsync(poll,timeout.Token);status.EnsureSuccessStatusCode();
                var statusText=await status.Content.ReadAsStringAsync(timeout.Token);if(statusText.Length>4096)throw new InvalidDataException();
                using var result=JsonDocument.Parse(statusText);
                if(result.RootElement.TryGetProperty("error",out var failure) && failure.GetString() is string error && error!="")throw new InvalidOperationException(error);
                if(result.RootElement.TryGetProperty("stage",out var stage)){state.Text=stage.GetString() switch {"awaiting_browser"=>"Aguardando abertura do navegador no endereço do SIEM. Se houver 404, confira domínio e caminho. Código "+code,"google_redirect"=>"Aguardando retorno do Google. Conclua o login no navegador. Código "+code,"google_callback"=>"Google retornou ao SIEM; validando identidade…",_=>state.Text};}
                if(!result.RootElement.GetProperty("approved").GetBoolean()){if(result.RootElement.GetProperty("email").GetString() is string pendingEmail && pendingEmail!="")state.Text="Conta Google identificada. No navegador, confirme o código "+code+" para autorizar o app.";continue;}
                var email=result.RootElement.GetProperty("email").GetString();
                if(origin!=server||MessageBox.Show(this,"Entrar no painel como "+email+"?\nConfirme que esta é a conta escolhida no navegador.","Confirmar identidade",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes) {state.Text="Login cancelado.";return;}
                var body=Encoding.UTF8.GetBytes("id="+Uri.EscapeDataString(id)+"&verifier="+Uri.EscapeDataString(verifier));
                // POST proof once into the WebView. The server sets its HttpOnly session directly.
                googleProof?.Dispose();googleProof=new MemoryStream();googleProof.Write(body);googleProof.Position=0;CryptographicOperations.ZeroMemory(body);
                var resource=browser.CoreWebView2.Environment.CreateWebResourceRequest(new Uri(server,"auth/desktop/consume").AbsoluteUri,"POST",googleProof,"Content-Type: application/x-www-form-urlencoded\r\n");
                browser.CoreWebView2.NavigateWithWebResourceRequest(resource);
                state.Text="Login Google autorizado · aguardando abertura do painel.";return;
            }
        }
        catch(OperationCanceledException){if(!exiting)state.Text=timeout.IsCancellationRequested?"Solicitação Google cancelada ou expirada. Clique em Entrar com Google para iniciar outra.":"O servidor demorou mais de 15 segundos para responder ao login Google. Tente novamente.";}
        catch(InvalidOperationException e){state.Text=e.Message;}
        catch(HttpRequestException e){state.Text="Falha na etapa Google: "+(e.StatusCode.HasValue?"HTTP "+(int)e.StatusCode.Value:"conexão HTTPS indisponível")+". Você pode tentar novamente.";}
        catch{state.Text="Falha ao abrir o navegador ou processar o login Google. Verifique o navegador padrão e tente novamente.";}
        finally{verifier="";googleLoginBusy=false;pendingGoogleLogin=null;}
    }
    void StartSound()
    {
        if (audio != null) return;
        try
        {
            using var enumerator = new MMDeviceEnumerator();
            outputDevice = settings.AudioDevice == "" ? enumerator.GetDefaultAudioEndpoint(DataFlow.Render, Role.Multimedia) : enumerator.GetDevice(settings.AudioDevice);
            if (outputDevice.State != DeviceState.Active) throw new InvalidOperationException();
            audio = new WasapiOut(outputDevice, AudioClientShareMode.Shared, true, 100);
            var beep=settings.SoundType=="beep" && !notifications.Any(n=>!n.Read && n.Continuous);
            audio.Init(new SignalGenerator(44100, 1) { Gain = Math.Clamp(settings.Volume,0,100)/100.0*0.35, Frequency = beep?880:550, FrequencyEnd = 1100, SweepLengthSecs = 1, Type = beep?SignalGeneratorType.Sin:SignalGeneratorType.Sweep }); audio.Play();
        }
        catch { StopSound(); state.Text = "Saída de áudio indisponível. Selecione novamente; não houve troca automática para o headphone."; }
    }
    void StopSound() { audio?.Stop(); audio?.Dispose(); audio = null; outputDevice?.Dispose(); outputDevice = null; }
    void SetNotificationStatus(string message)
    {
        notificationStatus=message;
        if(!googleLoginBusy)state.Text=message;
        RefreshNotificationWindow();
    }
    void RefreshNotificationWindow()
    {
        if(notificationList==null||notificationHint==null||notificationWindow==null||notificationWindow.IsDisposed)return;
        var selected=(notificationList.SelectedItem as NotificationItem)?.Value.Id;
        notificationList.BeginUpdate();notificationList.Items.Clear();
        foreach(var n in notifications)notificationList.Items.Add(new NotificationItem(n));
        for(int i=0;i<notificationList.Items.Count;i++)if(((NotificationItem)notificationList.Items[i]).Value.Id==selected)notificationList.SelectedIndex=i;
        notificationList.EndUpdate();
        notificationHint.Text=notificationStatus+(notifications.Length==0?"\nNenhuma notificação recebida pelo app. O login do painel e o vínculo de notificações são separados.":"");
    }
    sealed record NotificationItem(Notification Value)
    {
        public override string ToString()=>(Value.Read?"[Lida] ":"[Pendente] ")+Value.Title+" · "+Value.Detail;
    }
    void ShowNotifications()
    {
        if(notificationWindow is {IsDisposed:false}){notificationWindow.Activate();return;}
        var dialog=new Form{Icon=Branding.AppIcon,Text="Notificações do SIEM",Width=820,Height=520,StartPosition=FormStartPosition.CenterScreen};
        var list=new ListBox{Dock=DockStyle.Fill};var hint=new Label{Dock=DockStyle.Top,Height=70,Padding=new Padding(12)};
        var read=new Button{Text="Marcar selecionada como lida",Dock=DockStyle.Bottom,Height=38};
        var readAll=new Button{Text="Marcar todas como lidas",Dock=DockStyle.Bottom,Height=38};
        var refresh=new Button{Text="Sincronizar agora",Dock=DockStyle.Bottom,Height=38};
        notificationWindow=dialog;notificationList=list;notificationHint=hint;
        readAll.Click+=async(_,_)=>
        {
            var ids=notifications.Where(n=>!n.Read).Select(n=>n.Id).ToArray();
            if(ids.Length==0)return;
            readAll.Enabled=false;
            try
            {
                using var request=Request(HttpMethod.Post,"api/desktop/notifications/read-all");
                request.Content=System.Net.Http.Json.JsonContent.Create(new{ids});
                using var response=await http.SendAsync(request,lifetime.Token);response.EnsureSuccessStatusCode();
                nextPoll=default;await Poll();RefreshNotificationWindow();
            }
            catch{MessageBox.Show(dialog,"Não foi possível confirmar a leitura de todas as notificações no servidor.");}
            finally{readAll.Enabled=true;}
        };
        refresh.Click+=async(_,_)=>{nextPoll=default;await Poll();RefreshNotificationWindow();};
        read.Click+=async(_,_)=>
        {
            if(list.SelectedItem is not NotificationItem item)return;
            read.Enabled=false;
            try{using var request=Request(HttpMethod.Post,"api/desktop/notifications/"+Uri.EscapeDataString(item.Value.Id)+"/read");using var response=await http.SendAsync(request,lifetime.Token);response.EnsureSuccessStatusCode();nextPoll=default;await Poll();}
            catch{MessageBox.Show(dialog,"Não foi possível confirmar a leitura no servidor.");}finally{read.Enabled=true;}
        };
        dialog.FormClosed+=(_,_)=>{notificationWindow=null;notificationList=null;notificationHint=null;dialog.Dispose();};
        dialog.Controls.Add(list);dialog.Controls.Add(hint);dialog.Controls.Add(read);dialog.Controls.Add(readAll);dialog.Controls.Add(refresh);RefreshNotificationWindow();dialog.Show(this);
        nextPoll=default;_ = Poll();
    }
    bool resourcesDisposed;
    protected override void Dispose(bool disposing)
    {
        if (disposing && !resourcesDisposed) { resourcesDisposed=true; lifetime.Cancel(); pendingGoogleLogin?.Cancel(); notificationWindow?.Close(); googleProof?.Dispose(); timer.Dispose(); updateTimer.Dispose(); isolationBlink.Dispose(); tray.Visible = false; tray.Dispose(); StopSound(); http.Dispose(); browser.Dispose(); lifetime.Dispose(); }
        base.Dispose(disposing);
        // Profile is ephemeral; remove only this generated subdirectory, never a shared browser profile.
        try { if (Directory.Exists(profile)) Directory.Delete(profile, true); } catch { }
    }
}

internal static class SelfTest
{
 static string AssemblyVersion()=>System.Reflection.Assembly.GetExecutingAssembly().GetName().Version!.ToString(3);
    public static void Run()
    {
        var origin = SecurityPolicy.Origin("https://siem.example:8443");
        if (!SecurityPolicy.SameOrigin(origin, "https://siem.example:8443/api") || SecurityPolicy.SameOrigin(origin, "https://siem.example.evil:8443") || SecurityPolicy.SameOrigin(origin, "http://siem.example:8443")) throw new Exception("Origin policy failed");
        foreach (var invalid in new[] { "http://localhost", "https://user@siem.example", "https://siem.example/path", "https://siem.example/?key=secret" })
        { try { SecurityPolicy.Origin(invalid); throw new Exception("Unsafe origin accepted"); } catch (ArgumentException) { } }
        var plain = Encoding.UTF8.GetBytes("test-only-credential");
        var encrypted = ProtectedData.Protect(plain, null, DataProtectionScope.CurrentUser);
        if (!ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser).SequenceEqual(plain)) throw new Exception("DPAPI failed");
        if(Branding.AppIcon.Handle==IntPtr.Zero)throw new Exception("Brand icon missing");
 using(var associated=Icon.ExtractAssociatedIcon(Environment.ProcessPath!)){if(associated==null)throw new Exception("PE icon missing");using var b=associated.ToBitmap();var green=0;for(var y=0;y<b.Height;y++)for(var x=0;x<b.Width;x++){var c=b.GetPixel(x,y);if(c.A>128&&c.G>c.R*1.6&&c.G>c.B)green++;}if(green<b.Width*b.Height/10)throw new Exception("PE icon is not the Multipla logo");}
 using(var window=new Form{Icon=Branding.AppIcon,Text=Branding.AppName})using(var tray=new NotifyIcon{Icon=Branding.AppIcon,Text=Branding.AppName,Visible=false}){if(window.Icon.Handle==IntPtr.Zero||tray.Icon.Handle==IntPtr.Zero||!tray.Text.EndsWith(AssemblyVersion()))throw new Exception("Window/tray branding failed");}
 var budget=new AudioRequestBudget();var instant=DateTimeOffset.UtcNow;for(var i=0;i<16;i++)if(!budget.Allow(instant))throw new Exception("Legitimate audio burst discarded");if(budget.Allow(instant)||!budget.Allow(instant.AddSeconds(1)))throw new Exception("Audio request limit failed");
 using(var enumerator=new MMDeviceEnumerator()){var outputs=enumerator.EnumerateAudioEndPoints(DataFlow.Render,DeviceState.Active);foreach(var device in outputs)device.Dispose();}
 using(var panel=new PanelWindow(false,true)){if(!panel.ValidateIsolatedBranding())throw new Exception("Production PanelWindow/tray branding failed in isolated mode");}
 File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "self-test-result.txt"), "PASS: HTTPS, origin isolation, rejected unsafe URLs, DPAPI CurrentUser, brand icon, native Windows output enumeration");
    }
}
