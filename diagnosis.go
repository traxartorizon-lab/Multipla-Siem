package main

import (
	"regexp"
	"strconv"
	"strings"
)

type Diagnosis struct {
	Engine      string   `json:"engine"`
	Title       string   `json:"title"`
	Cause       string   `json:"cause"`
	Evidence    string   `json:"evidence"`
	Checks      []string `json:"checks"`
	Remediation []string `json:"remediation"`
	Uncertainty string   `json:"uncertainty"`
	Reference   string   `json:"reference,omitempty"`
}

var diagnosisOOM = regexp.MustCompile(`(?i)\boom\b|oom-kill|oom_kill|out of memory`)
var criticalPRI = regexp.MustCompile(`^<([0-9]{1,3})>`)

func criticalEvent(e Event) bool {
	if e.Level >= 12 || analysisCritical.MatchString(e.Message) {
		return true
	}
	if matches := criticalPRI.FindStringSubmatch(e.Message); len(matches) > 1 {
		priority, _ := strconv.Atoi(matches[1])
		if priority <= 191 && priority%8 <= 2 {
			return true
		}
	}
	if e.CEF != nil {
		_, level := cefAlert(*e.CEF)
		return level >= 12
	}
	return false
}

func localDiagnosis(e Event) *Diagnosis {
	if !criticalEvent(e) {
		return nil
	}
	m := strings.ToLower(e.Message)
	d := &Diagnosis{Engine: "Base de conhecimento local", Title: "Evento crítico exige investigação", Cause: "O evento foi classificado como crítico, mas a base local não identificou uma causa específica.", Evidence: redact(e.Message), Checks: []string{"Correlacione os eventos anteriores e posteriores no mesmo dispositivo.", "Confira o componente, horário e impacto no serviço."}, Remediation: []string{"Use a documentação do componente e os resultados das verificações antes de aplicar uma correção."}, Uncertainty: "Hipótese baseada no log; a causa raiz depende da verificação no dispositivo. Nenhuma correção é executada automaticamente."}
	if len(d.Evidence) > 1200 {
		d.Evidence = d.Evidence[:1200]
	}
	switch {
	case diagnosisOOM.MatchString(e.Message):
		d.Title = "Memória esgotada ou limite de memória atingido"
		d.Cause = "O kernel pode ter encerrado um processo por falta de memória disponível ou por um limite de memória do serviço/container. O log isolado não identifica a origem do consumo."
		d.Checks = []string{"Identifique no log OOM o processo encerrado e seu consumo.", "No Linux, consulte free -h, o journal do serviço e seus limites de memória; verifique também os limites da VM/container."}
		d.Remediation = []string{"Investigue vazamento ou aumento de carga no processo identificado.", "Após confirmar o impacto e a capacidade do host, ajuste a carga ou os limites de memória; planeje aumento de RAM quando necessário."}
		d.Reference = "https://cdn.kernel.org/doc/html/latest/admin-guide/sysctl/vm.html"
	case strings.Contains(m, "zfs") || strings.Contains(m, "zpool") || strings.Contains(m, "pool") && (strings.Contains(m, "faulted") || strings.Contains(m, "unavail")):
		d.Title = "Pool de armazenamento indisponível ou com falha"
		d.Cause = "O pool pode ter perdido dispositivos suficientes para funcionar ou encontrado erros de dados/metadados; é necessário confirmar o estado e a redundância."
		d.Checks = []string{"Consulte zpool status -v para localizar o pool e os dispositivos afetados.", "Correlacione erros de leitura, escrita e checksum com os logs do kernel e o estado dos discos/controladora."}
		d.Remediation = []string{"Priorize preservar os dados e verificar uma cópia de backup.", "Planeje o reparo ou a substituição do componente confirmado conforme a redundância e a documentação; não limpe erros ou recrie o pool sem identificar a causa."}
		d.Reference = "https://openzfs.github.io/openzfs-docs/Basic%20Concepts/Operations/Troubleshooting.html"
	case strings.Contains(m, "i/o error") || strings.Contains(m, "blk_update_request") || strings.Contains(m, "smart"):
		d.Title = "Falha de acesso ao armazenamento"
		d.Cause = "Pode haver falha de mídia, conexão, controladora ou indisponibilidade do dispositivo. Um erro de I/O não confirma sozinho que o disco deve ser substituído."
		d.Checks = []string{"Identifique o dispositivo e a operação que falhou nos logs.", "Verifique saúde SMART, conectividade, controladora e erros recorrentes; consulte também o estado do pool/RAID."}
		d.Remediation = []string{"Verifique o backup e preserve os dados antes de intervenções.", "Corrija o componente cuja falha foi confirmada; procedimentos de reparo de filesystem exigem planejamento e documentação específica."}
	case strings.Contains(m, "temperature"):
		d.Title = "Temperatura crítica detectada"
		d.Cause = "O equipamento reportou temperatura acima do limite; sensores, ventilação e carga precisam ser verificados."
		d.Checks = []string{"Confirme qual sensor/componente reportou o limite e confira sua leitura atual.", "Verifique ventiladores, fluxo de ar, ambiente e carga do equipamento."}
		d.Remediation = []string{"Corrija a refrigeração ou reduza a carga conforme as instruções do fabricante.", "Se o limite crítico persistir, planeje desligamento controlado e manutenção para proteger o hardware."}
	case strings.Contains(m, "ecc"):
		d.Title = "Erro de memória não corrigível"
		d.Cause = "Um erro ECC não corrigível pode indicar falha de memória ou do subsistema de memória; o módulo afetado precisa ser identificado."
		d.Checks = []string{"Confira os eventos de hardware e a identificação do DIMM/slot no controlador de gerenciamento.", "Verifique recorrência e os diagnósticos recomendados pelo fabricante."}
		d.Remediation = []string{"Planeje manutenção e substituição somente do componente cuja falha foi confirmada.", "Proteja as cargas e os dados antes de testes ou desligamentos."}
	case strings.Contains(m, "kernel panic"):
		d.Title = "Falha fatal do kernel"
		d.Cause = "O kernel interrompeu a operação. Hardware, driver, kernel e armazenamento são possibilidades; a mensagem e o rastreamento completo são necessários."
		d.Checks = []string{"Preserve o panic completo, o rastreamento e os logs do boot anterior.", "Correlacione com alterações de kernel/drivers, eventos de hardware e falhas de armazenamento."}
		d.Remediation = []string{"Corrija o componente confirmado e valide em manutenção.", "Se a falha começou após uma alteração, avalie retornar à versão estável conhecida depois de preservar evidências e confirmar o procedimento de recuperação."}
	case analysisFailure.MatchString(e.Message):
		d.Title = "Falhas de autenticação em evento crítico"
		d.Cause = "Pode haver credencial incorreta, problema no servidor de autenticação ou tentativa indevida. Falhas repetidas não comprovam invasão."
		d.Checks = []string{"Verifique usuário, origem e quantidade de tentativas; confirme se o acesso era esperado.", "No pfSense, consulte os logs do sistema e do servidor LDAP/RADIUS, quando utilizado."}
		d.Remediation = []string{"Corrija credenciais ou parâmetros do servidor após verificar a causa.", "Para origem não autorizada, revise a exposição e as regras de acesso seguindo a política do ambiente."}
		d.Reference = "https://docs.netgate.com/pfsense/en/latest/troubleshooting/authentication.html"
	}
	return d
}
