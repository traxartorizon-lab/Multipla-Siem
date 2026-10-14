# Multipla SIEM 1.2.35

## 1.2.35

MFA TOTP obrigatório nos acessos Google/locais, proteção de operações de maior impacto, verificação da criptografia antes de atualizar e recuperação pelo console root com revogação de vínculos. Escopo de cliente gravado na coleta e aplicado no servidor a consultas, relatórios, exportações, IA, métricas e notificações; contas novas sem acesso global implícito. Grupos com permissões adicionais separadas para contas, backup e terminal.

Cotas por origem, orçamento reservado a críticos, spool durável limitado, avisos de capacidade no journald e fila durável de email com tentativas/falhas. Dispositivos com problema agrupa repetições e permite ocultação temporária/permanente, mantendo detecção e notificações.

Camada root de isolamento exclusivo de ataques diretos em Tailscale ao SIEM, persistência da regra, liberação limitada e sirene contínua até leitura. Exige habilitação pelo administrador do host; logs encaminhados não acionam essa camada. Terminal SSH deixa de aceitar senhas/chaves pessoais e passa a certificados curtos para conta dedicada. Exige provisionamento do trust nos destinos. Syslog TLS autenticado disponível para migração planejada.

App Windows: origem correta na confirmação Google, cancelamento de login, atualização da janela de notificações, marcar todas como lidas, saída nativa do Windows sem microfone e ícone Multipla SIEM no executável, janela, barra de tarefas e bandeja. Atualize app e servidor; cadastre o autenticador e gere nova chave de vínculo após a migração MFA.

Coletores e bootstrap com manifestos Ed25519; pacote Windows com manifesto de arquivos verificável, SBOM e proveniência. Publicação somente após validação Linux e Windows. ISO deve ser autenticada antes do boot. Nenhuma chave privada de release é enviada ao CI. Não há certificado Authenticode de editora provisionado.

Backup completo inclui configurações de firewall/SSH/polkit/unidades próprias. Restore padrão preserva identidade Tailscale do destino e mantém aplicação parada para conferência; -replace-server exige original desligado. Ensaio aprovado em duas VMs Debian sintéticas sem rede, além de testes de autorização, TOTP/replay, PKCE/consentimento, isolamento por cliente, spool e certificados SSH. Essas evidências não substituem validação da sua implantação.

Leia SECURITY-RUNBOOK.md. Armazenamento externo imutável segue pendente por decisão do usuário. Proteção de branch/2FA do GitHub e provisionamento de certificados/contas nos hosts exigem administração externa e não são declarados ativados por esta release. O ambiente permanece de uma única instância; filas duráveis não constituem alta disponibilidade.

