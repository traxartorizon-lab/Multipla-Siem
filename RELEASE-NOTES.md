# Multipla Siem 1.2.33

## 1.2.33

Correções da avaliação de segurança: binários e CI usam Go 1.27.2 com SHA256 oficial fixado, substituindo Go 1.27.1 afetado por nove avisos alcançáveis da biblioteca padrão identificados pelo govulncheck. CI passa a bloquear publicação quando a análise oficial encontra vulnerabilidades alcançáveis.

Endpoint de métricas exige exatamente um cabeçalho Authorization no formato Bearer. Não aceita a chave bruta sem esquema. A chave continua restrita ao dispositivo, com TLS, limites e revogação. Abertura de terminal SSH exige auditoria persistida antes de iniciar; encerramento solicitado pelo operador também gera auditoria, sem registrar senha, chave privada ou comandos.

Regressões incluem acesso sem sessão, privilégio de visualização, CSRF, sessão SSH de outra conta, confusão de credencial de coletor, 19 tentativas por HTTPS real local e falha de persistência da auditoria SSH. Nenhum pentest foi executado contra produção. A revisão não certifica ausência de falhas nem resolve isolamento multiempresa, MFA local, imutabilidade de evidências ou disponibilidade por cota: esses riscos estão documentados no relatório.

