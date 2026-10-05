# Análise contínua e IA local

A análise local sempre roda no SIEM: padrões, estatística adaptativa e base de conhecimento produzem diagnóstico de eventos críticos. Ela não pode ser desligada pelo cadastro de configuração ou por importação. Diagnósticos são hipóteses verificáveis e não executam comandos. Logs sem causa conhecida recebem orientação de investigação, sem afirmar uma correção desconhecida.

A geração de texto por modelo usa Ollama somente em http://127.0.0.1:11434. O SIEM não instala Ollama nem baixa pesos automaticamente. Após atualizar para 1.2.5, confira no Debian:

```sh
command -v ollama
free -h
curl --max-time 3 http://127.0.0.1:11434/api/tags
```

Se Ollama não estiver instalado, siga https://docs.ollama.com/linux. A instalação padrão oficial permite:

```sh
curl -fsSL https://ollama.com/install.sh -o /root/multipla-ollama-install.sh
sh /root/multipla-ollama-install.sh
install -d -m 0755 /etc/systemd/system/ollama.service.d
cat > /etc/systemd/system/ollama.service.d/multipla-local.conf <<'EOF'
[Service]
Environment="OLLAMA_HOST=127.0.0.1:11434"
Environment="OLLAMA_NO_CLOUD=1"
Environment="OLLAMA_NUM_PARALLEL=1"
Environment="OLLAMA_MAX_LOADED_MODELS=1"
EOF
systemctl daemon-reload
systemctl enable --now ollama
systemctl restart ollama
ollama pull qwen3:0.6b
```

O modelo padrão qwen3:0.6b tem download de aproximadamente 523 MB (https://ollama.com/library/qwen3:0.6b); o consumo em execução é maior e depende do contexto. Confira RAM livre e disco antes de instalar. Modelos pequenos podem errar diagnósticos; um modelo local maior pode ser selecionado em Configurações > Diagnósticos e IA local se a capacidade do servidor permitir. Não abra a porta 11434 para a rede. A conexão local não exige alterar Google SSO ou Drive.

O SIEM verifica disponibilidade a cada 30 segundos e tenta diagnosticar os críticos recentes ainda sem resposta. Uma inferência por vez, no máximo 64 trabalhos enfileirados, prazo de 90 segundos e saída limitada. Modelo indisponível, resposta incompleta ou saturação são informados no painel. Todo crítico mantém o diagnóstico imediato da base local; não há garantia de inferência generativa para todo evento sob volume ilimitado ou indisponibilidade. Somente os eventos retidos na janela podem ser recuperados automaticamente pela fila. Resultados gerados e avaliações são preservados no estado do SIEM, com limites de 2.000 registros de cada tipo.

O modelo recebe logs com a redação de segredos aplicada pelo SIEM. O log é dado não confiável, não uma instrução; o modelo não recebe ferramentas. A saída é texto para revisão, não é executada e não determina bloqueios. Respostas inválidas são descartadas. Modelos cloud e entradas remotas anunciadas pelo Ollama são recusados; o modo OLLAMA_NO_CLOUD=1 protege também o serviço Ollama.

O backup completo recupera a seleção de modelo, os diagnósticos e as avaliações. Ollama e seus pesos são dependências externas e não estão incluídos no backup do SIEM; reinstale-os no servidor de recuperação. A base local funciona mesmo sem essa reinstalação. O SIEM não preserva um histórico ilimitado de inferências ou acompanhamentos.

Referências da base: https://cdn.kernel.org/doc/html/latest/admin-guide/sysctl/vm.html, https://openzfs.github.io/openzfs-docs/Basic%20Concepts/Operations/Troubleshooting.html e https://docs.netgate.com/pfsense/en/latest/troubleshooting/authentication.html. Referência da API: https://docs.ollama.com/api/chat e https://docs.ollama.com/faq.
