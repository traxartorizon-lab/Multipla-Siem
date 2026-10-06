# Multipla Siem 1.2.18

Dashboard compacta e responsiva, mantendo a identidade visual escura e turquesa. Medidores atuais de CPU, memória e discos por máquina com coletor; gráfico de atividade de logs com áreas sobrepostas semitransparentes, períodos de 30 minutos, 1h, 6h, 24h e 7 dias, média ou máximo de logs por minuto. Usa o histórico já retido e sinaliza consultas parciais e dias sem arquivo. Menu recolhível em telas móveis, formulários em uma coluna e controles adaptados para toque.

Cards de dispositivos compactos com Ver mais/menos, expansão preservada durante atualizações e ping manual restrito a dispositivos cadastrados, com autenticação administrativa, CSRF e auditoria. Filtros de eventos por data/hora, palavra ou IP, com paginação e intervalo máximo de 31 dias sujeito à retenção.

Coletor Windows com instalação interativa, solicitação UAC, prompts de configuração sem expor a chave na linha de comando, primeira coleta automática e mensagens de erro mantidas abertas. Mantém envio HTTPS, validação TLS, tarefa LocalService, proteção da chave e nenhuma alteração de antivírus ou política global. Validação de sintaxe e testes locais; compatibilidade com políticas específicas do Bitdefender requer piloto.

Alerta sonoro opcional para novos críticos enquanto o painel está aberto: bipe ou sirene, volume, teste e parada; desativado por padrão, sem tocar histórico ao entrar. Deduplicação e intervalo mínimo de 10 segundos, duração máxima de 4 segundos, sujeitos à política de áudio do navegador. Áudios locais com licenças e fontes em ALERT-SOUNDS-LICENSES.json. Favicon SVG/ICO com M turquesa em fundo verde escuro.

Validação: suíte Go, go vet, testes de áudio e histórico/agregação, prévia de navegador com dados de demonstração e larguras de 320/390/768/1440 pixels. Builds Linux amd64 e arm64; manifestos e binários do servidor/atualizador verificados com Ed25519.
