# Multipla Siem 1.2.29

## 1.2.29

Alertas sonoros por descrição: escolha entre bipe, sirene e o som padrão do navegador ao configurar um evento crítico. Gerenciar alertas sonoros na guia Eventos permite ouvir, trocar o som, ativar ou desativar somente o áudio e excluir a classificação crítica daquela descrição, preservando o histórico original. Alertas silenciados permanecem disponíveis para reativação. Configurações são persistidas no servidor e compatíveis com backups anteriores.

Saída de áudio selecionável nas configurações do navegador/computador: escolha uma saída disponibilizada pelo navegador ou pelo seletor nativo, quando suportado. Não solicita acesso ao microfone. Se a saída escolhida estiver indisponível, informa o problema sem tocar silenciosamente na saída padrão. Navegadores sem suporte exibem orientação para usar o mixer de volume do sistema. A preferência de saída permanece local ao navegador.

Validação: testes de persistência, silenciamento, exclusão sem apagar evidência, permissões de leitura/escrita, tipo de som inválido, seleção de saída, dispositivo indisponível, sintaxe JavaScript, testes gerais e revisão visual. Compatibilidade com hardware e permissões reais deve ser validada no computador do usuário.

