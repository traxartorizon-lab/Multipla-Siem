# Multipla Siem 1.2.12

Corrige o bloqueio de cores ANSI pelo CSP: estilos dinâmicos do xterm recebem nonce aleatório por página. A política de scripts permanece restrita, sem unsafe-inline. Não modifica a saída SSH ou configurações do equipamento.

Validação: cores ANSI no navegador com CSP ativo, sem erros de estilo; nonce único por resposta HTML; testes Go e vet.
