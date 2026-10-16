# Publicador Windows e SmartScreen

Estado: preparação do fluxo. O proprietário informou que ainda não possui certificado de assinatura de código nem serviço de assinatura. Portanto, a aplicação não ganhou uma identidade Authenticode confiável nesta revisão. A assinatura Ed25519 dos pacotes verifica a distribuição do SIEM, mas não fornece identidade de publicador ao Windows.

Não desativar SmartScreen/Defender, importar uma raiz autoassinada ou remover a marca de download para simular confiança. Mesmo com certificado válido, a Microsoft pode continuar mostrando um aviso até formar reputação suficiente; não existe garantia de ausência de alertas.

## Fluxo a ativar depois da contratação e validação da identidade

1. Compilar em ambiente limpo a revisão aprovada; comparar byte a byte com o manifesto do payload **antes de assinar**, usando toolchains e dependências travados. Guardar esse manifesto como evidência da compilação.
2. Enviar somente os componentes próprios `Multipla.Siem.exe` e `Multipla.Siem.dll` ao signatário segregado. A identidade, cadeia e perfil devem ser previamente aprovados. Usar chave não exportável/HSM ou serviço com identidade federada, mínimo privilégio e aprovação de release. Não guardar PFX/senha no repositório ou logs.
3. Assinar com SHA-256 e timestamp RFC3161 SHA-256 de serviço confiável. Com SignTool, os argumentos relevantes são `/fd SHA256 /tr ENDERECO_TSA_APROVADO /td SHA256`; a seleção da identidade depende do certificado/serviço efetivamente escolhido. Nenhuma assinatura é disparada por este documento.
4. Verificar a cadeia e timestamp com `signtool verify /pa /all /v /tw`. Executar `scripts/verify-authenticode.ps1` para cada arquivo próprio, informando caminho, Subject exato aprovado, SHA-256 do certificado e caminho do SignTool. O verificador recusa arquivo sem assinatura, publicador/certificado diferente e ausência de timestamp. Uma rotação de certificado exige revisão explícita da identidade aceita.
5. Preservar componentes Microsoft/NAudio/WebView2 e suas assinaturas existentes. Validar os hashes aprovados do payload e as identidades esperadas dos componentes já assinados; bibliotecas gerenciadas originalmente sem Authenticode continuam vinculadas aos hashes/lock de dependências. Não reassinar arquivos de terceiros como se fossem próprios.
6. Somente **depois** da validação Authenticode, gerar os hashes finais, manifesto Ed25519, SBOM/proveniência e ZIP de distribuição. Vincular a evidência do payload original à revisão e aos hashes dos binários finais assinados. O timestamp altera os bytes: os hashes finais não podem ser comparados ao manifesto anterior como se fossem a mesma representação.
7. A publicação deve validar ambos os estágios: payload compilado original e cadeia/publicador/timestamp + hashes finais assinados. Nunca remover a comparação atual para simplesmente aceitar qualquer EXE assinado. A pipeline atual permanece verificando o payload reproduzível sem Authenticode; ainda não foi alterada para um serviço que não existe.

## Validações e bloqueios

O verificador pode ser analisado e exercitado em casos negativos sem certificado. Os casos positivos de cadeia pública, timestamp, revogação e integridade após assinatura precisam ser executados quando a identidade real estiver disponível. Nenhum teste local substitui reputação SmartScreen em máquinas de usuários.

Fontes oficiais consultadas em 14/10/2026:

- [Microsoft: reputação SmartScreen](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation).
- [Microsoft: Artifact Signing e proteção da chave](https://learn.microsoft.com/en-us/azure/artifact-signing/overview).
- [Microsoft: SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool).
