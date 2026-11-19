# FiscalIA PFG

**Sistema de apoio à fiscalização de contratos com dedicação exclusiva de mão de obra — Pagamento pelo Fato Gerador (PFG).**

> **Protótipo local, versão 0.7.2.** Destinado a estudo e testes com **dados fictícios**. Não é homologado para uso institucional ou com dados pessoais reais. **Não publique o servidor na internet.**

![Prévia da interface](interface-permissoes.png)

## Objetivo

Apoiar fiscais técnicos, fiscais administrativos e gestores no acompanhamento de contratos, trabalhadores, postos, fatos geradores, conferência documental e elaboração de pareceres. O software **não aprova pagamentos automaticamente** e não substitui a análise do fiscal.

## Funcionalidades

- Cadastro de contratos, trabalhadores, postos e períodos de referência.
- Fatos geradores, memórias de cálculo parametrizadas, controle de avos e limites.
- Importação de planilhas Excel/CSV e conferência de folhas/documentos.
- Login com perfis **ADMIN**, **TECNICO**, **ADMINISTRATIVO** e **GESTOR**.
- **Permissões por contrato** atribuídas pelo administrador e verificadas no servidor.
- Pareceres com fluxo de elaboração, revisão e assinatura **interna** com verificação de integridade.
- IA configurável (Ollama local; integração com provedores externos) para **análises assistidas**, nunca para ateste automático.
- Auditoria de operações, proteção CSRF e verificações de integridade de anexos.

## Requisitos

- Python **3.11+**.
- Navegador moderno.
- A biblioteca padrão do Python é suficiente para as funções principais. Para extração de texto em PDFs, instale opcionalmente `pymupdf`.
- Para IA local, instale e inicie o **Ollama** separadamente.

## Executar no Windows / PyCharm

1. Abra esta pasta no PyCharm.
2. Execute `FiscalIA_PFG_Moderno_Seguro.py` (ou use `INICIAR_WINDOWS.bat`).
3. Acesse **http://127.0.0.1:8765**.
4. No primeiro uso, o terminal mostra o login **admin** e uma **senha temporária aleatória**; troque-a antes de usar.

Se a porta estiver ocupada, encerre a versão antiga ou altere a variável `FISCALIA_PORT`. Não execute duas versões usando o mesmo banco.

## Executar no Ubuntu

```bash
python3 FiscalIA_PFG_Moderno_Seguro.py
```

## Testes

```bash
python -m unittest -v test_seguranca.py
```

Os testes automatizados utilizam dados fictícios e diretórios temporários. Eles **não** representam auditoria de segurança ou homologação independente.

## Segurança, dados e privacidade

**Nunca publique:** `dados_fiscalia/`, bancos SQLite, anexos de contratos, documentos de trabalhadores, chaves de assinatura, tokens, `.env` ou backups. O `.gitignore` contém regras para esses arquivos, mas **confira manualmente os arquivos e o histórico antes de cada commit**. Se um segredo for publicado, revogue e substitua-o.

O aplicativo limita o servidor a `127.0.0.1`. **Não use em ambiente de produção:** permanecem pendentes criptografia de aplicação, isolamento de anexos potencialmente maliciosos, auditoria imutável, implantação com HTTPS/SSO, testes de invasão e homologação institucional. Consulte [SEGURANCA_PENDENCIAS.md](SEGURANCA_PENDENCIAS.md).

**IA:** a conexão local pode analisar texto extraído de documentos. Integrações externas utilizam informações estruturadas reduzidas, mas qualquer uso com dados contratuais exige avaliação de privacidade e autorização institucional.

## Documentação

Consulte o [manual de instalação e migração](LEIA-ME.md). A assinatura de pareceres é **interna** e **não equivale** a assinatura qualificada ICP-Brasil ou a assinatura oficial do processo administrativo.

## Licença

O FiscalIA PFG é um projeto de software livre distribuído sob os termos da GNU General Public License, versão 3.0 (GPL-3.0).

É permitido utilizar, estudar, modificar, compartilhar e distribuir o software, inclusive para fins comerciais, desde que sejam respeitadas as condições estabelecidas pela licença GPL v3.

As versões modificadas distribuídas também deverão observar as condições da GPL v3, incluindo a disponibilização do código-fonte correspondente.

Consulte o arquivo LICENSE para conhecer os termos completos.

Licença: GPL-3.0-only.
