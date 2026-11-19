# FiscalIA PFG — Segurança: correções e pendências

## Corrigido nesta versão (verificado por leitura do código e testes HTTP)

1. **Segregação de contratos:** tabela `usuario_contratos`, atribuição por ADMIN, filtragem de consultas e relatórios, bloqueio de acesso por ID de objeto.
2. **Autenticação:** nova senha inicial aleatória por padrão, controle de tentativas e registro de falhas. `admin/admin` somente por opção explícita de demonstração.
3. **Anexos:** validação de nome interno, proteção contra travessia de diretórios e symlinks, arquivos restritos no Linux, SHA-256 comparado no download e na análise documental.
4. **Autoria da conferência:** identidade obtida da sessão, independentemente do campo de formulário.
5. **Administração:** somente ADMIN pode criar contratos, atribuir acessos e visualizar auditoria completa.

## Ainda não resolvido — não usar em produção

- Criptografia transparente de arquivos e banco não implementada; permissões NTFS/BitLocker/LUKS dependem do ambiente.
- CSP do front-end ainda permite scripts inline. Uma correção rigorosa exige remover JavaScript e eventos inline, preservar funcionamento e testar no navegador.
- Sem isolamento antimalware/sandbox para PDFs e documentos Office.
- Assinatura HMAC interna não equivale a assinatura oficial; chave e banco permanecem no mesmo armazenamento.
- Logs locais podem ser alterados por administrador do dispositivo; necessitam centralização e imutabilidade para trilha institucional.
- Sem deploy multiusuário por HTTPS, SSO, rotatividade de segredos, política de retenção ou backup criptografado automatizado.
- Sem avaliação LGPD, plano de resposta a incidentes, testes de intrusão e homologação das regras financeiras com contrato real.
- Integração de IA externa sem quotas e governança completa de tokens/custos.

**Escopo da auditoria:** mudanças implementadas sobre o arquivo Python fornecido; testes de regressão e revisão estática, não certificação de segurança.
