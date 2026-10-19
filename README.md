# Sentinela

Aplicação web para triagem inicial de segurança de projetos enviados em ZIP ou hospedados em repositórios públicos do GitHub.

## Iniciar automaticamente no Windows

Para iniciar o servidor em segundo plano a cada entrada na sua conta do Windows, abra o PowerShell nesta pasta e execute:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\auto-start.ps1
```

A configuração vale para o usuário atual e começa no próximo login do Windows. Depois, abra `http://localhost:3000` no navegador. O script não abre o navegador automaticamente.

Para remover a inicialização automática, execute no PowerShell:

```powershell
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'SentinelaAppSec'
```

## Execução manual para desenvolvimento

Requer Node.js 20 ou superior.

```powershell
npm.cmd install
npm.cmd start
```

O comando inicia a aplicação em `http://localhost:3000`, vinculada por padrão apenas a `127.0.0.1`. O arquivo `.env` local é carregado pelo backend; mantenha as credenciais fora do navegador e nunca versione esse arquivo. Projetos enviados têm arquivos `.env` e `.env.*` excluídos antes da análise e do envio à IA.

Para uma implantação atrás de proxy/rede, configure `HOST` explicitamente (por exemplo, `HOST=0.0.0.0`) e coloque o serviço atrás de autenticação, TLS e regras de firewall. A aplicação emitirá um aviso ao iniciar com interface de rede; CORS não protege a API contra chamadas diretas.

## Desenvolvimento com Live Server

1. Inicie o backend em um terminal com `npm.cmd start` e mantenha-o em execução.
2. No VS Code, use **Go Live** do Live Server para servir `index.html` (porta padrão `5500`).
3. No Edge, abra o endereço informado pelo Live Server, normalmente `http://127.0.0.1:5500`.

O frontend detecta o Live Server em `localhost`/`127.0.0.1` e encaminha as chamadas à API na porta `3000`. A API permite CORS apenas para origens locais de desenvolvimento ou origens HTTPS exatas configuradas em `APP_ORIGINS` (separadas por vírgula); CORS é uma política de navegador e não substitui autenticação.

## Integrações

- OpenAI (obrigatória para analisar projetos): configure `OPENAI_API_KEY`. Todo projeto submetido é enviado à API OpenAI para análise contextual, após mascaramento de padrões conhecidos de credenciais. Sem essa variável, os endpoints de análise ficam indisponíveis e a interface bloqueia o envio. `OPENAI_MODEL` pode selecionar outro modelo compatível com a API Responses e saída JSON estruturada. Envie somente código que você tem autorização para compartilhar.
- E-mail: configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `MAIL_FROM` e `SECURITY_EMAIL`. O relatório só é enviado ao endereço fixo em `SECURITY_EMAIL` quando a pessoa aciona o botão. O transporte SMTP precisa aceitar conexão de saída do servidor.
- Auditoria de dependências: lockfiles reconhecidos são consultados na API pública OSV. Esta consulta depende de conectividade de saída para `api.osv.dev`.

Sem SMTP, o relatório continua disponível para download em DOCX, mas não pode ser enviado por e-mail. O download JSON não é oferecido pela interface.

## Escopo e limitações

A aplicação faz triagem estática baseada em padrões, consulta vulnerabilidades de versões fixas encontradas em alguns lockfiles, identifica indícios de hospedagem e tecnologias/configurações de banco nos arquivos enviados e exige análise contextual por IA. O código analisável é enviado à OpenAI após exclusão de arquivos `.env`/`.env.*` e mascaramento de padrões conhecidos de credenciais; mascaramento não detecta toda credencial possível. Não instala nem executa o projeto, não consulta a infraestrutura implantada, não valida conectividade/disponibilidade do banco e não testa endpoints em execução. O achado de CSRF é apenas candidato heurístico: requer endpoint mutável e indícios de sessão/cookie no mesmo arquivo, e precisa ser confirmado manualmente. O prompt de correção recomenda validação e diff revisável; não altera arquivos automaticamente. As conclusões sobre hospedagem e banco são inferências dos arquivos analisados, não confirmação do ambiente de produção. A ferramenta não substitui SAST dedicado, análise de composição de software, pentest ou revisão profissional. Regras podem gerar falsos positivos ou não reconhecer falhas; o resultado não certifica segurança, conformidade com a LGPD ou certificação ISO.

Limites atuais: ZIP de 20 MB, conteúdo descompactado de 50 MB, 1.200 entradas, 300 arquivos de texto e 500 KB por arquivo. A consulta OSV cobre npm, PyPI, Packagist e crates.io nos formatos de lockfile reconhecidos pelo analisador.

Os relatórios ficam apenas na memória do processo para permitir o envio ao destinatário configurado e desaparecem quando o servidor reinicia. Há limitação básica de 30 solicitações de API por IP a cada 15 minutos.

## Exposição em rede

O servidor não implementa autenticação, autorização por usuário, gestão de consentimento organizacional nem armazenamento durável. Ele escuta apenas em loopback por padrão. Não defina `HOST` para uma interface de rede nem o exponha à internet ou a uma rede compartilhada sem colocar uma camada de autenticação, TLS, controles de acesso, política de retenção, limites operacionais e revisão de segurança. Analise apenas código que você tenha autorização para enviar.