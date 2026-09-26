# Etapa 1: Pipeline DevSecOps e Análise de Código

**Projeto:** Ford Pós-Venda (Desafio 02, VIN Share), app mobile com API, telemetria IoT, painel analítico e modelo de leads.
**Objetivo:** mostrar como a segurança entra no ciclo de desenvolvimento, do commit ao deploy, com Semgrep (SAST) e Trufflehog (Secret Scanning) rodando de verdade sobre o código do projeto.

> **Transparência sobre o cenário de teste.** Para demonstrar o pipeline detectando e barrando falhas, o primeiro commit do repositório contém, de propósito, uma versão inicial da API com falhas típicas de antes do hardening (`api/legado/`, `app/legado/`) e um arquivo `.env` com **credenciais falsas** (chave AWS, token GitHub e senha MQTT criadas só para o teste, sem acesso a nada). Os achados sobre o código atual do app (`app/js/app.js`) são reais.

---

## 1. Visão geral do pipeline

![Diagrama do pipeline DevSecOps](pipeline-devsecops.png)

O pipeline tem três barreiras. Cada uma pega o problema num momento diferente, e juntas formam defesa em profundidade:

| Ponto de execução | Quando roda | Ferramentas | O que acontece se falhar |
|---|---|---|---|
| **pre-commit** (máquina do dev) | A cada `git commit` | Trufflehog (arquivos do commit), Semgrep (regras do projeto) | O commit não é criado |
| **GitHub Actions** | Push, pull request e toda segunda às 06h | Trufflehog (histórico completo), Semgrep (projeto + OWASP), Trivy (imagem e Dockerfile) | O job falha e o PR fica bloqueado |
| **Security gate** | Depois dos 3 jobs | `needs: [segredos, sast, container]` | O deploy não roda |
| **Dependabot** (contínuo) | Semanal | SCA das Actions e da imagem base | Abre PR de atualização |

A execução semanal existe porque um código parado também pode ficar vulnerável: as regras e a base de CVEs mudam, mesmo sem commit novo.

**Arquivos do pipeline:**
- `.pre-commit-config.yaml`: hooks locais
- `.github/workflows/devsecops.yml`: pipeline de CI/CD
- `.github/dependabot.yml`: SCA contínuo
- `.semgrep/ford-regras.yml`: 11 regras SAST do projeto
- `Dockerfile` e `nginx/default.conf`: imagem de produção endurecida

---

## 2. SAST com Semgrep

### 2.1 Por que regras próprias

As regras da comunidade (`p/owasp-top-ten`, `p/javascript`) são genéricas. Escrevemos 11 regras para os riscos específicos deste app. Por exemplo, o protótipo guarda o token só em memória, e a regra `ford.token-em-web-storage` impede que alguém volte a usar `localStorage`. No CI, as regras do projeto **bloqueiam** o pipeline; as da comunidade são **informativas** e vão para a aba Security do GitHub.

| Regra | Risco no projeto | Referência (OWASP Top 10:2025) |
|---|---|---|
| `ford.xss-innerhtml-dinamico` | Nome do cliente ou dado da API injetado como HTML | A05:2025, CWE-79 |
| `ford.execucao-dinamica-de-codigo` | `eval` executando entrada do usuário | A05:2025, CWE-95 |
| `ford.token-em-web-storage` | JWT roubável por XSS e persistido no aparelho | Mobile M9, CWE-922 |
| `ford.jwt-decode-sem-verificar` | Token forjado com `role: admin` aceito | API2:2023, CWE-347 |
| `ford.jwt-sem-algoritmo-fixo` | Ataque `alg: none` ou confusão de algoritmo | API2:2023, CWE-327 |
| `ford.segredo-fixo-no-codigo` | Chave JWT, AWS ou MQTT escrita no código | A07:2025, CWE-798 |
| `ford.hash-fraco` | Senhas em MD5/SHA-1 quebradas rapidamente | A04:2025, CWE-328 |
| `ford.aleatorio-inseguro` | Código de recuperação de senha previsível | A04:2025, CWE-338 |
| `ford.cors-curinga` | Qualquer site chamando a API em nome do usuário | A02:2025, CWE-942 |
| `ford.log-com-dado-sensivel` | Senha ou token gravado em log (LGPD) | A09:2025, CWE-532 |
| `ford.exposicao-de-ambiente` | Endpoint de debug devolvendo `process.env` | A02:2025, CWE-200 |

### 2.2 Primeira varredura: 16 achados, pipeline bloqueado

![Semgrep antes](evidencias/01-semgrep-antes.png)

O Semgrep terminou com `exit code 1`, o que faz o job falhar no GitHub Actions. Dez das onze regras dispararam:

| Regra | Achados | Onde |
|---|---|---|
| `segredo-fixo-no-codigo` | 6 | 1 na API legada (`JWT_SECRET`), 5 em `app.js` |
| `xss-innerhtml-dinamico` | 2 | 1 em `app.js` (tela de login), 1 no legado |
| `aleatorio-inseguro`, `cors-curinga`, `execucao-dinamica-de-codigo`, `exposicao-de-ambiente`, `hash-fraco`, `jwt-decode-sem-verificar`, `log-com-dado-sensivel`, `token-em-web-storage` | 1 cada | Código legado |

### 2.3 Triagem dos achados

Um SAST não é só rodar a ferramenta: cada achado precisa ser classificado.

| Classificação | Qtd. | Tratamento |
|---|---|---|
| **Verdadeiro positivo** | 11 | Corrigido (10 no legado + o `innerHTML` da tela de login) |
| **Risco aceito** | 3 | Senhas das contas de demonstração, que o protótipo mostra na própria tela de login. Marcadas com `// nosemgrep` e justificativa no código. Em produção, esse bloco não existe |
| **Falso positivo** | 2 | `senha: 'erroSenha'` é o id de um elemento da tela; `senha: 'SenhaErrada1'` é a senha errada usada de propósito pela simulação de ataque. Marcados com justificativa |

Antes da primeira varredura oficial, a regra de segredo fixo também foi **refinada**. Na primeira versão, ela marcava textos de interface como `'Informe sua senha.'`. Passamos a exigir valor sem espaços, o que eliminou esse tipo de falso positivo sem perder os segredos reais.

**Correção real no app.** A tela de login montava o HTML com `${CONFIG.EMAIL_MAX}` dentro de `innerHTML`. O valor era uma constante, mas o padrão é perigoso e seria copiado para outros lugares. O HTML passou a ser fixo, e o limite é aplicado pelo DOM (`input.maxLength = CONFIG.EMAIL_MAX`).

**Correções do código legado** (commit `security: corrige os 16 achados do Semgrep`):

| Achado | Como ficou no app |
|---|---|
| MD5 na senha | PBKDF2-SHA256 com salt por usuário (100 mil iterações nesta etapa; elevado para 600 mil na Etapa 4) |
| `jwt.decode` sem verificar | `analisarToken()` confere assinatura, algoritmo, validade e versão |
| `JWT_SECRET` no código | Chave HMAC gerada em tempo de execução, não exportável |
| Token em `localStorage` | Token só em memória |
| `innerHTML` com nome do usuário | Função `el()` com `textContent` |
| `eval` em filtro | Filtros por lista fechada de valores |
| `Math.random()` em código de recuperação | `crypto.randomUUID()` e `crypto.getRandomValues()` |
| CORS `*` | Sem CORS aberto: app e API na mesma origem (CSP `connect-src 'self'`) |
| Log com `req.body` | Log estruturado sem senha nem token, com e-mail mascarado |
| Endpoint `/debug` com `process.env` | Removido |

### 2.4 Depois das correções: 0 achados, pipeline liberado

![Semgrep depois](evidencias/04-semgrep-depois.png)

### 2.5 Limitação encontrada

O Semgrep **não analisa JavaScript escrito dentro de arquivos HTML**. Nos testes, uma falha dentro de `<script>` passou sem alerta. Por isso, o repositório separa o app em `index.html`, `css/styles.css` e `js/app.js`. Isso também permitiu uma CSP com `script-src 'self'`, sem scripts inline.

---

## 3. Secret Scanning com Trufflehog

### 3.1 Segredos no histórico

![Trufflehog antes](evidencias/02-trufflehog-antes.png)

O Trufflehog analisou todos os commits e encontrou duas credenciais no arquivo `.env` do commit inicial: uma chave AWS e um token pessoal do GitHub. O relatório traz commit, arquivo, linha e autor, e, no caso do GitHub, o link do guia de rotação. O `exit code 183` faz o job falhar no CI.

### 3.2 Apagar o arquivo não resolve

![Trufflehog histórico](evidencias/03-trufflehog-historico.png)

Depois de `git rm --cached .env` e da criação do `.gitignore`, o Trufflehog **continuou encontrando as duas credenciais**. Elas seguem no histórico, e qualquer pessoa com acesso ao repositório consegue recuperá-las. Por isso o job de CI usa `fetch-depth: 0` (histórico completo), e não só o último commit.

### 3.3 Remediação

1. **Revogar e rotacionar** as credenciais imediatamente. Este é o passo que realmente resolve: uma chave vazada deve ser considerada comprometida.
2. **Remover do histórico** com `git filter-repo --invert-paths --path .env`. Isso reescreve todos os commits, então exige combinar com a equipe e fazer `git push --force`.
3. **Impedir que volte:** `.gitignore` para `.env`, um `.env.example` sem valores, segredos de CI no GitHub Secrets, o hook de pre-commit e o `.dockerignore`, que impede o `.env` de entrar na imagem.

![Trufflehog depois](evidencias/06-trufflehog-depois.png)

Depois da limpeza: 0 segredos e `exit code 0`.

### 3.4 Limitação encontrada

O `.env` do teste também tinha uma senha MQTT dentro da URL do broker (`mqtts://usuario:senha@broker`), que é o canal da telemetria IoT. **O Trufflehog não detectou.** Nenhuma ferramenta cobre todos os formatos. Por isso o projeto combina camadas: a regra Semgrep `ford.segredo-fixo-no-codigo`, o `.gitignore`, a revisão de PR e o *push protection* do GitHub.

---

## 4. pre-commit: a barreira antes do commit

![pre-commit bloqueando](evidencias/05-precommit-bloqueio.png)

Simulamos um desenvolvedor tentando commitar um arquivo de configuração da telemetria com a chave AWS escrita no código e um `innerHTML` inseguro. Os dois hooks falharam e **o commit não foi criado**. O Trufflehog pegou a chave AWS, e o Semgrep pegou as duas credenciais e o `innerHTML`. Uma ferramenta confirma a outra.

O pre-commit pode ser ignorado com `git commit --no-verify`. É por isso que o CI repete as mesmas verificações: o pre-commit dá retorno rápido ao desenvolvedor, e o CI é a garantia.

---

## 5. SCA: Software Composition Analysis (pesquisa)

**O que é.** A análise das dependências de terceiros (bibliotecas, imagens, actions) contra bases públicas de vulnerabilidades conhecidas (CVEs). Corresponde ao risco **A03:2025, Software Supply Chain Failures** (no Top 10 de 2021, era o A06, Vulnerable and Outdated Components).

**Ferramentas.**
- **Dependabot:** nativo do GitHub e gratuito. Abre PR de atualização.
- **Snyk:** análise mais profunda e sugestão de correção.
- **`npm audit`:** direto no ecossistema Node.
- **OWASP Dependency-Check:** para projetos Java e .NET.

**Onde entra no fluxo.** De forma contínua, fora do caminho do commit: a vulnerabilidade pode ser descoberta numa dependência que ninguém alterou. Também entra no PR, quando alguém adiciona ou atualiza uma dependência.

**O que já está configurado.** O protótipo não usa bibliotecas npm, mas o projeto tem duas dependências reais:
- as **GitHub Actions** do pipeline;
- a **imagem base** do container.

O `.github/dependabot.yml` acompanha as duas semanalmente. Quando a API virar um serviço Node.js, basta ativar o bloco `npm`, que já está comentado no arquivo.

**Cadeia de suprimentos.** As actions do workflow estão fixadas pelo **hash do commit** (`actions/checkout@3d3c42e…  # v7.0.1`), e não pela tag. Uma tag pode ser movida pelo dono do repositório, ou por um invasor, para código malicioso, que rodaria no nosso pipeline com acesso ao código e aos segredos. O hash não muda. O Dependabot continua atualizando esses hashes.

---

## 6. Container Security (pesquisa e configuração)

**O que é.** A análise da imagem Docker, das vulnerabilidades dos pacotes do sistema e da configuração do `Dockerfile`, antes de ela ir para produção.

**Ferramentas.**
- **Trivy:** open source, analisa imagem, Dockerfile e IaC.
- **Grype.**
- **Docker Scout.**
- **Hadolint:** boas práticas de Dockerfile.

**Onde entra no fluxo.** Depois do `docker build` e antes do push da imagem ou do deploy. No nosso workflow, é o job `container`, e o deploy depende dele.

**O que já está configurado.** O job roda o Trivy duas vezes:
- na **imagem**, falhando em CVE CRITICAL ou HIGH que já tenha correção disponível;
- na **configuração** do Dockerfile.

O Trivy não foi executado no nosso ambiente de testes, porque ele precisa baixar a base de vulnerabilidades. Ele roda no GitHub Actions do repositório.

**Imagem endurecida (`Dockerfile`):**

| Prática | Risco reduzido |
|---|---|
| Base `nginx-unprivileged` e `USER 101` (sem root) | Invasor que explore o nginx não vira root do container |
| Imagem Alpine mínima | Menos pacotes, menos CVEs |
| `.dockerignore` excluindo `.env`, `.git`, `.semgrep` e `api` | Segredo e histórico fora da imagem |
| `HEALTHCHECK` | Container com falha é detectado e reiniciado |
| `server_tokens off` e bloqueio de `/.` no nginx | Não revela versão nem expõe `.env` e `.git` |
| CSP, HSTS, `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `Permissions-Policy` | XSS, clickjacking, downgrade para HTTP, vazamento de URL |

---

## 7. Como cada etapa reduz os riscos do projeto

| Risco do projeto | Barreira | Como reduz |
|---|---|---|
| Credencial da AWS (telemetria) ou do broker MQTT vazada no Git | pre-commit + Trufflehog no CI + `.gitignore` | Barra no commit; se passar, acha no histórico e bloqueia o deploy |
| XSS no app (nome do cliente, observações do agendamento) | Semgrep `xss-innerhtml-dinamico` + CSP | Barra o padrão no código; a CSP bloqueia script injetado se algo escapar |
| Token forjado para virar admin | Semgrep `jwt-*` | Impede `decode` sem verificação e `verify` sem algoritmo fixo |
| Senhas quebradas em caso de vazamento do banco | Semgrep `hash-fraco` | Proíbe MD5 e SHA-1 |
| Dados pessoais em log (LGPD) | Semgrep `log-com-dado-sensivel` | Impede log de senha, token e corpo da requisição |
| Biblioteca ou action com CVE | Dependabot + actions fixadas por hash | Atualização contínua e proteção contra tag adulterada |
| Imagem com pacote vulnerável ou rodando como root | Trivy + Dockerfile endurecido | Bloqueia CVE crítica; reduz o impacto de uma invasão |
| Código com falha chegando à produção | Security gate | Deploy só com os 3 jobs aprovados |

---

## 8. Como reproduzir

```bash
# Semgrep (regras do projeto)
semgrep scan --config .semgrep/ --error --metrics=off

# Trufflehog (histórico completo)
trufflehog git file://. --no-verification --fail

# Hooks locais
pip install pre-commit && pre-commit install
```

Versões usadas: Semgrep 1.178.0 e Trufflehog 3.97.9.
