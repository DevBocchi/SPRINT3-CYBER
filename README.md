# Ford Pós-Venda: protótipo mobile (Challenge Ford, Desafio 02)

App do cliente, painel do Analista Ford e gestão do Administrador, construído com foco em segurança para a Sprint 3 de Cybersecurity.

## Estrutura

```
app/                    app estático (HTML, CSS e JS separados; CSP sem script inline)
.semgrep/               11 regras SAST do projeto
.github/workflows/      pipeline DevSecOps (Trufflehog, Semgrep, Trivy, deploy)
.github/dependabot.yml  SCA contínuo
.pre-commit-config.yaml hooks locais (Trufflehog e Semgrep)
Dockerfile, nginx/      imagem de produção sem root e com cabeçalhos de segurança
monitoramento/          catálogo das 12 regras de alerta (com KQL para o Kibana) e métricas por domínio
docs/                   documentação das etapas, diagramas e evidências
```

O app inclui um **Centro de Segurança** (painel à direita): simulações de ataque, logs em JSON, alertas em tempo real, painel de métricas e console de resposta a incidentes (SANS PICERL).

## Rodar localmente

```bash
cd app && python3 -m http.server 8080          # ou:
docker build -t ford-posvenda . && docker run -p 8080:8080 ford-posvenda
```

Contas de teste: `cliente@demo.com` / `Cliente@2026`, `analista@ford.com` / `Analista@2026`, `admin@ford.com` / `Admin@2026`.

## Ativar o pipeline no GitHub

1. Suba o repositório para o GitHub (`main` como branch principal).
2. **Settings, Pages:** em *Source*, escolha **GitHub Actions**.
3. **Settings, Branches:** crie uma regra para `main` exigindo os checks `Secret Scanning (Trufflehog)`, `SAST (Semgrep)` e `Container Security (Trivy)`. Sem isso, o PR com falha pode ser mesclado mesmo com o pipeline vermelho.
4. **Settings, Code security:** ative *Dependabot alerts*, *Secret scanning* e *Push protection*.
5. Em cada máquina: `pip install pre-commit semgrep`, instale o Trufflehog e rode `pre-commit install`.
