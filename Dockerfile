# Imagem de produção do app (arquivos estáticos servidos pelo nginx)
# Base sem root: o processo não roda como administrador do container.
# Em produção, fixar por digest (@sha256:...) e deixar o Dependabot atualizar.
FROM nginxinc/nginx-unprivileged:stable-alpine

# Correção apontada pelo Trivy: CVE-2026-93990 (HIGH) na libexpat 2.8.4 da imagem base.
# Enquanto a imagem oficial não é reconstruída, atualizamos o pacote aqui.
# Precisa de root só para o apk; o USER 101 abaixo volta para o usuário sem privilégios.
USER root
RUN apk upgrade --no-cache libexpat

COPY --chown=101:101 nginx/default.conf /etc/nginx/conf.d/default.conf
COPY --chown=101:101 app/ /usr/share/nginx/html/

USER 101
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/ >/dev/null || exit 1