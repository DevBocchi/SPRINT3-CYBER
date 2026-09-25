# Imagem de produção do app (arquivos estáticos servidos pelo nginx)
# Base sem root: o processo não roda como administrador do container.
# Em produção, fixar por digest (@sha256:...) e deixar o Dependabot atualizar.
FROM nginxinc/nginx-unprivileged:stable-alpine

COPY --chown=101:101 nginx/default.conf /etc/nginx/conf.d/default.conf
COPY --chown=101:101 app/ /usr/share/nginx/html/

USER 101
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/ >/dev/null || exit 1
