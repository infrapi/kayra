# The Kayra image GoReleaser publishes on every release
# (ghcr.io/infrapi/kayra, see .goreleaser.yaml): the kayra binary it has
# just built, for each platform, on Alpine. No
# configuration inside: mount one at /etc/kayra/kayra.yaml.
#
#   podman run -v ./kayra.yaml:/etc/kayra/kayra.yaml:ro,z -p 8080:8080 ghcr.io/infrapi/kayra serve
#   podman run --rm ghcr.io/infrapi/kayra --version
FROM docker.io/library/alpine:3.22

# ca-certificates: OIDC, LDAPS and reconcile endpoints over TLS. curl: the
# healthcheck an orchestrator runs, e.g.
#   curl -fsS http://127.0.0.1:8080/apis/system.<domain>/v1/-/healthz
RUN apk add --no-cache ca-certificates curl \
 && adduser -D -H -u 10001 kayra

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/kayra /usr/local/bin/

ENV KAYRA_CONFIG_FILE=/etc/kayra/kayra.yaml
USER kayra
EXPOSE 8080
ENTRYPOINT ["kayra"]
CMD ["serve"]
