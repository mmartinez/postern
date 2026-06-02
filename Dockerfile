# Production image for postern — distinct from .devcontainer/Dockerfile.
#
# distroless/base-debian12 ships glibc + ca-certificates: the credential SDK
# (internal/credstore/onepassword) links glibc dynamically, and postern verifies
# upstream TLS against the system roots. The :nonroot tag runs as uid 65532.
#
# The binary is built and injected by goreleaser (see .goreleaser.yaml's dockers
# block) — a bare `docker build .` has no binary to COPY, so images are produced
# through the goreleaser release path, not by hand.
FROM gcr.io/distroless/base-debian12:nonroot

COPY postern /usr/local/bin/postern

# Default proxy port (proxy.listen in config.yaml). In container deployments set
# proxy.listen to 0.0.0.0:14321 so the agent container can reach the proxy.
EXPOSE 14321

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/postern"]
CMD ["server"]
