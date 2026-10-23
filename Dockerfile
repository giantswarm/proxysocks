FROM gsoci.azurecr.io/giantswarm/alpine:3.20.3-giantswarm
FROM scratch

COPY --from=0 /etc/passwd /etc/passwd
COPY --from=0 /etc/group /etc/group

ARG TARGETARCH
COPY proxysocks-linux-${TARGETARCH} /proxysocks
USER giantswarm

ENTRYPOINT ["/proxysocks"]

