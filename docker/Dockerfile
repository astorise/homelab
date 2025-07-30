FROM rancher/k3s:latest AS k3s
FROM busybox:latest
COPY --from=k3s /bin/k3s /bin/k3s
# COPY --from=k3s /bin/aux /bin/aux

