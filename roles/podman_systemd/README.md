# lit.foundational.podman_systemd

Manage persistent Podman kube services through Quadlet and systemd.

The role renders a `.kube` Quadlet unit, reloads systemd, and can start,
restart, stop, enable, disable, or remove the generated service.

`podman_systemd_networks` is an optional list of native Quadlet `Network=`
values. It supports Podman's network options without adding an imperative
`podman kube play` wrapper. For example:

```yaml
podman_systemd_networks:
  - podman-default-kube-network:ip=10.89.0.20
```

Each entry must be a non-empty single-line string. Static addresses must be
reserved by the inventory and remain inside the selected Podman network.
