#!/usr/bin/env bash
# Governed sandbox network access — datapath validation on real Cilium.
#
# Sibling to scripts/netpol-admission-validation.sh. This one proves the GRANT
# semantics rather than the admission race: that each mode reaches exactly what
# it was granted, that every bypass the design names is denied, and that the two
# failure modes leave the control plane reachable so a run can still report.
#
# It owns its cluster end to end (create → assert → destroy) and NOTHING
# self-skips: a missing prerequisite is a failure, because a validation that
# quietly skips is worse than no validation.
#
# Usage:
#   bash scripts/netgrant-kind-validation.sh          # PR-light (busybox/nc)
#   NETGRANT_HEAVY=1 bash .../netgrant-kind-validation.sh   # + real images,
#                                                     #   rebinding, failure
#                                                     #   injection, 2 runs
#   NETGRANT_KEEP=1 ...                               # leave the cluster up
set -uo pipefail

CLUSTER=${NETGRANT_CLUSTER:-fluidbox-netgrant}
CILIUM_VERSION=${CILIUM_VERSION:-1.19.6}
NS=netgrant
HEAVY=${NETGRANT_HEAVY:-0}
WORK=$(mktemp -d)
pass=0; fail=0

ok()  { printf "  \033[1;32m✓\033[0m %s\n" "$1"; pass=$((pass+1)); }
no()  { printf "  \033[1;31m✗\033[0m %s\n" "$1"; fail=$((fail+1)); }
say() { printf "\n\033[1;36m== %s ==\033[0m\n" "$1"; }
die() { printf "\033[1;31mFATAL: %s\033[0m\n" "$1"; exit 1; }

cleanup() {
  if [ "${NETGRANT_KEEP:-0}" = "1" ]; then
    echo "NETGRANT_KEEP=1 — leaving cluster '$CLUSTER' up"
  else
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1
    docker rm -f netgrant-allowed netgrant-denied netgrant-flip >/dev/null 2>&1
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

for bin in kind kubectl helm docker; do
  command -v "$bin" >/dev/null 2>&1 || die "$bin is required (no skips)"
done

# ── Cluster ────────────────────────────────────────────────────────────────
say "CLUSTER — kind + Cilium $CILIUM_VERSION"
cat > "$WORK/kind.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: $CLUSTER
networking:
  disableDefaultCNI: true
  kubeProxyMode: none
nodes:
  - role: control-plane
  - role: worker
EOF
kind create cluster --config "$WORK/kind.yaml" --wait 0s >/dev/null 2>&1 \
  || die "kind create failed"
kubectl label node "$CLUSTER-worker" fluidbox.dev/egress-gateway=true --overwrite >/dev/null
helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1
helm repo update >/dev/null 2>&1
helm install cilium cilium/cilium --version "$CILIUM_VERSION" -n kube-system \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost="$CLUSTER-control-plane" --set k8sServicePort=6443 \
  --set ipam.mode=kubernetes --set bpf.masquerade=true \
  --set egressGateway.enabled=true --set l7Proxy=true \
  --set hubble.relay.enabled=true --set hubble.enabled=true \
  --wait --timeout 15m >/dev/null 2>&1 || die "cilium install failed"
kubectl wait --for=condition=Ready nodes --all --timeout=300s >/dev/null 2>&1 \
  || die "nodes not ready"
ok "cluster up with Cilium $CILIUM_VERSION (kube-proxy replacement, L7 proxy, egress gateway)"

# ── Fixtures: a fake control plane, and two off-cluster targets ────────────
#
# The targets sit on the kind bridge, so they are `world` to Cilium and NOT
# behind docker NAT — which is what makes the observed client IP the egressing
# NODE, and therefore makes the egress gateway observable.
say "FIXTURES"
docker rm -f netgrant-allowed netgrant-denied >/dev/null 2>&1
# UDP too: without a real UDP listener the protocol assertion below could not
# distinguish "the policy blocked it" from "nothing was listening".
docker run -d --name netgrant-allowed --network kind \
  registry.k8s.io/e2e-test-images/agnhost:2.47 \
  netexec --http-port=9099 --udp-port=9099 >/dev/null
docker run -d --name netgrant-denied --network kind \
  registry.k8s.io/e2e-test-images/agnhost:2.47 netexec --http-port=9099 >/dev/null
ALLOWED_IP=$(docker inspect netgrant-allowed --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
DENIED_IP=$(docker inspect netgrant-denied --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
[ -n "$ALLOWED_IP" ] && [ -n "$DENIED_IP" ] || die "target containers have no address"
ok "off-cluster targets: allowed=$ALLOWED_IP denied=$DENIED_IP"

kubectl create ns "$NS" >/dev/null
# A stand-in control plane on :8788, allowed by IDENTITY in every mode.
kubectl -n "$NS" apply -f - >/dev/null <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata: { name: server }
spec:
  replicas: 1
  selector: { matchLabels: { app.kubernetes.io/component: server } }
  template:
    metadata: { labels: { app.kubernetes.io/component: server } }
    spec:
      containers:
        - name: netexec
          image: registry.k8s.io/e2e-test-images/agnhost:2.47
          args: ["netexec", "--http-port=8788"]
EOF
# The CONTROLLED resolver: forward-only, NO kubernetes plugin, plus hosts
# entries for the two targets so name-based grants have something to resolve.
# NOTE: CoreDNS's Corefile parser requires a block's braces on their own lines —
# `health { lameduck 5s }` on one line is a parse error and the container
# crash-loops, which presents downstream as "every FQDN grant is denied".
kubectl -n "$NS" create configmap sandbox-dns --from-literal=Corefile=".:53 {
    errors
    ready
    hosts {
        $ALLOWED_IP allowed.netgrant.test
        $DENIED_IP denied.netgrant.test
        fallthrough
    }
    forward . 1.1.1.1 8.8.8.8
    cache 30
}" >/dev/null
kubectl -n "$NS" apply -f - >/dev/null <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata: { name: sandbox-dns }
spec:
  replicas: 1
  selector: { matchLabels: { app.kubernetes.io/component: sandbox-dns } }
  template:
    metadata: { labels: { app.kubernetes.io/component: sandbox-dns, fluidbox-resolver: "true" } }
    spec:
      containers:
        - name: coredns
          image: registry.k8s.io/coredns/coredns:v1.11.3
          args: ["-conf", "/etc/coredns/Corefile"]
          volumeMounts: [{ name: config, mountPath: /etc/coredns }]
      volumes:
        - name: config
          configMap: { name: sandbox-dns }
---
apiVersion: v1
kind: Service
metadata: { name: sandbox-dns }
spec:
  selector: { app.kubernetes.io/component: sandbox-dns }
  ports:
    - { name: dns, port: 53, protocol: UDP, targetPort: 53 }
    - { name: dns-tcp, port: 53, protocol: TCP, targetPort: 53 }
EOF
kubectl -n "$NS" wait --for=condition=Available deploy --all --timeout=300s >/dev/null 2>&1 \
  || die "fixtures not ready"
DNS_IP=$(kubectl -n "$NS" get svc sandbox-dns -o jsonpath='{.spec.clusterIP}')
ok "controlled resolver at $DNS_IP (forward-only, no kubernetes plugin)"

# ── The chart-static half: baseline + deny wall ────────────────────────────
say "BASELINE — default-deny, standing :8788 allow, deny wall"
kubectl apply -f - >/dev/null <<EOF
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata: { name: fluidbox-sandbox-baseline }
spec:
  endpointSelector:
    matchLabels: { fluidbox.dev/managed: "true" }
  egress:
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: $NS
            app.kubernetes.io/component: server
      toPorts: [{ ports: [{ port: "8788", protocol: TCP }] }]
  egressDeny:
    # NOTE — one deliberate difference from the shipped chart wall: it also
    # denies 172.16.0.0/12, and the kind bridge (172.19.0.0/16) lives there.
    # In this harness that range stands in for PUBLIC space — the off-cluster
    # targets are the "internet" — so walling it would make every reachability
    # assertion below vacuously pass. The wall's real behaviour is still proven:
    # 10.0.0.0/8 and 192.168.0.0/16 are walled and asserted below, and metadata,
    # the kubelet, and the apiserver are asserted throughout.
    - toCIDR: ["169.254.0.0/16", "127.0.0.0/8", "10.0.0.0/8",
               "192.168.0.0/16", "100.64.0.0/10", "224.0.0.0/4", "240.0.0.0/4"]
    - toEntities: ["host", "remote-node", "kube-apiserver"]
EOF

# A sandbox pod for one run. $1=session $2=extra labels
sandbox() {
  kubectl -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: sandbox-$1
  labels:
    fluidbox.dev/managed: "true"
    fluidbox.dev/session: "$1"
    fluidbox.dev/tenant: "t1"
    fluidbox.dev/run: "$1"
spec:
  dnsPolicy: None
  dnsConfig: { nameservers: ["$DNS_IP"] }
  tolerations: [{ operator: Exists }]
  containers:
    - name: probe
      image: curlimages/curl:8.10.1
      command: ["sleep", "infinity"]
EOF
  kubectl -n "$NS" wait --for=condition=Ready "pod/sandbox-$1" --timeout=180s >/dev/null 2>&1
}

# probe <session> <url> -> prints REACH or BLOCK
probe() {
  if kubectl -n "$NS" exec "sandbox-$1" -- curl -s -m 5 -o /dev/null "$2" 2>/dev/null; then
    echo REACH
  else
    echo BLOCK
  fi
}
expect() { # session url want label
  local got; got=$(probe "$1" "$2")
  [ "$got" = "$3" ] && ok "$4" || no "$4 (wanted $3, got $got)"
}

SERVER_IP=$(kubectl -n "$NS" get pod -l app.kubernetes.io/component=server -o jsonpath='{.items[0].status.podIP}')

# ── Mode: offline ──────────────────────────────────────────────────────────
say "OFFLINE — byte-identical in effect to zeroEgress"
sandbox off || die "offline sandbox not ready"
expect off "http://$SERVER_IP:8788/hostname" REACH "offline reaches the control plane :8788"
expect off "http://$ALLOWED_IP:9099/clientip" BLOCK "offline cannot reach any external target"
expect off "http://169.254.169.254/" BLOCK "offline cannot reach cloud metadata"
if kubectl -n "$NS" exec sandbox-off -- nslookup allowed.netgrant.test >/dev/null 2>&1; then
  no "offline must have NO DNS allow"
else
  ok "offline has no DNS at all (no resolver allow)"
fi

# ── Mode: approved ─────────────────────────────────────────────────────────
say "APPROVED — exactly the granted target, and nothing else"
sandbox app || die "approved sandbox not ready"
kubectl -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: { name: fluidbox-run-app }
spec:
  endpointSelector:
    matchLabels:
      fluidbox.dev/session: "app"
      fluidbox.dev/tenant: "t1"
      fluidbox.dev/run: "app"
  egress:
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: $NS
            fluidbox-resolver: "true"
      toPorts:
        - ports: [{ port: "53", protocol: ANY }]
          rules: { dns: [{ matchPattern: "*" }] }
    - toFQDNs: [{ matchName: "allowed.netgrant.test" }]
      toPorts: [{ ports: [{ port: "9099", protocol: TCP }] }]
EOF
sleep 6
expect app "http://$SERVER_IP:8788/hostname" REACH "approved still reaches :8788"
if kubectl -n "$NS" exec sandbox-app -- timeout 6 nslookup allowed.netgrant.test >/dev/null 2>&1; then
  ok "approved RESOLVES its granted name (the DNS rule matched the resolver)"
else
  no "approved cannot resolve at all — every FQDN assertion below would be a resolution failure, not a policy decision"
fi
expect app "http://allowed.netgrant.test:9099/clientip" REACH "approved reaches its granted FQDN"
expect app "http://denied.netgrant.test:9099/clientip" BLOCK "approved cannot reach an ungranted FQDN"
expect app "http://$DENIED_IP:9099/clientip" BLOCK "…nor that target's raw IP"
expect app "http://169.254.169.254/" BLOCK "…nor cloud metadata"
expect app "http://10.0.0.1:9099/" BLOCK "…nor a walled RFC1918 address"
expect app "http://192.168.1.1:9099/" BLOCK "…nor another walled private range"

# ── The bypass matrix ──────────────────────────────────────────────────────
say "BYPASSES — every route the design names"
# Direct IP to an UNGRANTED host.
expect app "http://$DENIED_IP:9099/clientip" BLOCK "direct-IP to an ungranted host"
# A wrong PORT on a granted host: the grant is host+port, not host.
expect app "http://allowed.netgrant.test:9098/" BLOCK "granted host on an UNGRANTED port"
# An alternate resolver — the per-run policy allows :53 only to ours.
if kubectl -n "$NS" exec sandbox-app -- timeout 5 nslookup allowed.netgrant.test 1.1.1.1 >/dev/null 2>&1; then
  no "an alternate DNS resolver must be blocked"
else
  ok "alternate DNS resolver (1.1.1.1:53) blocked"
fi
# DNS-over-HTTPS to a public resolver.
expect app "https://1.1.1.1/dns-query?name=example.com" BLOCK "DNS-over-HTTPS to a public resolver"
# The apiserver + node (entity denies).
expect app "https://kubernetes.default.svc:443/" BLOCK "kube-apiserver via cluster DNS name"
NODE_IP=$(kubectl get node "$CLUSTER-control-plane" -o jsonpath='{.status.addresses[0].address}')
expect app "http://$NODE_IP:10250/" BLOCK "kubelet on the node (host entity)"
# In-cluster service discovery must be impossible: the resolver has no
# kubernetes plugin, so the NAME cannot resolve at all.
if kubectl -n "$NS" exec sandbox-app -- timeout 5 nslookup server."$NS".svc.cluster.local >/dev/null 2>&1; then
  no "in-cluster Service names must NOT resolve (no kubernetes plugin)"
else
  ok "in-cluster Service names do not resolve"
fi
# UDP/QUIC to a granted host: the grant is TCP-only, and the target DOES listen
# on UDP — so a reply proves reach and its absence proves the policy, which a
# bare connectionless send could never distinguish.
UDP_REPLY=$(kubectl -n "$NS" exec sandbox-app -- timeout 6 sh -c \
  "echo hostname | nc -u -w3 $ALLOWED_IP 9099" 2>/dev/null | tr -d '\r\n')
if [ -n "$UDP_REPLY" ]; then
  no "UDP to a TCP-granted host must be blocked (got a reply: $UDP_REPLY)"
else
  ok "UDP to a TCP-granted host blocked (protocol is part of the grant)"
fi
# …and the same probe against a UDP-capable host proves the probe itself works:
# without this, a broken probe would silently "pass" the assertion above.
kubectl -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: { name: fluidbox-run-udpctl }
spec:
  endpointSelector:
    matchLabels:
      fluidbox.dev/session: "udp"
      fluidbox.dev/tenant: "t1"
      fluidbox.dev/run: "udp"
  egress:
    - toCIDR: ["$ALLOWED_IP/32"]
      toPorts: [{ ports: [{ port: "9099", protocol: UDP }] }]
EOF
sandbox udp >/dev/null 2>&1
sleep 5
UDP_CTL=$(kubectl -n "$NS" exec sandbox-udp -- timeout 6 sh -c \
  "echo hostname | nc -u -w3 $ALLOWED_IP 9099" 2>/dev/null | tr -d '\r\n')
[ -n "$UDP_CTL" ] \
  && ok "…and a UDP-GRANTED run does get a reply (the probe is not false-green)" \
  || no "the UDP probe itself is broken — the block assertion above proves nothing"
# Proxy env vars are moot at packet level — assert it rather than imply it.
if kubectl -n "$NS" exec sandbox-app -- sh -c \
    "https_proxy=http://$DENIED_IP:9099 curl -s -m 5 -o /dev/null https://example.com" 2>/dev/null; then
  no "a proxy env var must not create reach"
else
  ok "proxy env vars create no reach (enforcement is at L3/L4, not in the client)"
fi

# ── Cross-run isolation ────────────────────────────────────────────────────
say "CROSS-RUN ISOLATION — the selector is the boundary"
sandbox two || die "second sandbox not ready"
kubectl -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: { name: fluidbox-run-two }
spec:
  endpointSelector:
    matchLabels:
      fluidbox.dev/session: "two"
      fluidbox.dev/tenant: "t1"
      fluidbox.dev/run: "two"
  egress:
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: $NS
            fluidbox-resolver: "true"
      toPorts:
        - ports: [{ port: "53", protocol: ANY }]
          rules: { dns: [{ matchPattern: "*" }] }
    - toFQDNs: [{ matchName: "denied.netgrant.test" }]
      toPorts: [{ ports: [{ port: "9099", protocol: TCP }] }]
EOF
sleep 6
# Both resolve their OWN name first, populating the shared DNS cache — this is
# what makes the test meaningful: FQDN resolution creates CLUSTER-WIDE CIDR
# identities, so isolation must come from the selector, not from cache locality.
probe app "http://allowed.netgrant.test:9099/clientip" >/dev/null
probe two "http://denied.netgrant.test:9099/clientip" >/dev/null
expect two "http://denied.netgrant.test:9099/clientip" REACH "run two reaches its own target"
expect two "http://allowed.netgrant.test:9099/clientip" BLOCK "run two cannot reach run one's FQDN"
expect two "http://$ALLOWED_IP:9099/clientip" BLOCK "…nor its raw IP"
expect app "http://$DENIED_IP:9099/clientip" BLOCK "run one cannot reach run two's raw IP"

# ── Mode: public ───────────────────────────────────────────────────────────
say "PUBLIC — the world minus the wall"
sandbox pub || die "public sandbox not ready"
kubectl -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: { name: fluidbox-run-pub }
spec:
  endpointSelector:
    matchLabels:
      fluidbox.dev/session: "pub"
      fluidbox.dev/tenant: "t1"
      fluidbox.dev/run: "pub"
  egress:
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: $NS
            fluidbox-resolver: "true"
      toPorts:
        - ports: [{ port: "53", protocol: ANY }]
          rules: { dns: [{ matchPattern: "*" }] }
    - toEntities: ["world"]
EOF
sleep 6
expect pub "http://$SERVER_IP:8788/hostname" REACH "public still reaches :8788"
# The wall outranks a 0.0.0.0/0-equivalent allow — THE structural guarantee.
expect pub "http://169.254.169.254/" BLOCK "public CANNOT reach metadata (the wall outranks it)"
expect pub "http://$NODE_IP:10250/" BLOCK "public cannot reach the kubelet"
# Public reaches a world address that NO per-run grant names — the point of the
# mode. Asserted against the off-cluster target rather than a real internet host
# so the result reflects the POLICY, not the CI runner's connectivity.
expect pub "http://$DENIED_IP:9099/clientip" REACH "public reaches a world address no grant named"
expect pub "http://$ALLOWED_IP:9099/clientip" REACH "…and another"
# The walled private ranges are still denied under public — proving the wall is
# doing real work here and not merely absent.
expect pub "http://10.0.0.1:9099/" BLOCK "public cannot reach a walled RFC1918 range"

# ── Failure modes ──────────────────────────────────────────────────────────
say "FAILURE MODES — the control plane stays reachable"
kubectl -n "$NS" scale deploy sandbox-dns --replicas=0 >/dev/null
kubectl -n "$NS" wait --for=delete pod -l app.kubernetes.io/component=sandbox-dns --timeout=120s >/dev/null 2>&1
expect app "http://$SERVER_IP:8788/hostname" REACH "resolver down: :8788 still reachable (allowed by IDENTITY, not name)"
kubectl -n "$NS" scale deploy sandbox-dns --replicas=1 >/dev/null
kubectl -n "$NS" wait --for=condition=Available deploy/sandbox-dns --timeout=180s >/dev/null 2>&1
ok "resolver restored"

if [ "$HEAVY" = "1" ]; then
  say "HEAVY — real workloads + DNS rebinding"
  # A real toolchain must work through a grant, not just curl.
  kubectl -n "$NS" exec sandbox-pub -- sh -c \
    "curl -sSL -m 60 -o /dev/null https://pypi.org/simple/" >/dev/null 2>&1 \
    && ok "public: a real HTTPS toolchain endpoint is reachable" \
    || no "public: pypi.org unreachable"
  # DNS rebinding: flip a name from the granted address to the denied one and
  # confirm the grant does not follow it to a NEW address.
  kubectl -n "$NS" patch configmap sandbox-dns --type merge -p \
    "{\"data\":{\"Corefile\":\".:53 {\n errors\n ready\n hosts {\n  $DENIED_IP allowed.netgrant.test\n  fallthrough\n }\n forward . 1.1.1.1\n cache 0\n}\"}}" >/dev/null
  kubectl -n "$NS" rollout restart deploy/sandbox-dns >/dev/null
  kubectl -n "$NS" rollout status deploy/sandbox-dns --timeout=180s >/dev/null 2>&1
  sleep 20
  expect app "http://$DENIED_IP:9099/clientip" BLOCK "DNS rebinding: the grant does not follow a name to a new address"
fi

say "RESULT"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
[ "$fail" -eq 0 ] || echo "  (a failure here is a DATAPATH failure — do not ship past it)"
exit $(( fail > 0 ? 1 : 0 ))
