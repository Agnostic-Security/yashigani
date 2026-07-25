<!-- Last updated: 2026-07-14 (LAURA-411-001 — operator guidance for securing a self-run inference backend) -->
# Securing Your Self-Run Inference Backend

Yashigani routes all model traffic through **Caddy, the authentication perimeter** — authentication, RBAC, OPA policy, budget caps, audit, and PII/sensitivity inspection all live there. If you run your **own** local inference server (Ollama, LM Studio, llama.cpp server, vLLM, …) and leave its API open, any process on the host — or anything on your network if it is bound beyond loopback — can call it **directly**, bypassing every one of those controls.

> **Ollama has no built-in authentication** on its serve API: an unauthenticated request to `:11434` is answered. LM Studio and most local servers are the same. Securing the backend is the operator's responsibility — this document shows you how.

## What an open backend bypasses
A direct call to the backend that does not go through Caddy is **not** subject to:
- Authentication / identity
- RBAC + OPA model-permission enforcement
- Budget caps & usage accounting
- Audit trail
- PII / sensitivity inspection
- Model-integrity pinning

## Two distinct exposures
1. **Network exposure** — the backend is reachable from *other hosts* (bound to `0.0.0.0` or a LAN address). **Firewall rules close this** (Steps 1–2).
2. **Same-host access** — any *local process* reaches the backend over loopback. A packet firewall **cannot** distinguish local processes on loopback; close this by containment (Step 3) or accept it as a same-host-trust residual on a single-operator workstation (see *Honest limitation*).

---

## Step 1 — bind to loopback only
Make sure the backend is **not** listening on all interfaces.

- **Ollama:** `OLLAMA_HOST=127.0.0.1:11434` (this is the default — *verify* it is not `0.0.0.0:11434`).
- **LM Studio / llama.cpp / vLLM:** set the bind/host to `127.0.0.1` (ports differ: LM Studio `1234`, llama.cpp `8080`, vLLM `8000` — substitute below).

Verify:
```bash
# macOS / Linux — should show 127.0.0.1, NOT 0.0.0.0 or *
lsof -nP -iTCP:11434 -sTCP:LISTEN        # macOS
ss -ltnp 'sport = :11434'                # Linux
```

## Step 2 — firewall rules (defense-in-depth vs network exposure)
These block the port on the *network* while leaving loopback and the Yashigani gateway working. Adjust the **interface** (macOS) and the **gateway subnet** (Linux containers) to your host. All require administrator/root on the machine you are protecting.

### macOS — `pf`
Block inbound to the backend port on the physical interface(s); loopback (where the gateway reaches it via gvproxy/VPNKit) is untouched.
```
# /etc/pf.anchors/com.yashigani.backend
block drop in quick on en0 proto tcp to any port 11434
# add a line per active interface if multi-homed (en1, en5, utun*, ...)
```
Load and enable. **The anchor must be *referenced* in the main ruleset (`/etc/pf.conf`), or its rules are loaded into the kernel but never evaluated** — `pfctl -a … -s rules` will show them yet packets are never matched, giving false confidence:
```bash
# 1. Reference the anchor in the main ruleset (once):
echo 'anchor "com.yashigani.backend"' | sudo tee -a /etc/pf.conf
sudo pfctl -f /etc/pf.conf
# 2. Load the anchor's rules and enable pf:
sudo pfctl -a com.yashigani.backend -f /etc/pf.anchors/com.yashigani.backend
sudo pfctl -e            # if pf is not already enabled
```
> Without the `anchor "com.yashigani.backend"` line in `pf.conf`, `pfctl -e` alone does **not** activate the anchor's rules. Verify enforcement by actually connecting from a non-loopback address, not just by listing the rules.

Find your active interface with `route get default | awk '/interface/{print $2}'`.

### Linux — `iptables`
Allow loopback and the gateway container subnet; drop everything else to the port.
```bash
sudo iptables -A INPUT -p tcp --dport 11434 -i lo -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 11434 -s 10.89.0.0/16 -j ACCEPT   # podman default; docker is typically 172.16.0.0/12
sudo iptables -A INPUT -p tcp --dport 11434 -j DROP
```
> If your `INPUT` chain has a default `ACCEPT` policy or an existing broad `ACCEPT` rule, the appended (`-A`) `DROP` is evaluated *after* it and never fires. In that case use `-I INPUT 1 …` (insert at the top) instead of `-A INPUT …` so these rules are matched first. Same applies to `nft add rule` (append) vs `nft insert rule`.

Persist with `iptables-save` / your distro's `netfilter-persistent`.

### Linux — `nftables`
```bash
sudo nft add rule inet filter input tcp dport 11434 iif lo accept
sudo nft add rule inet filter input tcp dport 11434 ip saddr 10.89.0.0/16 accept
sudo nft add rule inet filter input tcp dport 11434 drop
```

### Linux — `ufw`
```bash
sudo ufw allow from 10.89.0.0/16 to any port 11434 proto tcp
sudo ufw deny 11434/tcp
```

### Linux — `firewalld`
```bash
sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=10.89.0.0/16 port port=11434 protocol=tcp accept'
sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 port port=11434 protocol=tcp drop'
sudo firewall-cmd --reload
```
Find the gateway subnet with `podman network inspect <yashigani-net> | grep -i subnet` (or `docker network inspect`).

## Step 3 — containerize the backend (strongest, closes both exposures)
Run the backend as a **container on Yashigani's internal network only, not host-published**. Then *only* the gateway can reach it — no host process can, and no firewall rule is needed. This is the recommended posture on Linux/production.

> **macOS exception:** GPU (Metal) requires the backend to run **host-native**, so it cannot be containerized on macOS. On macOS, use Steps 1–2 + Step 4 and treat the same-host residual per *Honest limitation*.

## Step 4 — route the backend's egress through Caddy
So the backend's *outbound* traffic (model pulls, telemetry, tool fetches) is monitored and policy-governed rather than going straight to the internet, point it at Caddy as its egress proxy:
```bash
# example — the backend's own environment
HTTPS_PROXY=http://<caddy-egress-host>:<port>
HTTP_PROXY=http://<caddy-egress-host>:<port>
```
This is what puts a self-run backend's egress under the same OPA + monitoring as Yashigani's managed backends. (Model *integrity* — a swapped/trojaned model — is handled separately by model-integrity pinning; you do not need to route pulls through Caddy for that.)

## Honest limitation
A packet firewall **cannot** stop a *same-host process on loopback* — it filters by address/port, and all local processes share `127.0.0.1`. Fully closing that would require binding to a Unix socket with file permissions (which Ollama does not support) or containment (Step 3). On a **single-operator workstation** this is within your trust boundary. On a **shared or multi-tenant host**, prefer the containerized backend (Step 3); do not rely on firewall rules alone.

## Quick checklist
- [ ] Backend bound to `127.0.0.1` (Step 1)
- [ ] Firewall rule dropping non-loopback access to the port (Step 2)
- [ ] Containerized + not host-published where possible (Step 3, Linux)
- [ ] Backend egress pointed at Caddy (Step 4)
- [ ] Understood the same-host loopback residual (Honest limitation)
