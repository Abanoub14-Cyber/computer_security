# LINFO2347 — Network Security Project

A Mininet-based enterprise network simulation with attack demonstrations and firewall protections.

## Network Topology

```
[ws2 10.1.0.2] ─┐
                 ├─ s1 ── r1 (10.1.0.1 / 10.12.0.1) ── s2 ── r2 (10.12.0.2 / 10.2.0.1) ── internet (10.2.0.2)
[ws3 10.1.0.3] ─┘                                       │
                                              ┌──────────┼──────────┬──────────┐
                                           http        dns         ntp        ftp
                                        10.12.0.10  10.12.0.20  10.12.0.30  10.12.0.40
```

- **LAN** (`10.1.0.0/24`): trusted workstations (ws2, ws3), gateway r1
- **DMZ** (`10.12.0.0/24`): HTTP, DNS, NTP, FTP servers
- **Internet** (`10.2.0.0/24`): external host, gateway r2

## Baseline Firewall Rules

Two routers enforce a default-drop policy:

**r1** (`rules_r1.sh`): allows outbound traffic from the LAN (`10.1.0.0/24`) and returns established/related flows. Everything else is dropped.

**r2** (`rules_r2.sh`): allows LAN-initiated traffic, Internet→DMZ new connections, and DMZ→LAN returns. A workaround rule (`ip saddr 10.12.0.0/24 ip daddr 10.1.0.0/24 accept`) is required because without it, DMZ replies get re-routed via r1 in a loop; this is safe since r1 blocks unsolicited DMZ→LAN traffic anyway.

## Running the Topology

```bash
# Basic startup (no protections)
sudo python3 topo.py

# With one or more protections enabled
sudo python3 topo.py -i -t -s -d -a

# Connectivity test
sudo python3 topo.py -p
```

| Flag | Protection |
|------|------------|
| `-i` | ICMP ping sweep |
| `-t` | TCP SYN scan |
| `-s` | SSH brute-force |
| `-d` | DNS reflected DDoS |
| `-a` | ARP cache poisoning |


> **Note:** Protections can be applied at any time from the Mininet CLI, even if the topology was started without them. From any router/host shell in the CLI (e.g. `mininet> r2 sh protection/protect_ICMP.sh`), or using the commands listed in each section below.

---

## Attacks & Protections

### 1. ICMP Ping Sweep

**Attack** — from `internet`, scan the DMZ subnet:
```bash
internet> python3 attack/attack_ICMP.py 10.12.0.0/24
```
Sends ICMP echo-requests to all addresses and lists live hosts.

**Verify** — on r2, capture the flood of inbound echo-requests:
```bash
r2> tcpdump -i r2-eth12 icmp
```
Without protection you'll see continuous echo-request/reply pairs. With protection, replies stop after the rate limit kicks in.

**Apply protection at runtime:**
```bash
r2> sh protection/protect_ICMP.sh
```

**Protection** (`protect_ICMP.sh`) — rate-limits ICMP echo-requests per source to 5/second (burst 3) on r2. Excess packets are dropped.

---

### 2. TCP SYN Scan

**Attack** — from `internet`, scan a DMZ server:
```bash
internet> python3 attack/attack_TCP.py 10.12.0.10 1 1024
```
Sends SYN packets and identifies open ports from SYN-ACK responses.

**Verify** — on r2, watch the SYN flood arrive:
```bash
r2> tcpdump -i r2-eth12 'tcp[tcpflags] & tcp-syn != 0'
```
Without protection, SYN-ACKs come back for open ports. With protection, SYNs are dropped after the burst is exhausted and the scan stalls.

**Apply protection at runtime:**
```bash
r2> sh protection/protect_TCP.sh
```

**Protection** (`protect_TCP.sh`) — rate-limits new TCP SYN connections per source to 5/second (burst 3) on r2. Excess SYNs are dropped.

---

### 3. SSH Brute-Force

**Attack** — from `internet`, against a DMZ SSH server:
```bash
internet> python3 attack/attack_SSH.py 10.12.0.10 mininet wordlist.txt
```
Iterates through `wordlist.txt` attempting SSH logins. The included wordlist is intentionally small for demonstration; real-world lists are far larger.

**Verify** — on r2, watch SSH connection attempts:
```bash
r2> tcpdump -i r2-eth12 'tcp port 22'
```
Without protection, each attempt produces a full TCP handshake. With protection, connections from the attacker are dropped after 3 attempts/minute and the script reports them as blocked.

**Apply protection at runtime:**
```bash
r2> sh protection/protect_SSH.sh
```

**Protection** (`protect_SSH.sh`) — sources exceeding 3 new SSH connections/minute are dynamically blacklisted for 5 minutes on r2.

---

### 4. DNS Reflected DDoS
**Assumption**: ws3 (10.1.0.3) is treated as a compromised insider host for this attack.

**Attack** — from `ws3`, spoofing the victim's IP toward the DNS server:
```bash
ws3> python3 attack/attack_DNS_DDoS.py 10.1.0.2 10.12.0.20 1000
```
Sends 1000 spoofed DNS queries with `src=victim`. The DNS server floods the victim with unsolicited replies.

**Verify** — on ws2, capture the flood of unsolicited DNS replies:
```bash
ws2> tcpdump -i ws2-eth0 'udp port 5353'
```
On dns capture the flow of requests and replies to observe the amplification factor (around x1,6) in reply size.
```bash
ws2> tcpdump -i any udp port 5353
```
Without protection, ws2 is bombarded with DNS responses it never requested. With protection, the rate of incoming responses is capped and most are dropped at r2.

**Apply protection at runtime:**
```bash
r2> sh protection/protect_DNS_DDoS.sh
```

**Protection** (`protect_DNS_DDoS.sh`) — rate-limits UDP responses from the DNS server (`10.12.0.20:53`) to any single destination at 5/second (burst 10) on r2. Excess responses are dropped.

---

### 5. ARP Cache Poisoning (MITM)
**Assumption**: ws3 (10.1.0.3) is treated as a compromised insider host for this attack.

**Attack** — from `ws3` on the LAN, intercept traffic between `ws2` and `r1`:
```bash
ws3> python3 attack/attack_ARP.py 10.1.0.2 10.1.0.1 ws3-eth0
```
Sends gratuitous ARP replies to both victims, associating each other's IP with ws3's MAC. IP forwarding is enabled on ws3 so traffic still flows (transparent MITM).

**Verify** — check ws2's ARP cache for the poisoned entry, and capture intercepted traffic on ws3:
```bash
# On ws2: r1's IP should be mapped to ws3's MAC (not r1's real MAC)
ws2> ip neigh show dev ws2-eth0

# On ws3: confirm forwarded packets from ws2 are passing through
ws3> tcpdump -i ws3-eth0 -n
```
With protection, `ip neigh show` on ws2 will always show r1's real MAC regardless of the spoofed ARP replies.

**Apply protection at runtime:**
```bash
# Get the real MACs first, then run on ws2
r1> cat /sys/class/net/r1-eth0/address
ws3> cat /sys/class/net/ws3-eth0/address
ws2> sh protection/protect_ARP.sh <r1_mac> <ws3_mac>
```

**Protection** (`protect_ARP.sh`) — installs permanent static ARP entries on ws2 for r1 and ws3, preventing the cache from being overwritten by spoofed replies.