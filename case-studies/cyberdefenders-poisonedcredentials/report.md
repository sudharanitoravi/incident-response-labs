# Incident Report — CyberDefenders PoisonedCredentials
**Platform:** CyberDefenders | **Date:** April 2026
**Category:** Network Forensics | **Difficulty:** Beginner
**Status:** Completed
**Tool Used:** Wireshark
**PCAP File:** PoisonedCredentials.pcap

---

## Executive Summary
This investigation analysed a network packet capture of an LLMNR 
poisoning attack. The attacker exploited the Link-Local Multicast 
Name Resolution (LLMNR) protocol to intercept name resolution 
requests from a victim machine, responded with a poisoned reply 
pointing to the attacker's IP, and captured NTLMv2 credential 
hashes when the victim attempted to authenticate. The captured 
credentials belong to the user cybercactus.local\janesmith on 
a machine identified as ACCOUNTINGPC in the CYBERCACTUS domain.

---

## What is LLMNR Poisoning?
LLMNR (Link-Local Multicast Name Resolution) is a Windows protocol 
used to resolve hostnames on a local network when DNS fails. When 
a Windows machine cannot resolve a hostname via DNS, it broadcasts 
an LLMNR query to all devices on the network asking "who is [hostname]?"

An attacker listening on the network can respond to these broadcasts 
claiming to be the requested hostname. The victim then attempts to 
authenticate with the attacker's machine, sending NTLMv2 credential 
hashes which the attacker captures and can crack offline.

This is one of the most common Active Directory attack techniques 
and requires no special privileges — just network access.

---

## Artifacts Analysed
| File | Type | Description |
|------|------|-------------|
| PoisonedCredentials.pcap | Network capture | Full packet capture — 269 total packets |

---

## Tools Used
| Tool | Purpose |
|------|---------|
| Wireshark | PCAP analysis and protocol filtering |

---

## Screenshots & Analysis

### 01 — LLMNR Queries from Victim Machine
![LLMNR queries](screenshots/01-POISONED.png)
*Filter applied: `llmnr and ip.src == 192.168.232.162`*

*Victim machine (192.168.232.162) is broadcasting LLMNR queries 
for a hostname called "fileshaare" — note the deliberate typo 
with double "a". This suggests a user or application typed the 
wrong hostname, triggering LLMNR broadcast resolution.*

**LLMNR queries visible:**
| Packet | Time | Query | Type |
|--------|------|-------|------|
| 52 | 74.356170 | fileshaare | A (IPv4) |
| 53 | 74.356581 | fileshaare | AAAA (IPv6) |
| 69 | 74.406407 | fileshaare | A |
| 70 | 74.407088 | fileshaare | AAAA |
| 76 | 74.419239 | fileshaare | A |
| 77 | 74.419852 | fileshaare | AAAA |
| 84 | 74.438101 | fileshaare | A |
| 85 | 74.438618 | fileshaare | AAAA |

**Packet 53 detail visible:**
- Protocol: LLMNR
- Source: 192.168.232.162 (victim)
- Destination: 224.0.0.252 (LLMNR multicast address)
- Query: fileshaare type AAAA class IN
- Port: 5355 (LLMNR default port)

*The victim is broadcasting to 224.0.0.252 — the LLMNR multicast 
address. Every device on the network receives this query. This is 
the moment the attacker sees the opportunity to respond.*

**Why "fileshaare" matters:**
The misspelled hostname "fileshaare" indicates a user tried to 
access a file share that doesn't exist. DNS couldn't resolve it, 
so Windows fell back to LLMNR — exactly the condition an attacker 
waits for.*

---

### 02 — LLMNR Poisoning Response
![LLMNR poisoning](screenshots/02-POISONED.png)
*Filter applied: `llmnr`*

*This screenshot shows the full LLMNR conversation including 
the attacker's poisoned response — the critical moment of the attack.*

**Key packets showing the poisoning:**
| Packet | Source | Destination | Info | Significance |
|--------|--------|-------------|------|-------------|
| 84 | 192.168.232.162 | 224.0.0.252 | Query fileshaare A | Victim queries |
| 85 | 192.168.232.162 | 224.0.0.252 | Query fileshaare AAAA | Victim queries |
| 87 | 192.168.232.215 | 192.168.232.162 | Response fileshaare A 192.168.232.215 |  Attacker responds |
| 88 | 192.168.232.215 | 192.168.232.162 | Response fileshaare AAAA fe80::c0a9:714f:8ea7:3313 |  Attacker responds |

**The poisoning sequence:**
1. Victim (192.168.232.162) broadcasts "who is fileshaare?"
2. Attacker (192.168.232.215) responds "I am fileshaare"
3. Victim believes the attacker and attempts to connect
4. Victim sends NTLMv2 credentials to authenticate

**Additional poisoning visible for "prinetr":**
| Packet | Info |
|--------|------|
| 171 | Response prinetr A 192.168.232.215 |
| 172 | Response prinetr AAAA fe80::c0a9:714f:8ea7:3313 |

*The attacker is also poisoning queries for "prinetr" — another 
misspelled hostname (likely "printer"). This shows the attacker 
is systematically responding to ALL LLMNR queries on the network.*

**Attacker IP identified: 192.168.232.215**

---

### 03 — Packet 171 Detail — Poisoned Response
![Packet detail](screenshots/03-POISONED.png)
*Detailed view of Packet 171 — the LLMNR poisoned response 
from attacker to victim for the "prinetr" hostname query.*

**Packet 171 full details:**
| Field | Value |
|-------|-------|
| Frame | 90 bytes on wire |
| Source MAC | VMware_44:ca:ef (00:0c:29:44:ca:ef) |
| Destination MAC | VMware_9c:01:34 (00:0c:29:9c:01:34) |
| Source IP | 192.168.232.215 (attacker) |
| Destination IP | 192.168.232.176 (victim 2) |
| Protocol | LLMNR (UDP port 5355) |
| Message type | Response — No error |

**LLMNR response flags:**
| Flag | Value | Meaning |
|------|-------|---------|
| Message is response | 1 | This is a reply, not a query |
| Opcode | Standard query (0) | Normal resolution |
| Conflict | The name is considered unique | Attacker claims ownership |
| Truncated | Not truncated | Full response |
| Tentative | Not tentative | Confident claim |
| Reply code | No error (0) | Appears legitimate |

*The attacker's response mimics a legitimate LLMNR reply perfectly — 
all flags appear normal to the victim machine, which has no way to 
verify the response is malicious.*

---

### 04 — SMB2 NTLM Authentication Capture
![SMB authentication](screenshots/04-POISONED.png)
*Filter applied: `tcp.stream eq 11`*

*After the victim believed the attacker's poisoned LLMNR response, 
it attempted to connect to the attacker via SMB (port 445) and 
sent NTLMv2 credentials for authentication.*

**SMB2 session setup sequence:**
| Packet | Protocol | Info | Significance |
|--------|----------|------|-------------|
| 232 | TCP | SYN to port 445 | Victim connects to attacker |
| 233 | TCP | SYN-ACK | Attacker accepts |
| 234 | TCP | ACK | Handshake complete |
| 235 | SMB | Negotiate Protocol Request | SMB negotiation begins |
| 236 | SMB2 | Negotiate Protocol Response | Attacker responds |
| 240 | SMB2 | Session Setup NTLMSSP_NEGOTIATE |  NTLM auth begins |
| 241 | SMB2 | Session Setup NTLMSSP_CHALLENGE |  Server sends challenge |
| 242 | SMB2 | Session Setup NTLMSSP_AUTH User: cybercactus.local\janesmith |  Credentials captured |
| 261 | TCP | RST ACK | Connection reset |

**Critical — Packet 242:**
`Session Setup Request, NTLMSSP_AUTH, User: cybercactus.local\janesmith`

*The victim sent NTLMv2 credentials for user janesmith in the 
cybercactus.local domain. The attacker has now captured these 
credential hashes which can be cracked offline using tools like 
Hashcat or John the Ripper.*

**Connection terminated with RST (Packet 261):**
The attacker reset the connection after capturing credentials — 
they got what they needed and dropped the session.

---

### 05 — NTLMSSP Challenge Details
![NTLMSSP challenge](screenshots/05-POISONED.png)
*Filter applied: `ip.dst == 192.168.215 and smb2`*

*Detailed view of the NTLMSSP Challenge packet (241) revealing 
the target environment details disclosed by the attacker's 
fake SMB server.*

**NTLMSSP Challenge details:**
| Field | Value | Significance |
|-------|-------|-------------|
| NTLMSSP Identifier | NTLMSSP | Protocol confirmed |
| Message Type | NTLMSSP_CHALLENGE (2) | Server sending challenge |
| Target Name | CYBERCACTUS |  Domain name revealed |
| NTLM Server Challenge | c8eb5e4b7c037617 | Challenge value for NTLMv2 |
| NetBIOS domain name | CYBERCACTUS | Domain confirmed |
| NetBIOS computer name | ACCOUNTINGPC |  Machine name revealed |
| DNS computer name | AccountingPC.cybercactus.local | Full FQDN |
| DNS domain name | cybercactus.local | Full domain name |
| DNS tree name | cybercactus.local | AD forest name |
| Version | 10.0 Build 19041 | Windows 10/11 confirmed |

**What this reveals to the attacker:**
- Domain: cybercactus.local
- Machine: ACCOUNTINGPC
- OS: Windows 10 (Build 19041)
- User: janesmith (from packet 242)
- Full username: cybercactus.local\janesmith

*With the captured NTLMv2 hash and this environment context, 
the attacker can:*
1. Crack the hash offline using Hashcat/John the Ripper
2. Use the hash directly in Pass-the-Hash attacks
3. Relay the hash to other machines in the domain
4. Access ACCOUNTINGPC if the password is weak

---

## Complete Attack Timeline

| Step | Time | Action | Evidence | MITRE |
|------|------|--------|---------|-------|
| 1 | 74.356s | Victim (192.168.232.162) broadcasts LLMNR query for "fileshaare" | Packets 52–85 | T1557.001 |
| 2 | 74.441s | Attacker (192.168.232.215) sends poisoned LLMNR response | Packets 87–88 | T1557.001 |
| 3 | 254.182s | Attacker poisons "prinetr" query for second victim | Packet 171 | T1557.001 |
| 4 | 398.424s | Victim connects to attacker on SMB port 445 | Packet 232 TCP SYN | T1187 |
| 5 | 398.431s | SMB protocol negotiation begins | Packets 235–236 | T1187 |
| 6 | 398.465s | NTLM authentication initiated | Packet 240 | T1187 |
| 7 | 398.466s | Attacker sends NTLMSSP challenge | Packet 241 | T1187 |
| 8 | 398.476s | Victim sends NTLMv2 hash for janesmith | Packet 242 | T1187 |
| 9 | 398.630s | Attacker resets connection — credentials captured | Packet 261 RST | T1187 |

---

## Indicators of Compromise (IOCs)

| IOC | Type | Value |
|-----|------|-------|
| Attacker IP | IP Address | 192.168.232.215 |
| Victim IP 1 | IP Address | 192.168.232.162 |
| Victim IP 2 | IP Address | 192.168.232.176 |
| Compromised user | Username | cybercactus.local\janesmith |
| Target machine | Hostname | ACCOUNTINGPC |
| Domain | Active Directory | cybercactus.local |
| Queried hostname 1 | LLMNR | fileshaare |
| Queried hostname 2 | LLMNR | prinetr |
| NTLM challenge | Hash | c8eb5e4b7c037617 |
| SMB port | Port | 445 |
| LLMNR port | Port | 5355 |
| OS identified | Version | Windows 10 Build 19041 |

---

## MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|-----------|-----|---------|
| LLMNR/NBT-NS Poisoning | T1557.001 | Attacker responded to LLMNR broadcasts |
| Forced Authentication | T1187 | Victim sent NTLMv2 hash to attacker |
| Adversary in the Middle | T1557 | Attacker intercepted name resolution |
| Network Sniffing | T1040 | Passive monitoring for LLMNR queries |
| OS Credential Dumping: NTLM | T1003 | NTLMv2 hash captured from SMB auth |

---

## Response Recommendations

### Immediate Actions
1. Disable LLMNR on all Windows machines via Group Policy
2. Disable NBT-NS (NetBIOS Name Service) — similar attack vector
3. Reset password for cybercactus.local\janesmith immediately
4. Check if janesmith's credentials were used for lateral movement
5. Isolate or investigate 192.168.232.215 — attacker machine
6. Audit all SMB connections to 192.168.232.215

### Remediation
1. Disable LLMNR via GPO:
   Computer Configuration → Administrative Templates → 
   Network → DNS Client → Turn off Multicast Name Resolution → Enabled
2. Enable SMB signing to prevent relay attacks
3. Implement Network Access Control (NAC)
4. Deploy IDS rules to detect LLMNR poisoning attempts
5. Use strong passwords — NTLMv2 hashes are crackable with weak passwords
6. Implement multi-factor authentication across the domain

### Detection Rules to Create
1. Alert on LLMNR responses from non-DNS servers
2. Alert on SMB connections to unexpected internal IPs
3. Alert on NTLMSSP authentication failures in bulk
4. Alert on new devices responding to LLMNR queries

---

## Key Learnings
- LLMNR poisoning requires zero privileges — just network access
- Windows machines automatically trust LLMNR responses with no verification
- NTLMv2 hashes captured this way can be cracked offline or relayed
- The attack is completely passive until the poisoned response is sent
- Disabling LLMNR via Group Policy completely eliminates this attack vector
- SMB signing prevents credential relay even if hashes are captured
- This attack is the first step in many real-world Active Directory compromises
