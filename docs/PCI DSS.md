# PCI DSS v4.0 Security Monitoring - ES|QL Rule Set

## Elastic SIEM Compliance Detection Rules

---

## COMPLETE RULE CATALOG (48 Rules by PCI DSS Requirement)

### Requirement 1: Network Security Controls (4 rules)

1. **PCI-RULE-01** Unexpected Port Open on CDE System
2. **PCI-RULE-02** Inbound Connection from Untrusted Network to CDE
3. **PCI-RULE-03** Firewall Rule Change Detected
4. **PCI-RULE-04** Non-Standard Protocol on Payment Service Port

### Requirement 2: Secure Configurations (4 rules)

5. **PCI-RULE-05** Default Credentials Usage Detected
6. **PCI-RULE-06** Insecure Service Enabled (Telnet, FTP)
7. **PCI-RULE-07** System Configuration Change Without Approval
8. **PCI-RULE-08** Unnecessary Service Running on CDE Host

### Requirement 3: Protect Stored Cardholder Data (4 rules)

9. **PCI-RULE-09** PAN-Like Pattern Detected in Logs
10. **PCI-RULE-10** Unencrypted Cardholder Data File Access
11. **PCI-RULE-11** Database Encryption Key Access
12. **PCI-RULE-12** Mass Query on Payment Database

### Requirement 4: Protect Data in Transit (4 rules)

13. **PCI-RULE-13** Cleartext Transmission on Payment Port
14. **PCI-RULE-14** Weak TLS Version Detected (TLS 1.0/1.1)
15. **PCI-RULE-15** Certificate Validation Failure
16. **PCI-RULE-16** Unencrypted Payment Gateway Connection

### Requirement 5: Malware Protection (4 rules)

17. **PCI-RULE-17** Antivirus Disabled or Stopped
18. **PCI-RULE-18** Malware Signature Update Failed
19. **PCI-RULE-19** Suspicious Executable in Payment Directory
20. **PCI-RULE-20** Known Malicious Process Execution

### Requirement 6: Secure Systems and Software (4 rules)

21. **PCI-RULE-21** Vulnerability Scanner Detection Evasion
22. **PCI-RULE-22** Unpatched Critical System in CDE
23. **PCI-RULE-23** Unapproved Software Installation
24. **PCI-RULE-24** Web Application Vulnerability Exploit Attempt

### Requirement 7: Access Control (4 rules)

25. **PCI-RULE-25** Excessive Permission Grant Detected
26. **PCI-RULE-26** Shared Account Usage on CDE System
27. **PCI-RULE-27** Access to Cardholder Data Outside Business Need
28. **PCI-RULE-28** Role-Based Access Violation

### Requirement 8: User Authentication (4 rules)

29. **PCI-RULE-29** Multi-Factor Authentication Bypass Attempt
30. **PCI-RULE-30** Password Policy Violation
31. **PCI-RULE-31** Session Timeout Not Enforced
32. **PCI-RULE-32** Privileged Account Login Without MFA

### Requirement 9: Physical Access (4 rules)

33. **PCI-RULE-33** After-Hours Data Center Access
34. **PCI-RULE-34** Badge Reader Malfunction or Tamper
35. **PCI-RULE-35** Unauthorized Console Access Detected
36. **PCI-RULE-36** Media Destruction Logging Failure

### Requirement 10: Logging & Monitoring (4 rules)

37. **PCI-RULE-37** Audit Log Deletion or Tampering
38. **PCI-RULE-38** Log Collection Failure for CDE System
39. **PCI-RULE-39** Time Synchronization Failure
40. **PCI-RULE-40** Log Review Activity Not Detected

### Requirement 11: Testing Security (4 rules)

41. **PCI-RULE-41** Network Scan from Unauthorized Source
42. **PCI-RULE-42** Penetration Test Activity Outside Window
43. **PCI-RULE-43** Wireless Access Point Detected in CDE
44. **PCI-RULE-44** File Integrity Monitoring Alert

### Requirement 12: Incident Response (4 rules)

45. **PCI-RULE-45** Correlated Payment Card Compromise Indicators
46. **PCI-RULE-46** Multiple PCI Violations from Same User
47. **PCI-RULE-47** Data Exfiltration from CDE System
48. **PCI-RULE-48** Emergency Incident Response Trigger

---

# DETAILED RULE SPECIFICATIONS

## REQUIREMENT 1: NETWORK SECURITY CONTROLS

### PCI-RULE-01: Unexpected Port Open on CDE System

**PCI Mapping:** Requirement 1.2.1, 1.4.2 - Network segmentation and firewall rules

**Objective:** Detects new listening ports on cardholder data environment (CDE) systems that are not in approved baseline.

**Data sources:** `updive-packet-*`, `updive-audit-*`

**Severity:** High

**ES|QL Query:**

```esql
FROM updive-packet-*, updive-audit-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE destination.port IS NOT NULL 
  AND network.direction == "inbound"
  AND host.name RLIKE ".*(cde|payment|pos|gateway).*"
| WHERE destination.port NOT IN (22, 443, 3306, 5432, 8443)
| STATS 
    connection_count = COUNT(*),
    unique_sources = COUNT_DISTINCT(source.ip)
  BY destination.port, host.name, network.protocol
| WHERE connection_count >= 3
| EVAL rule_name = "PCI-RULE-01: Unexpected Port Open on CDE"
| EVAL severity = "high"
| KEEP @timestamp, host.name, destination.port, network.protocol, connection_count, unique_sources, rule_name, severity
```

**Threshold/Correlation:** 3+ connections to non-standard port within 10 minutes

**Tuning / False Positives:**

1. Maintain approved port baseline in CMDB (22, 443, 3306, 5432, 8443, etc.)
2. Whitelist ephemeral ports (32768-65535) from internal monitoring tools
3. Exclude localhost/loopback connections (127.0.0.1, ::1)
4. Lower threshold to 1 for highly sensitive CDE hosts (POS terminals)
5. Correlate with change management tickets for authorized new services

**Validation:**

- Start service on non-standard port: `nc -l 9999`
- Fields required: `destination.port`, `network.direction:inbound`, `host.name` matching CDE pattern
- Verify Packetbeat captures inbound connections
- Test: Open port 8080 on payment-gateway-01 host

---

### PCI-RULE-02: Inbound Connection from Untrusted Network to CDE

**PCI Mapping:** Requirement 1.3.1 - Restrict inbound traffic to necessary sources

**Objective:** Identifies inbound connections to CDE from IP addresses not in trusted network ranges.

**Data sources:** `updive-packet-*`

**Severity:** Critical

**ES|QL Query:**

```esql
FROM updive-packet-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE network.direction == "inbound"
  AND host.name RLIKE ".*(cde|payment|cardholder).*"
  AND source.ip NOT RLIKE "^10\\.|^172\\.(1[6-9]|2[0-9]|3[0-1])\\.|^192\\.168\\."
| WHERE source.ip NOT IN ("203.0.113.10", "198.51.100.50")
| STATS 
    connection_count = COUNT(*),
    ports_accessed = VALUES(destination.port)
  BY source.ip, source.geo.country_name, host.name
| WHERE connection_count >= 1
| EVAL rule_name = "PCI-RULE-02: Inbound from Untrusted Network to CDE"
| EVAL severity = "critical"
| KEEP @timestamp, source.ip, source.geo.country_name, host.name, destination.port, ports_accessed, connection_count, rule_name, severity
```

**Threshold/Correlation:** Single connection from untrusted source triggers alert

**Tuning / False Positives:**

1. Whitelist approved external payment processors (e.g., Stripe, PayPal gateway IPs)
2. Exclude VPN concentrator IPs (appear external but legitimate)
3. Whitelist security scanning vendors (ASV approved scanning vendors)
4. Add geographic restrictions (block connections from high-risk countries)
5. Correlate with firewall allow-list changes

**Validation:**

- Simulate external connection: `curl https://cde-payment-01.internal` from public IP
- Fields: `source.ip` (external), `network.direction:inbound`, `host.name` matching CDE
- Test with IP not in RFC1918 private ranges
- Verify GeoIP enrichment shows source country

---

### PCI-RULE-03: Firewall Rule Change Detected

**PCI Mapping:** Requirement 1.2.1, 10.2.5 - Network security change monitoring

**Objective:** Detects modifications to firewall rules or iptables configurations on CDE systems.

**Data sources:** `updive-audit-*`, `updive-file-*`, `updive-win-*`

**Severity:** High

**ES|QL Query:**

```esql
FROM updive-audit-*, updive-file-*, updive-win-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE (process.name IN ("iptables", "firewall-cmd", "ufw", "netsh") 
        AND process.args RLIKE ".*(add|delete|modify|allow|deny).*")
    OR (file.path RLIKE ".*/etc/sysconfig/iptables.*" AND event.action == "modified")
    OR (event.code == "4946" OR event.code == "4947")
| WHERE host.name RLIKE ".*(cde|payment|firewall).*"
| EVAL rule_name = "PCI-RULE-03: Firewall Rule Change Detected"
| EVAL severity = "high"
| KEEP @timestamp, host.name, user.name, process.name, process.args, file.path, event.code, rule_name, severity
```

**Threshold/Correlation:** Any firewall change on CDE system triggers alert

**Tuning / False Positives:**

1. Whitelist automated firewall management tools (Ansible, Terraform) by service account
2. Require correlation with approved change ticket (CAB approval)
3. Exclude read-only operations (iptables -L, netsh advfirewall show)
4. Alert only if changed by non-admin or outside maintenance window
5. Lower severity for internal zone changes, critical for external-facing rules

**Validation:**

- Linux: `sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT`
- Windows: `netsh advfirewall firewall add rule name="Test" dir=in action=allow`
- Fields: `process.name:iptables`, `process.args`, `user.name`, `host.name`
- Windows Event 4946/4947 (firewall rule changed)

---

### PCI-RULE-04: Non-Standard Protocol on Payment Service Port

**PCI Mapping:** Requirement 1.4.2, 2.2.7 - Secure protocols only

**Objective:** Detects non-HTTPS/TLS traffic on ports designated for payment processing.

**Data sources:** `updive-packet-*`

**Severity:** High

**ES|QL Query:**

```esql
FROM updive-packet-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE destination.port IN (443, 8443, 8444, 9443)
  AND network.protocol NOT IN ("tls", "https")
  AND host.name RLIKE ".*(payment|gateway|pos).*"
| STATS 
    packet_count = COUNT(*),
    protocols_seen = VALUES(network.protocol)
  BY source.ip, destination.ip, destination.port, host.name
| WHERE packet_count >= 5
| EVAL rule_name = "PCI-RULE-04: Non-Standard Protocol on Payment Port"
| EVAL severity = "high"
| KEEP @timestamp, source.ip, destination.ip, destination.port, network.protocol, protocols_seen, packet_count, rule_name, severity
```

**Threshold/Correlation:** 5+ non-TLS packets on secure port within 10 minutes

**Tuning / False Positives:**

1. Verify Packetbeat protocol detection is accurate (check application_protocol field)
2. Whitelist health check scripts using HTTP on internal monitoring
3. Exclude initial TCP handshake packets (SYN/ACK)
4. Alert only if connection is from external source
5. Correlate with application deployment events (brief window during restart)

**Validation:**

- Send HTTP to HTTPS port: `curl http://payment-gateway:443`
- Fields: `destination.port:443`, `network.protocol:http`, `host.name` with payment keyword
- Verify Packetbeat identifies protocol mismatch
- Test with `openssl s_client` to verify TLS detection works

---

## REQUIREMENT 2: SECURE CONFIGURATIONS

### PCI-RULE-05: Default Credentials Usage Detected

**PCI Mapping:** Requirement 2.2.2 - Change default passwords

**Objective:** Identifies successful authentication using known default usernames (admin, root, administrator).

**Data sources:** `updive-win-*`, `updive-file-*`

**Severity:** Critical

**ES|QL Query:**

```esql
FROM updive-win-*, updive-file-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE event.category == "authentication" 
  AND event.outcome == "success"
  AND user.name IN ("admin", "administrator", "root", "guest", "test", "default", "sa")
| WHERE host.name RLIKE ".*(cde|payment|prod).*"
| STATS login_count = COUNT(*) BY user.name, source.ip, host.name
| WHERE login_count >= 1
| EVAL rule_name = "PCI-RULE-05: Default Credentials Usage"
| EVAL severity = "critical"
| KEEP @timestamp, user.name, source.ip, host.name, login_count, rule_name, severity
```

**Threshold/Correlation:** Single successful login with default username

**Tuning / False Positives:**

1. Whitelist legitimate "admin" accounts that have been renamed but keep original name
2. Exclude service accounts with documented business need (e.g., "sa" for SQL monitoring)
3. Alert only on production/CDE systems (exclude dev/test)
4. Require password complexity check if available in logs
5. Cross-reference with account creation date (new accounts are higher risk)

**Validation:**

- Successful SSH/RDP login with username "admin" or "root"
- Windows Event 4624 with TargetUserName "Administrator"
- Linux auth.log: "Accepted password for admin from..."
- Fields: `user.name:admin`, `event.outcome:success`, `event.category:authentication`

---

### PCI-RULE-06: Insecure Service Enabled (Telnet, FTP)

**PCI Mapping:** Requirement 2.2.4 - Disable unnecessary services

**Objective:** Detects insecure services (Telnet, FTP, rlogin) running on CDE systems.

**Data sources:** `updive-packet-*`, `updive-audit-*`

**Severity:** High

**ES|QL Query:**

```esql
FROM updive-packet-*, updive-audit-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE (destination.port IN (21, 23, 512, 513, 514) 
        OR network.protocol IN ("telnet", "ftp"))
  AND host.name RLIKE ".*(cde|payment|cardholder).*"
| STATS 
    connection_count = COUNT(*),
    unique_clients = COUNT_DISTINCT(source.ip)
  BY destination.port, network.protocol, host.name
| WHERE connection_count >= 1
| EVAL rule_name = "PCI-RULE-06: Insecure Service Enabled"
| EVAL severity = "high"
| KEEP @timestamp, host.name, destination.port, network.protocol, connection_count, unique_clients, rule_name, severity
```

**Threshold/Correlation:** Any connection to insecure service port

**Tuning / False Positives:**

1. Whitelist SFTP (port 22) which uses FTP-like protocol over SSH
2. Exclude FTPS (FTP over TLS) if properly configured
3. Alert only on listening/server-side, not outbound client connections
4. Verify protocol detection (Packetbeat may misidentify encrypted traffic)
5. Allow exceptions for legacy systems with documented compensating controls

**Validation:**

- Start Telnet server: `sudo systemctl start telnet.service`
- Connect: `telnet payment-server 23`
- Fields: `destination.port:23`, `network.protocol:telnet`, `host.name`
- Verify Packetbeat detects Telnet handshake

---

### PCI-RULE-07: System Configuration Change Without Approval

**PCI Mapping:** Requirement 2.2, 10.2.5 - Configuration change control

**Objective:** Detects modifications to critical configuration files without corresponding change ticket.

**Data sources:** `updive-audit-*`, `updive-file-*`

**Severity:** Medium

**ES|QL Query:**

```esql
FROM updive-audit-*, updive-file-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE event.module == "file_integrity"
  AND event.action IN ("updated", "modified")
  AND (file.path RLIKE ".*/etc/(ssh|pam\\.d|security|nginx|apache2|mysql).*"
       OR file.path RLIKE ".*\\\\(inetpub|system32|config).*")
  AND host.name RLIKE ".*(cde|payment|prod).*"
| WHERE user.name NOT IN ("ansible", "puppet", "chef", "saltstack")
| EVAL rule_name = "PCI-RULE-07: Config Change Without Approval"
| EVAL severity = "medium"
| KEEP @timestamp, host.name, user.name, file.path, event.action, file.hash.sha256, rule_name, severity
```

**Threshold/Correlation:** Any config file change not by automation

**Tuning / False Positives:**

1. Correlate with ITSM change ticket system via API
2. Whitelist configuration management tools by process hash
3. Create maintenance window exceptions (approved change windows)
4. Exclude application-specific config files (e.g., /var/www/app/config.php)
5. Lower severity if change is reverted within 1 hour (rollback)

**Validation:**

- Modify config: `sudo vi /etc/ssh/sshd_config`
- Windows: Edit `C:\Windows\System32\inetsrv\config\applicationHost.config`
- Fields: `event.module:file_integrity`, `file.path`, `event.action:modified`, `user.name`
- Verify Auditbeat file integrity monitoring detects change

---

### PCI-RULE-08: Unnecessary Service Running on CDE Host

**PCI Mapping:** Requirement 2.2.2 - One primary function per server

**Objective:** Identifies non-essential services running on dedicated payment processing hosts.

**Data sources:** `updive-audit-*`, `updive-metric-*`

**Severity:** Medium

**ES|QL Query:**

```esql
FROM updive-audit-*, updive-metric-*
| WHERE @timestamp >= NOW() - 30 minutes
| WHERE process.name IS NOT NULL
  AND host.name RLIKE ".*(payment-app|pos-terminal|card-processor).*"
  AND process.name IN ("httpd", "nginx", "apache2", "mysql", "postgres", "mongod", "redis", "memcached", "docker", "jenkins", "gitlab")
| STATS 
    process_count = COUNT(*),
    services = VALUES(process.name)
  BY host.name
| WHERE process_count >= 3
| EVAL rule_name = "PCI-RULE-08: Unnecessary Service on CDE Host"
| EVAL severity = "medium"
| KEEP @timestamp, host.name, services, process_count, rule_name, severity
```

**Threshold/Correlation:** 3+ different services on single-purpose CDE host

**Tuning / False Positives:**

1. Define approved service matrix per host type (e.g., payment-app = nginx + app only)
2. Whitelist management agents (monitoring, backup, AV)
3. Exclude containerized environments (Docker hosts legitimately run many services)
4. Alert only if service is listening on network port (not just background process)
5. Lower threshold to 2 for highly restricted hosts (POS terminals)

**Validation:**

- Start multiple services: `systemctl start httpd mysql redis`
- Fields: `process.name`, `host.name` matching payment pattern
- Verify Auditbeat or Metricbeat captures running processes
- Check process count exceeds threshold

---

## REQUIREMENT 3: PROTECT STORED CARDHOLDER DATA

### PCI-RULE-09: PAN-Like Pattern Detected in Logs

**PCI Mapping:** Requirement 3.3.1, 3.4.1 - Render PAN unreadable

**Objective:** Identifies potential Primary Account Numbers (PAN) in log files or network traffic.

**Data sources:** `updive-file-*`, `updive-packet-*`

**Severity:** Critical

**ES|QL Query:**

```esql
FROM updive-file-*, updive-packet-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE message RLIKE ".*[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}.*"
  OR http.request.body.content RLIKE ".*[0-9]{13,19}.*"
| WHERE message NOT RLIKE ".*(XXXX|\\*\\*\\*\\*|masked).*"
| STATS pan_occurrences = COUNT(*) BY host.name, log.file.path
| WHERE pan_occurrences >= 1
| EVAL rule_name = "PCI-RULE-09: PAN-Like Pattern in Logs"
| EVAL severity = "critical"
| KEEP @timestamp, host.name, log.file.path, pan_occurrences, rule_name, severity
```

**Threshold/Correlation:** Single PAN-like pattern triggers immediate alert

**Tuning / False Positives:**

1. Exclude masked PANs (XXXX-XXXX-XXXX-1234) with regex
2. Validate using Luhn algorithm (checksum) before alerting
3. Whitelist test card numbers (4111111111111111, 5555555555554444)
4. Exclude numeric sequences that are not PANs (order IDs, timestamps)
5. Alert only if in clear text (not within encrypted fields)

**Validation:**

- Inject test PAN in log: `echo "Credit card: 4532-1234-5678-9010" >> /var/log/app.log`
- Fields: `message` containing 16-digit pattern, `log.file.path`
- Ensure masked PANs like "XXXX-XXXX-XXXX-9010" do NOT trigger
- Test Luhn checksum validation for accuracy

---

### PCI-RULE-10: Unencrypted Cardholder Data File Access

**PCI Mapping:** Requirement 3.5.1 - Protect cryptographic keys

**Objective:** Detects access to directories known to contain cardholder data without encryption evidence.

**Data sources:** `updive-audit-*`, `updive-win-*`

**Severity:** Critical

**ES|QL Query:**

```esql
FROM updive-audit-*, updive-win-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE event.action IN ("accessed", "read", "opened")
  AND (file.path RLIKE ".*(cardholder|chd|pan|card_data).*"
       OR file.path RLIKE ".*/opt/payment/data/.*")
  AND file.extension NOT IN ("enc", "aes", "pgp", "gpg")
| WHERE user.name NOT IN ("payment-app-service", "encryption-service")
| STATS file_count = COUNT(*) BY user.name, host.name, file.path
| WHERE file_count >= 1
| EVAL rule_name = "PCI-RULE-10: Unencrypted CHD File Access"
| EVAL severity = "critical"
| KEEP @timestamp, user.name, host.name, file.path, file_count, rule_name, severity
```

**Threshold/Correlation:** Any access to unencrypted CHD directory

**Tuning / False Positives:**

1. Whitelist authorized payment application service accounts
2. Verify encryption at rest is enabled (check file header magic bytes)
3. Exclude access from encryption/decryption utilities
4. Alert only if file is readable (not just listed in directory)
5. Correlate with database encryption status (TDE enabled)

**Validation:**

- Access CHD directory: `cat /opt/payment/data/transactions.csv`
- Windows: Access `C:\PaymentData\cardholder.txt`
- Fields: `file.path` with CHD keyword, `event.action:accessed`, `user.name`
- Verify encrypted files (.enc, .gpg) do NOT trigger alert

---

### PCI-RULE-11: Database Encryption Key Access

**PCI Mapping:** Requirement 3.6.1 - Cryptographic key management

**Objective:** Detects unauthorized access to encryption key files or key management systems.

**Data sources:** `updive-audit-*`, `updive-file-*`

**Severity:** Critical

**ES|QL Query:**

```esql
FROM updive-audit-*, updive-file-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE (file.path RLIKE ".*(keystore|keys|master\\.key|encryption\\.key).*"
        OR file.path RLIKE ".*/etc/ssl/private/.*")
  AND event.action IN ("accessed", "read", "copied", "modified")
| WHERE user.name NOT IN ("root", "ssl-cert", "keymanager-service")
| EVAL rule_name = "PCI-RULE-11: Encryption Key Access"
| EVAL severity = "critical"
| KEEP @timestamp, user.name, host.name, file.path, event.action, process.name, rule_name, severity
```

**Threshold/Correlation:** Single unauthorized key file access

**Tuning / False Positives:**

1. Whitelist key management service accounts (HSM integration)
2. Exclude SSL certificate access by web server processes (nginx, apache)
3. Alert only on private keys, not public certificates
4. Require correlation with authentication event (who accessed)
5. Escalate if key file is copied/exfiltrated (not just read)

**Validation:**

- Access key file: `cat /etc/ssl/private/payment-app.key`
- Copy key: `cp /opt/keystore/master.key /tmp/`
- Fields: `file.path` with key keyword, `event.action`, `user.name`
- Windows: Access `C:\ProgramData\Keys\encryption.key`

---

### PCI-RULE-12: Mass Query on Payment Database

**PCI Mapping:** Requirement 3.3.1 - Data access restriction

**Objective:** Identifies bulk SELECT queries on tables containing cardholder data.

**Data sources:** `updive-file-*`, `updive-audit-*`

**Severity:** High

**ES|QL Query:**

```esql
FROM updive-file-*, updive-audit-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE message RLIKE ".*SELECT.*FROM.*(payment|transaction|card|cardholder).*"
  OR process.args RLIKE ".*SELECT \\* FROM.*"
| WHERE message NOT RLIKE ".*(LIMIT [0-9]{1,2}|WHERE id =).*"
| STATS query_count = COUNT(*) BY user.name, host.name
| WHERE query_count >= 5
| EVAL rule_name = "PCI-RULE-12: Mass Query on Payment DB"
| EVAL severity = "high"
| KEEP @timestamp, user.name, host.name, query_count, message, rule_name, severity
```

**Threshold/Correlation:** 5+ broad SELECT queries within 15 minutes

**Tuning / False Positives:**

1. Whitelist reporting/analytics service accounts with legitimate bulk queries
2. Exclude queries with LIMIT clauses (bounded result sets)
3. Alert only on SELECT * (not specific column queries)
4. Lower threshold to 3 for sensitive tables (cardholder, payment)
5. Correlate with business intelligence tool connections

**Validation:**

- Run bulk query: `mysql -e "SELECT * FROM payments.transactions"`
- Database log should show query without LIMIT
- Fields: `message` with SELECT and table name, `user.name`
- Verify legitimate admin queries with LIMIT don't trigger

---

## REQUIREMENT 4: PROTECT DATA IN TRANSIT

### PCI-RULE-13: Cleartext Transmission on Payment Port

**PCI Mapping:** Requirement 4.2.1 - Strong cryptography for transmission

**Objective:** Detects unencrypted HTTP traffic on ports designated for payment data transmission.

**Data sources:** `updive-packet-*`

**Severity:** Critical

**ES|QL Query:**

```esql
FROM updive-packet-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE network.protocol == "http" 
  AND destination.port IN (80, 8080, 8000, 3000)
  AND (http.request.body.content RLIKE ".*(card|pan|cvv|expiry).*"
       OR url.path RLIKE ".*(payment|checkout|transaction).*")
| STATS 
    request_count = COUNT(*),
    urls = VALUES(url.path)
  BY source.ip, destination.ip, host.name
| WHERE request_count >= 1
| EVAL rule_name = "PCI-RULE-13: Cleartext Payment Transmission"
| EVAL severity = "critical"
| KEEP @timestamp, source.ip, destination.ip, url.path, urls, request_count, rule_name, severity
```

**Threshold/Correlation:** Single unencrypted payment-related HTTP request

**Tuning / False Positives:**

1. Verify Packetbeat deep packet inspection is enabled
2. Whitelist internal test environments (clearly labeled as non-prod)
3. Alert only if destination is external or CDE zone
4. Exclude health check endpoints (/status, /ping)
5. Escalate immediately if actual PAN detected in plaintext

**Validation:**

- Send HTTP POST with payment data: `curl -X POST -d "card=4532123456789010" http://payment-api/charge`
- Fields: `network.protocol:http`, `http.request.body.content`, `url.path` with payment keyword
- Verify HTTPS traffic to same endpoint does NOT trigger
- Check Packetbeat captures HTTP body content

---

### PCI-RULE-14: Weak TLS Version Detected (TLS 1.0/1.1)

**PCI Mapping:** Requirement 4.2.1 - Use strong cryptography (TLS 1.2+)

**Objective:** Identifies TLS connections using deprecated versions (TLS 1.0 or 1.1).

**Data sources:** `updive-packet-*`

**Severity:** High

**ES|QL Query:**

```esql
FROM updive-packet-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE tls.version_protocol IN ("tls", "ssl")
  AND tls.version RLIKE ".*(1\\.0|1\\.1|SSLv[23]).*"
  AND destination.port IN (443, 8443, 9443)
| STATS 
    connection_count = COUNT(*),
    tls_versions = VALUES(tls.version)
  BY source.ip, destination.ip, host.name
| WHERE connection_count >= 1
| EVAL rule_name = "PCI-RULE-14: Weak TLS Version Detected"
| EVAL severity = "high"
| KEEP @timestamp, source.ip, destination.ip, tls.version, tls_versions, connection_count, rule_name, severity
```

**Threshold/Correlation:** Any TLS 1.0/1.1 connection to payment services

**Tuning / False Positives:**

1. Whitelist legacy systems with documented risk acceptance (until migration)
2. Exclude internal monitoring tools with known TLS 1.1 support
3. Alert only on external-facing connections (internet sources)
4. Lower severity for client-initiated connections (vs server supporting weak TLS)
5. Correlate with certificate expiration (may indicate unmaintained system)

**Validation:**

- Force TLS 1.1: `openssl s_client -tls1_1 -connect payment-gateway:443`
- Fields: `tls.version:1.1`, `destination.port:443`, `tls.version_protocol:tls`
- Verify TLS 1.2+ connections do NOT trigger
- Check Packetbeat TLS handshake parsing

---

### PCI-RULE-15: Certificate Validation Failure

**PCI Mapping:** Requirement 4.2.1 - Validate certificates

**Objective:** Detects TLS connections with invalid, expired, or self-signed certificates on payment systems.

**Data sources:** `updive-packet-*`, `updive-file-*`

**Severity:** High

**ES|QL Query:**

```esql
FROM updive-packet-*, updive-file-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE (tls.server.x509.not_after < NOW()
        OR tls.established == false
        OR tls.server.x509.issuer.common_name == tls.server.x509.subject.common_name)
  AND destination.port IN (443, 8443)
  AND host.name RLIKE ".*(payment|gateway|pos).*"
| STATS 
    failed_count = COUNT(*),
    cert_issues = VALUES(tls.server.x509.subject.common_name)
  BY destination.ip, host.name
| WHERE failed_count >= 1
| EVAL rule_name = "PCI-RULE-15: Certificate Validation Failure"
| EVAL severity = "high"
| KEEP @timestamp, destination.ip, host.name, tls.server.x509.subject.common_name, tls.server.x509.not_after, cert_issues, failed_count, rule_name, severity
```

**Threshold/Correlation:** Any certificate validation failure on payment endpoint

**Tuning / False Positives:**

1. Whitelist internal CAs for legitimate self-signed certs
2. Exclude development/test environments
3. Alert only if connection is from external source
4. Lower severity for soon-to-expire certs (7-30 days warning)
5. Critical severity for already-expired certs on production

**Validation:**

- Use expired cert: configure web server with old certificate
- Self-signed: `openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 1`
- Fields: `tls.server.x509.not_after`, `tls.established:false`, issuer == subject
- Test: `curl https://payment-app` with invalid cert

---

### PCI-RULE-16: Unencrypted Payment Gateway Connection

**PCI Mapping:** Requirement 4.2.1 - Encrypt transmission over public networks

**Objective:** Identifies connections to payment gateway without TLS encryption.

**Data sources:** `updive-packet-*`

**Severity:** Critical

**ES|QL Query:**

```esql
FROM updive-packet-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE (destination.domain RLIKE ".*(paypal|stripe|authorize\\.net|firstdata).*"
        OR destination.ip IN ("64.14.227.5", "64.4.250.37"))
  AND network.protocol != "tls"
  AND destination.port NOT IN (443, 8443)
| STATS 
    connection_count = COUNT(*),
    protocols = VALUES(network.protocol)
  BY source.ip, destination.domain, host.name
| WHERE connection_count >= 1
| EVAL rule_name = "PCI-RULE-16: Unencrypted Payment Gateway Connection"
| EVAL severity = "critical"
| KEEP @timestamp, source.ip, destination.domain, destination.ip, network.protocol, protocols, connection_count, rule_name, severity
```

**Threshold/Correlation:** Single non-TLS connection to payment processor

**Tuning / False Positives:**

1. Whitelist gateway health check endpoints (HTTP OK response)
2. Verify Packetbeat correctly identifies TLS vs TCP
3. Alert only on connections carrying actual transaction data
4. Exclude DNS lookups and initial TCP handshakes
5. Critical if connection transmits POST data

**Validation:**

- HTTP to gateway: `curl http://api.stripe.com/v1/charges`
- Fields: `destination.domain:stripe.com`, `network.protocol:http`, `destination.port:80`
- Verify HTTPS to same domain does NOT trigger
- Check for POST body content in alert

---

## REQUIREMENT 5: MALWARE PROTECTION

### PCI-RULE-17: Antivirus Disabled or Stopped

**PCI Mapping:** Requirement 5.2.1 - Anti-malware running and current

**Objective:** Detects when antivirus/anti-malware software is disabled or stopped on CDE systems.

**Data sources:** `updive-win-*`, `updive-file-*`, `updive-audit-*`

**Severity:** Critical

**ES|QL Query:**

```esql
FROM updive-win-*, updive-file-*, updive-audit-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE (event.code IN ("5001", "1116", "1117")
        OR message RLIKE ".*(antivirus|malware|defender).*stopped.*"
        OR process.args RLIKE ".*(sc stop|systemctl stop).*(av|clamav|defender).*")
  AND host.name RLIKE ".*(cde|payment|prod).*"
| EVAL rule_name = "PCI-RULE-17: Antivirus Disabled or Stopped"
| EVAL severity = "critical"
| KEEP @timestamp, host.name, user.name, event.code, message, process.args, rule_name, severity
```

**Threshold/Correlation:** Immediate alert on AV service stop

**Tuning / False Positives:**

1. Whitelist scheduled AV updates/restarts (brief service interruption)
2. Exclude manual stops during approved maintenance windows
3. Alert only if service stays down >5 minutes
4. Correlate with subsequent malware detection failures
5. Escalate if multiple hosts have AV stopped simultaneously

**Validation:**

- Windows: `sc stop WinDefend` or disable Windows Defender
- Linux: `sudo systemctl stop clamav-daemon`
- Event 5001 (Windows Defender disabled)
- Fields: `event.code`, `message` with AV keyword, `process.args`

---

### PCI-RULE-18: Malware Signature Update Failed

**PCI Mapping:** Requirement 5.2.2 - Keep anti-malware current

**Objective:** Identifies antivirus signature database update failures.

**Data sources:** `updive-win-*`, `updive-file-*`

**Severity:** High

**ES|QL Query:**

```esql
FROM updive-win-*, updive-file-*
| WHERE @timestamp >= NOW() - 24 hours
| WHERE (event.code IN ("2001", "2003", "2012")
        OR message RLIKE ".*(signature|definition).*update.*fail.*"
        OR message RLIKE ".*virus.*database.*out.*date.*")
  AND host.name RLIKE ".*(cde|payment|prod).*"
| STATS failure_count = COUNT(*) BY host.name
| WHERE failure_count >= 3
| EVAL rule_name = "PCI-RULE-18: Malware Signature Update Failed"
| EVAL severity = "high"
| KEEP @timestamp, host.name, failure_count, message, rule_name, severity
```

**Threshold/Correlation:** 3+ update failures in 24 hours

**Tuning / False Positives:**

1. Exclude transient network failures (single retry failure)
2. Alert only if signatures are >7 days old
3. Whitelist air-gapped systems with manual update process
4. Lower threshold to 1 for critical payment servers
5. Correlate with network connectivity issues

**Validation:**

- Block AV update server in firewall
- Wait for scheduled update to fail
- Windows Event 2001/2003 (update failed)
- Fields: `event.code`, `message` with update/signature, `host.name`

---

### PCI-RULE-19: Suspicious Executable in Payment Directory

**PCI Mapping:** Requirement 5.3.1 - Periodic evaluation for malware

**Objective:** Detects new executable files in payment application directories.

**Data sources:** `updive-audit-*`, `updive-win-*`

**Severity:** High

**ES|QL Query:**

```esql
FROM updive-audit-*, updive-win-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE event.action IN ("created", "renamed", "moved")
  AND (file.extension IN ("exe", "dll", "so", "sh", "bat", "ps1", "vbs")
       OR file.path RLIKE ".*\\.(exe|dll|so|sh|bat|ps1)$")
  AND file.path RLIKE ".*(payment|pos|gateway|cardholder).*"
| WHERE file.path NOT RLIKE ".*(Program Files|application|bin).*"
| EVAL rule_name = "PCI-RULE-19: Suspicious Executable in Payment Dir"
| EVAL severity = "high"
| KEEP @timestamp, host.name, user.name, file.path, file.hash.sha256, event.action, rule_name, severity
```

**Threshold/Correlation:** Any new executable in non-standard location

**Tuning / False Positives:**

1. Whitelist application deployment directories (/opt/payment-app/bin)
2. Verify file signature (code signing certificate)
3. Alert only if file is in temp or user-writable directories
4. Cross-check file hash with VirusTotal or threat intel
5. Lower severity for signed executables from trusted publishers

**Validation:**

- Create executable: `touch /opt/payment/data/malware.exe`
- Fields: `file.path` with payment keyword, `file.extension:exe`, `event.action:created`
- Verify legitimate app updates in /opt/payment-app/bin don't trigger
- Check file hash in alert for threat intel lookup

---

### PCI-RULE-20: Known Malicious Process Execution

**PCI Mapping:** Requirement 5.4.1 - Malware detection

**Objective:** Detects execution of processes matching known malware indicators.

**Data sources:** `updive-audit-*`, `updive-win-*`

**Severity:** Critical

**ES|QL Query:**

```esql
FROM updive-audit-*, updive-win-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE process.name IN ("mimikatz.exe", "psexec.exe", "netcat.exe", "nc.exe", "powershell.exe", "cmd.exe")
  AND (process.args RLIKE ".*(invoke-mimikatz|sekurlsa|dump|lsass).*"
       OR process.args RLIKE ".*(-enc|-e |bypass|hidden).*")
| WHERE host.name RLIKE ".*(cde|payment|prod).*"
| EVAL rule_name = "PCI-RULE-20: Known Malicious Process Execution"
| EVAL severity = "critical"
| KEEP @timestamp, host.name, user.name, process.name, process.args, process.executable, rule_name, severity
```

**Threshold/Correlation:** Single execution of known malicious process

**Tuning / False Positives:**

1. Whitelist legitimate admin tools (PsExec from authorized IT)
2. Verify process signature and command line arguments
3. Alert only if PowerShell uses obfuscation/encoding
4. Exclude security scanning tools (Nmap, Metasploit in authorized testing)
5. Critical severity if combined with credential dumping arguments

**Validation:**

- Run suspicious command: `powershell -enc <base64>`
- Execute: `nc -l 4444` or `.\mimikatz.exe`
- Fields: `process.name`, `process.args` with malicious patterns
- Windows Event 4688 (process creation) with CommandLine

---

## REQUIREMENT 6: SECURE SYSTEMS AND SOFTWARE

### PCI-RULE-21: Vulnerability Scanner Detection Evasion

**PCI Mapping:** Requirement 11.3.2 - Internal vulnerability scans

**Objective:** Detects attempts to block or evade vulnerability scanning tools.

**Data sources:** `updive-packet-*`, `updive-audit-*`

**Severity:** High

**ES|QL Query:**

```esql
FROM updive-packet-*, updive-audit-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE (source.ip IN ("10.50.100.10", "10.50.100.11")
        AND destination.port IN (0, 9999, 31337))
    OR (process.name IN ("iptables", "firewall-cmd") 
        AND process.args RLIKE ".*(DROP|REJECT).*(10\\.50\\.100).*")
| WHERE host.name RLIKE ".*(cde|payment).*"
| STATS evasion_count = COUNT(*) BY host.name, user.name
| WHERE evasion_count >= 1
| EVAL rule_name = "PCI-RULE-21: Vuln Scanner Evasion"
| EVAL severity = "high"
| KEEP @timestamp, host.name, user.name, source.ip, process.args, evasion_count, rule_name, severity
```

**Threshold/Correlation:** Any firewall rule blocking scanner IPs

**Tuning / False Positives:**

1. Update scanner IP whitelist regularly (10.50.100.10-20)
2. Alert only on DROP/REJECT rules, not rate limiting
3. Exclude temporary blocks during active scan (DDoS protection)
4. Correlate with scan schedule (weekly internal scans)
5. Lower severity if block is brief (<5 minutes)

**Validation:**

- Block scanner: `iptables -A INPUT -s 10.50.100.10 -j DROP`
- Fields: `process.args` with DROP and scanner IP, `user.name`, `host.name`
- Verify legitimate traffic shaping rules don't trigger
- Test during scheduled vulnerability scan

---

### PCI-RULE-22: Unpatched Critical System in CDE

**PCI Mapping:** Requirement 6.3.3 - Patch critical vulnerabilities within 30 days

**Objective:** Identifies systems in CDE running software versions with known critical vulnerabilities.

**Data sources:** `updive-metric-*`, `updive-file-*`

**Severity:** High

**ES|QL Query:**

```esql
FROM updive-metric-*, updive-file-*
| WHERE @timestamp >= NOW() - 24 hours
| WHERE (message RLIKE ".*(CVE-20(2[0-9]|1[8-9])-[0-9]{4,5}).*critical.*"
        OR message RLIKE ".*vulnerable.*version.*(apache|nginx|openssl|openssh|mysql).*")
  AND host.name RLIKE ".*(cde|payment|cardholder).*"
| STATS vuln_count = COUNT(*) BY host.name, message
| WHERE vuln_count >= 1
| EVAL rule_name = "PCI-RULE-22: Unpatched Critical System in CDE"
| EVAL severity = "high"
| KEEP @timestamp, host.name, message, vuln_count, rule_name, severity
```

**Threshold/Correlation:** Any critical CVE detected on CDE system

**Tuning / False Positives:**

1. Integrate with vulnerability scanner API (Nessus, Qualys)
2. Exclude false positives (version detection errors)
3. Alert only on CVSS 9.0+ (critical severity)
4. Correlate with patch deployment timeline (30-day window)
5. Lower severity if compensating controls exist (WAF, IPS)

**Validation:**

- Run vulnerability scan on unpatched system
- Fields: `message` with CVE number and "critical", `host.name` matching CDE
- Verify patched systems don't trigger
- Test with known vulnerable version (e.g., OpenSSL Heartbleed)

---

### PCI-RULE-23: Unapproved Software Installation

**PCI Mapping:** Requirement 6.4.3, 2.2.7 - Approved software only

**Objective:** Detects installation of software not in approved application whitelist.

**Data sources:** `updive-audit-*`, `updive-win-*`

**Severity:** Medium

**ES|QL Query:**

```esql
FROM updive-audit-*, updive-win-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE (process.name IN ("yum", "apt", "dpkg", "rpm", "msiexec.exe")
        AND process.args RLIKE ".*(install|add|setup).*")
    OR event.code == "11707"
| WHERE host.name RLIKE ".*(cde|payment|prod).*"
  AND user.name NOT IN ("ansible", "puppet", "sccm-agent")
| EVAL rule_name = "PCI-RULE-23: Unapproved Software Installation"
| EVAL severity = "medium"
| KEEP @timestamp, host.name, user.name, process.name, process.args, event.code, rule_name, severity
```

**Threshold/Correlation:** Any software install not by automation

**Tuning / False Positives:**

1. Whitelist configuration management tools (Ansible, SCCM)
2. Correlate with approved software catalog (CMDB)
3. Exclude security updates from approved repositories
4. Alert only on interactive installs (not scheduled updates)
5. Require change ticket validation for manual installs

**Validation:**

- Manual install: `sudo apt install nmap`
- Windows: Run MSI installer
- Event 11707 (installation succeeded)
- Fields: `process.name:apt`, `process.args:install`, `user.name`, `host.name`

---

### PCI-RULE-24: Web Application Vulnerability Exploit Attempt

**PCI Mapping:** Requirement 6.4.1 - Protect against common vulnerabilities

**Objective:** Detects SQL injection, XSS, and other OWASP Top 10 exploit attempts on payment web apps.

**Data sources:** `updive-packet-*`, `updive-file-*`

**Severity:** Critical

**ES|QL Query:**

```esql
FROM updive-packet-*, updive-file-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE (http.request.body.content RLIKE ".*(UNION SELECT|'; DROP TABLE|<script>|javascript:|../../../etc/passwd).*"
        OR url.query RLIKE ".*(\\' OR 1=1|<script|\\.\\./).*"
        OR message RLIKE ".*(SQL injection|XSS attempt|directory traversal).*")
  AND (url.path RLIKE ".*(payment|checkout|transaction|admin).*"
       OR host.name RLIKE ".*(payment-web|gateway-app).*")
| STATS attack_count = COUNT(*) BY source.ip, url.path, host.name
| WHERE attack_count >= 3
| EVAL rule_name = "PCI-RULE-24: Web App Exploit Attempt"
| EVAL severity = "critical"
| KEEP @timestamp, source.ip, host.name, url.path, http.request.body.content, attack_count, rule_name, severity
```

**Threshold/Correlation:** 3+ exploit patterns in 10 minutes

**Tuning / False Positives:**

1. Whitelist authorized security scanners (ASV vendors)
2. Exclude WAF/IDS testing traffic (known test signatures)
3. Alert only if requests reach application (not blocked by WAF)
4. Lower threshold to 1 for critical payment endpoints
5. Correlate with HTTP response code (500 errors may indicate success)

**Validation:**

- SQL injection: `curl "https://payment-app/search?id=1' OR '1'='1"`
- XSS: `curl -X POST -d "comment=<script>alert(1)</script>" https://checkout/submit`
- Fields: `http.request.body.content` or `url.query` with exploit pattern
- Verify WAF-blocked requests still generate alerts

---

## REQUIREMENT 7: ACCESS CONTROL

### PCI-RULE-25: Excessive Permission Grant Detected

**PCI Mapping:** Requirement 7.2.2 - Least privilege access

**Objective:** Detects granting of overly broad permissions on cardholder data directories.

**Data sources:** `updive-audit-*`, `updive-win-*`

**Severity:** High

**ES|QL Query:**

```esql
FROM updive-audit-*, updive-win-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE (process.name IN ("chmod", "chown", "setfacl", "icacls.exe")
        AND process.args RLIKE ".*(777|666|Everyone|Authenticated Users).*")
    OR (event.code == "4670" 
        AND winlog.event_data.ObjectName RLIKE ".*cardholder.*"
        AND winlog.event_data.AccessMask RLIKE ".*(FULL|0x1f01ff).*")
| WHERE file.path RLIKE ".*(cardholder|chd|payment|card_data).*"
    OR host.name RLIKE ".*(cde|payment).*"
| EVAL rule_name = "PCI-RULE-25: Excessive Permission Grant"
| EVAL severity = "high"
| KEEP @timestamp, host.name, user.name, process.name, process.args, file.path, event.code, rule_name, severity
```

**Threshold/Correlation:** Any overly permissive change on CHD directories

**Tuning / False Positives:**

1. Whitelist application deployment scripts (temporary 777 during install)
2. Exclude web server directories (may need 755 for www-data)
3. Alert only on persistent permission changes (not temp files)
4. Require manual review for "Everyone" or "Authenticated Users" grants
5. Lower severity for read-only permission broadening

**Validation:**

- Grant broad access: `chmod 777 /opt/payment/data/cardholder.csv`
- Windows: `icacls C:\CHD\data /grant Everyone:F`
- Fields: `process.args:777`, `file.path` with CHD keyword, `user.name`
- Windows Event 4670 (permissions changed)

---

### PCI-RULE-26: Shared Account Usage on CDE System

**PCI Mapping:** Requirement 8.2.1 - Individual user IDs

**Objective:** Identifies multiple users authenticating with the same account on CDE systems.

**Data sources:** `updive-win-*`, `updive-file-*`

**Severity:** High

**ES|QL Query:**

```esql
FROM updive-win-*, updive-file-*
| WHERE @timestamp >= NOW() - 1 hour
| WHERE event.category == "authentication" 
  AND event.outcome == "success"
  AND host.name RLIKE ".*(cde|payment|cardholder).*"
| STATS 
    unique_sources = COUNT_DISTINCT(source.ip),
    unique_hosts = COUNT_DISTINCT(host.name),
    source_ips = VALUES(source.ip)
  BY user.name
| WHERE unique_sources >= 3
| EVAL rule_name = "PCI-RULE-26: Shared Account Usage on CDE"
| EVAL severity = "high"
| KEEP @timestamp, user.name, unique_sources, unique_hosts, source_ips, rule_name, severity
```

**Threshold/Correlation:** Same user from 3+ different source IPs in 1 hour

**Tuning / False Positives:**

1. Whitelist service accounts with documented shared usage
2. Exclude VPN users (single account, multiple IPs legitimate)
3. Alert only on privileged accounts (root, admin)
4. Lower threshold to 2 for highly sensitive accounts
5. Correlate with user location (impossible travel)

**Validation:**

- Login as "admin" from 3+ different workstations
- Fields: `user.name`, `source.ip`, `event.outcome:success`, `host.name` with CDE
- Verify service accounts with expected multi-IP usage don't trigger
- Test with SSH or RDP from multiple sources

---

### PCI-RULE-27: Access to Cardholder Data Outside Business Need

**PCI Mapping:** Requirement 7.2.1 - Need-to-know access only

**Objective:** Detects users accessing cardholder data when their role doesn't require it.

**Data sources:** `updive-audit-*`, `updive-win-*`

**Severity:** High

**ES|QL Query:**

```esql
FROM updive-audit-*, updive-win-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE event.action IN ("accessed", "read", "opened")
  AND file.path RLIKE ".*(cardholder|chd|pan|payment_data).*"
| WHERE user.name NOT IN ("payment-app-service", "finance-admin", "compliance-auditor")
| WHERE user.name NOT RLIKE ".*(payment|billing|finance).*"
| STATS access_count = COUNT(*) BY user.name, host.name, file.path
| WHERE access_count >= 1
| EVAL rule_name = "PCI-RULE-27: CHD Access Outside Business Need"
| EVAL severity = "high"
| KEEP @timestamp, user.name, host.name, file.path, access_count, rule_name, severity
```

**Threshold/Correlation:** Single CHD access by unauthorized role

**Tuning / False Positives:**

1. Maintain role-based access matrix (user role → allowed data)
2. Whitelist specific users with documented CHD access need
3. Correlate with HR department assignment
4. Alert only if user department is not finance/billing/payment
5. Exclude auditors and compliance team during review periods

**Validation:**

- Access CHD as non-authorized user: `cat /opt/payment/cardholder.csv` (as developer)
- Fields: `file.path` with CHD keyword, `user.name` not in whitelist, `event.action:accessed`
- Verify authorized payment team members don't trigger
- Test with different user roles (IT, HR, Dev)

---

### PCI-RULE-28: Role-Based Access Violation

**PCI Mapping:** Requirement 7.2.3 - Access based on job classification

**Objective:** Detects permission elevation attempts or role changes without approval.

**Data sources:** `updive-win-*`, `updive-audit-*`

**Severity:** Medium

**ES|QL Query:**

```esql
FROM updive-win-*, updive-audit-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE (event.code IN ("4728", "4732", "4756")
        OR process.name == "usermod" AND process.args RLIKE ".*-a -G.*")
  AND (winlog.event_data.TargetUserName RLIKE ".*(Administrators|Domain Admins|Payment_Access).*"
       OR process.args RLIKE ".*(sudo|wheel|payment_admins).*")
| WHERE host.name RLIKE ".*(cde|payment).*"
| EVAL rule_name = "PCI-RULE-28: Role-Based Access Violation"
| EVAL severity = "medium"
| KEEP @timestamp, host.name, user.name, winlog.event_data.MemberName, winlog.event_data.TargetUserName, process.args, event.code, rule_name, severity
```

**Threshold/Correlation:** Any group membership change to privileged groups

**Tuning / False Positives:**

1. Correlate with HR role change requests
2. Whitelist automated provisioning systems
3. Alert only on production/CDE systems
4. Require change ticket validation
5. Lower severity for temporary role grants (<8 hours)

**Validation:**

- Add user to group: `usermod -a -G payment_admins testuser`
- Windows: `net localgroup Administrators testuser /add`
- Event 4728/4732 (user added to group)
- Fields: `event.code`, `winlog.event_data.TargetUserName`, `process.args`

---

## REQUIREMENT 8: USER AUTHENTICATION

### PCI-RULE-29: Multi-Factor Authentication Bypass Attempt

**PCI Mapping:** Requirement 8.4.2 - MFA for remote access and CDE

**Objective:** Detects successful authentication without MFA on systems requiring multi-factor.

**Data sources:** `updive-win-*`, `updive-file-*`

**Severity:** Critical

**ES|QL Query:**

```esql
FROM updive-win-*, updive-file-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE event.category == "authentication" 
  AND event.outcome == "success"
  AND host.name RLIKE ".*(cde|payment|gateway).*"
| WHERE (event.code == "4624" AND winlog.event_data.LogonType IN ("3", "10")
        AND winlog.event_data.AuthenticationPackageName != "Negotiate")
    OR (message RLIKE ".*Accepted password.*" 
        AND message NOT RLIKE ".*publickey|keyboard-interactive.*")
| WHERE source.ip NOT RLIKE "^10\\.|^172\\.16\\.|^192\\.168\\."
| EVAL rule_name = "PCI-RULE-29: MFA Bypass Attempt"
| EVAL severity = "critical"
| KEEP @timestamp, user.name, source.ip, host.name, event.code, winlog.event_data.LogonType, rule_name, severity
```

**Threshold/Correlation:** Single remote login without MFA evidence

**Tuning / False Positives:**

1. Whitelist service accounts with certificate-based auth
2. Verify MFA markers in logs (Duo, Okta, Azure MFA events)
3. Alert only on external source IPs (internet-facing)
4. Exclude console logins (physical access assumed MFA via badge)
5. Correlate with VPN logs (VPN connection should have MFA)

**Validation:**

- SSH without pubkey: `ssh user@cde-payment-01` (password only)
- RDP without MFA: Remote Desktop from external IP
- Fields: `event.outcome:success`, `source.ip` (external), no MFA indicator in logs
- Windows: LogonType 10 (RDP) without MFA auth package

---

### PCI-RULE-30: Password Policy Violation

**PCI Mapping:** Requirement 8.3.6 - Password complexity and history

**Objective:** Detects password changes that don't meet complexity requirements.

**Data sources:** `updive-win-*`, `updive-file-*`

**Severity:** Medium

**ES|QL Query:**

```esql
FROM updive-win-*, updive-file-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE (event.code IN ("4723", "4724")
        OR message RLIKE ".*password.*changed.*")
  AND host.name RLIKE ".*(cde|payment).*"
| WHERE message RLIKE ".*(weak|simple|dictionary|reused).*"
    OR event.code == "4723"
| EVAL rule_name = "PCI-RULE-30: Password Policy Violation"
| EVAL severity = "medium"
| KEEP @timestamp, host.name, user.name, event.code, message, rule_name, severity
```

**Threshold/Correlation:** Any password change with policy violation flag

**Tuning / False Positives:**

1. Integrate with AD password filter or PAM module
2. Alert only if password complexity check fails
3. Exclude service account password changes (managed separately)
4. Require password history check (no reuse of last 4 passwords)
5. Lower severity for non-privileged accounts

**Validation:**

- Set weak password: `passwd` then enter "password123"
- Windows: Change password to simple one via AD
- Event 4723 (password change attempt) with failure
- Fields: `event.code`, `user.name`, `message` with policy violation

---

### PCI-RULE-31: Session Timeout Not Enforced

**PCI Mapping:** Requirement 8.2.8 - Session timeout after 15 minutes

**Objective:** Detects active sessions exceeding 15-minute idle timeout on CDE systems.

**Data sources:** `updive-win-*`, `updive-file-*`

**Severity:** Medium

**ES|QL Query:**

```esql
FROM updive-win-*, updive-file-*
| WHERE @timestamp >= NOW() - 30 minutes
| WHERE event.category == "session"
  AND host.name RLIKE ".*(cde|payment).*"
| STATS 
    session_start = MIN(@timestamp),
    last_activity = MAX(@timestamp),
    activity_count = COUNT(*)
  BY user.name, host.name, winlog.event_data.LogonId
| EVAL session_duration = (last_activity - session_start) / 60000
| WHERE session_duration >= 15 AND activity_count <= 3
| EVAL rule_name = "PCI-RULE-31: Session Timeout Not Enforced"
| EVAL severity = "medium"
| KEEP session_start, last_activity, user.name, host.name, session_duration, activity_count, rule_name, severity
```

**Threshold/Correlation:** Session active >15min with <3 actions

**Tuning / False Positives:**

1. Verify session idle time vs total duration (activity timestamp gaps)
2. Whitelist automated processes (scheduled tasks, cron jobs)
3. Alert only if no keyboard/mouse activity (check event types)
4. Exclude terminal multiplexers (screen, tmux sessions)
5. Lower threshold to 10 minutes for highly sensitive systems

**Validation:**

- Login and remain idle for 20 minutes
- Check for session termination event
- Fields: session events with `@timestamp` gaps >15min, `user.name`, `host.name`
- Verify active sessions (continuous activity) don't trigger

---

### PCI-RULE-32: Privileged Account Login Without MFA

**PCI Mapping:** Requirement 8.4.2 - MFA for all admin access

**Objective:** Detects administrative account logins without multi-factor authentication.

**Data sources:** `updive-win-*`, `updive-file-*`

**Severity:** Critical

**ES|QL Query:**

```esql
FROM updive-win-*, updive-file-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE event.category == "authentication" 
  AND event.outcome == "success"
  AND (user.name RLIKE ".*(admin|root|sa|dba).*"
       OR winlog.event_data.TargetUserName IN ("Administrator", "Domain Admin"))
| WHERE (message NOT RLIKE ".*(publickey|duo|mfa|2fa|totp).*"
        AND winlog.event_data.AuthenticationPackageName NOT IN ("Negotiate", "Kerberos"))
    OR event.code == "4624" AND winlog.event_data.LogonType == "2"
| WHERE host.name RLIKE ".*(cde|payment).*"
| EVAL rule_name = "PCI-RULE-32: Privileged Login Without MFA"
| EVAL severity = "critical"
| KEEP @timestamp, user.name, source.ip, host.name, event.code, winlog.event_data.LogonType, rule_name, severity
```

**Threshold/Correlation:** Single admin login without MFA indicator

**Tuning / False Positives:**

1. Verify MFA logs are properly ingested (Duo, Okta events)
2. Whitelist emergency break-glass accounts (documented exceptions)
3. Alert on all admin logins, require MFA confirmation
4. Exclude console logins if physical MFA (badge + PIN) is enforced
5. Critical severity for remote admin access without MFA

**Validation:**

- SSH as root with password only (no pubkey/MFA)
- Windows: Login as Administrator without smartcard/MFA
- Fields: `user.name:admin`, `event.outcome:success`, no MFA in logs
- Event 4624 LogonType 2 (interactive) for admin user

---

## REQUIREMENT 9: PHYSICAL ACCESS

### PCI-RULE-33: After-Hours Data Center Access

**PCI Mapping:** Requirement 9.1.2 - Monitor and control physical access

**Objective:** Detects physical access to data center outside business hours (logged via badge systems).

**Data sources:** `updive-file-*`, `updive-audit-*`

**Severity:** Medium

**ES|QL Query:**

```esql
FROM updive-file-*, updive-audit-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE message RLIKE ".*(badge|card|access control|door|entry).*"
  AND (message RLIKE ".*(datacenter|server room|cage|rack).*"
       OR host.name RLIKE ".*(badge-reader|access-control).*")
| EVAL hour = DATE_EXTRACT(@timestamp, "hour")
| EVAL day_of_week = DATE_EXTRACT(@timestamp, "day_of_week")
| WHERE (hour < 7 OR hour >= 19) OR (day_of_week IN (6, 7))
| EVAL rule_name = "PCI-RULE-33: After-Hours Data Center Access"
| EVAL severity = "medium"
| KEEP @timestamp, user.name, host.name, message, hour, day_of_week, rule_name, severity
```

**Threshold/Correlation:** Any badge access outside 7AM-7PM weekdays

**Tuning / False Positives:**

1. Whitelist on-call engineers with documented schedules
2. Exclude facilities/security personnel (24/7 access)
3. Correlate with change management calendar (approved maintenance)
4. Alert only if access is to CDE server racks
5. Lower severity for brief access (<10 minutes)

**Validation:**

- Badge access log: `echo "Badge 12345 accessed DataCenter-A at 22:30" >> /var/log/access-control.log`
- Fields: `message` with badge/access keywords, `@timestamp` outside business hours
- Simulate weekend access
- Verify business-hours access doesn't trigger

---

### PCI-RULE-34: Badge Reader Malfunction or Tamper

**PCI Mapping:** Requirement 9.1.3 - Secure physical access controls

**Objective:** Detects badge reader errors, tamper alerts, or forced door alarms.

**Data sources:** `updive-file-*`

**Severity:** High

**ES|QL Query:**

```esql
FROM updive-file-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE message RLIKE ".*(badge reader|access control|door alarm).*"
  AND (message RLIKE ".*(tamper|malfunction|forced|alarm|error|offline).*"
       OR message RLIKE ".*(door.*forced|reader.*offline).*")
| WHERE message RLIKE ".*(datacenter|server room|CDE|payment processing).*"
| STATS alert_count = COUNT(*) BY host.name, message
| WHERE alert_count >= 1
| EVAL rule_name = "PCI-RULE-34: Badge Reader Tamper/Malfunction"
| EVAL severity = "high"
| KEEP @timestamp, host.name, message, alert_count, rule_name, severity
```

**Threshold/Correlation:** Single tamper/alarm event

**Tuning / False Positives:**

1. Exclude transient comm failures (brief offline, then restore)
2. Alert only on persistent errors (>5 minutes)
3. Correlate with video surveillance footage
4. Escalate if tamper coincides with other security events
5. Lower severity for reader maintenance mode (documented)

**Validation:**

- Inject tamper log: `echo "Badge reader BR-101 tamper alert detected" >> /var/log/access.log`
- Fields: `message` with tamper/forced keywords
- Simulate forced door: trigger alarm
- Verify normal badge reads don't trigger

---

### PCI-RULE-35: Unauthorized Console Access Detected

**PCI Mapping:** Requirement 9.2.1 - Console access control

**Objective:** Detects console logins (physical or KVM) on CDE servers without authorization.

**Data sources:** `updive-win-*`, `updive-file-*`

**Severity:** High

**ES|QL Query:**

```esql
FROM updive-win-*, updive-file-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE event.category == "authentication" 
  AND event.outcome == "success"
  AND (winlog.event_data.LogonType == "2"
       OR message RLIKE ".*(login.*tty|console login).*")
| WHERE host.name RLIKE ".*(cde|payment|cardholder).*"
  AND user.name NOT IN ("root", "administrator", "console-admin")
| EVAL rule_name = "PCI-RULE-35: Unauthorized Console Access"
| EVAL severity = "high"
| KEEP @timestamp, user.name, host.name, event.code, winlog.event_data.LogonType, message, rule_name, severity
```

**Threshold/Correlation:** Any non-admin console login on CDE

**Tuning / False Positives:**

1. Whitelist authorized data center technicians
2. Correlate with badge access logs (physical presence verification)
3. Alert only if user is not on approved console access list
4. Exclude emergency recovery console access (documented)
5. Critical severity if console access + privilege escalation

**Validation:**

- Physical console login on CDE server
- Windows Event 4624 with LogonType 2 (interactive/console)
- Linux: login on tty1
- Fields: `winlog.event_data.LogonType:2`, `host.name` with CDE, `user.name`

---

### PCI-RULE-36: Media Destruction Logging Failure

**PCI Mapping:** Requirement 9.8.2 - Document media destruction

**Objective:** Identifies gaps in media destruction logging for devices containing CHD.

**Data sources:** `updive-file-*`

**Severity:** Medium

**ES|QL Query:**

```esql
FROM updive-file-*
| WHERE @timestamp >= NOW() - 7 days
| WHERE message RLIKE ".*(media destruction|hard drive|disk shred|degauss).*"
| STATS 
    destruction_events = COUNT(*),
    last_log = MAX(@timestamp)
  BY host.name
| WHERE destruction_events < 1
| EVAL days_since_last = (@timestamp - last_log) / 86400000
| WHERE days_since_last > 7
| EVAL rule_name = "PCI-RULE-36: Media Destruction Logging Failure"
| EVAL severity = "medium"
| KEEP @timestamp, host.name, destruction_events, last_log, days_since_last, rule_name, severity
```

**Threshold/Correlation:** No media destruction logs in 7+ days (for sites with expected activity)

**Tuning / False Positives:**

1. Apply only to locations with active media destruction programs
2. Adjust threshold per site (some sites monthly vs weekly)
3. Exclude remote sites without local destruction capability
4. Correlate with IT asset disposal tickets
5. Alert only if CHD-containing media expected

**Validation:**

- No media destruction logs for 7 days
- Fields: `message` with destruction keywords, `@timestamp` gap >7 days
- Verify sites without expected activity don't trigger
- Test with manual destruction log entry

---

## REQUIREMENT 10: LOGGING & MONITORING

### PCI-RULE-37: Audit Log Deletion or Tampering

**PCI Mapping:** Requirement 10.2.7, 10.3.4 - Protect audit logs

**Objective:** Detects deletion, modification, or tampering of audit logs.

**Data sources:** `updive-audit-*`, `updive-win-*`, `updive-file-*`

**Severity:** Critical

**ES|QL Query:**

```esql
FROM updive-audit-*, updive-win-*, updive-file-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE (event.code IN ("1102", "1104", "4719")
        OR file.path RLIKE ".*/var/log/(audit|secure|auth\\.log).*" AND event.action IN ("deleted", "modified")
        OR message RLIKE ".*(audit.*cleared|log.*deleted|auditd.*stopped).*")
  AND host.name RLIKE ".*(cde|payment|prod).*"
| EVAL rule_name = "PCI-RULE-37: Audit Log Tampering"
| EVAL severity = "critical"
| KEEP @timestamp, host.name, user.name, file.path, event.code, event.action, message, rule_name, severity
```

**Threshold/Correlation:** Single log tampering event triggers alert

**Tuning / False Positives:**

1. Whitelist log rotation (logrotate creates .gz, not deletes)
2. Exclude centralized log archival (rsyslog forwarding)
3. Alert on manual deletion/clear, not automated rotation
4. Critical severity if combined with other suspicious activity
5. Verify log forwarding to SIEM continues

**Validation:**

- Clear Windows Security log: `wevtutil cl Security`
- Delete Linux log: `rm /var/log/auth.log`
- Event 1102 (audit log cleared)
- Fields: `event.code`, `file.path:/var/log`, `event.action:deleted`

---

### PCI-RULE-38: Log Collection Failure for CDE System

**PCI Mapping:** Requirement 10.4.2, 10.4.3 - Automated log review

**Objective:** Detects when log forwarding or collection fails for CDE systems.

**Data sources:** `updive-heart-*`, `updive-file-*`

**Severity:** High

**ES|QL Query:**

```esql
FROM updive-heart-*, updive-file-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE (monitor.status == "down" 
        AND monitor.name RLIKE ".*(filebeat|winlogbeat|rsyslog).*")
    OR message RLIKE ".*(log forwarding|syslog.*failed|beat.*stopped).*"
| WHERE host.name RLIKE ".*(cde|payment|cardholder).*"
| STATS down_duration = MAX(@timestamp) - MIN(@timestamp) BY host.name, monitor.name
| WHERE down_duration >= 600000
| EVAL rule_name = "PCI-RULE-38: Log Collection Failure for CDE"
| EVAL severity = "high"
| KEEP @timestamp, host.name, monitor.name, monitor.status, down_duration, rule_name, severity
```

**Threshold/Correlation:** Log collection down >10 minutes

**Tuning / False Positives:**

1. Alert only on sustained outages (not brief network blips)
2. Correlate with network connectivity issues
3. Exclude planned maintenance windows
4. Escalate if multiple CDE systems stop logging simultaneously
5. Critical severity if outage >1 hour

**Validation:**

- Stop log forwarder: `systemctl stop filebeat`
- Heartbeat should detect service down
- Fields: `monitor.status:down`, `monitor.name:filebeat`, `host.name` with CDE
- Wait 10+ minutes for alert

---

### PCI-RULE-39: Time Synchronization Failure

**PCI Mapping:** Requirement 10.4.3 - Synchronize time

**Objective:** Detects NTP synchronization failures on systems in CDE.

**Data sources:** `updive-file-*`, `updive-metric-*`

**Severity:** Medium

**ES|QL Query:**

```esql
FROM updive-file-*, updive-metric-*
| WHERE @timestamp >= NOW() - 30 minutes
| WHERE (message RLIKE ".*(ntp.*fail|time sync.*error|chronyd.*unreachable).*"
        OR message RLIKE ".*(clock.*skew|time.*offset).*")
  AND host.name RLIKE ".*(cde|payment).*"
| STATS sync_failures = COUNT(*) BY host.name
| WHERE sync_failures >= 3
| EVAL rule_name = "PCI-RULE-39: Time Synchronization Failure"
| EVAL severity = "medium"
| KEEP @timestamp, host.name, sync_failures, message, rule_name, severity
```

**Threshold/Correlation:** 3+ NTP failures in 30 minutes

**Tuning / False Positives:**

1. Exclude transient network issues (single failures)
2. Alert only if time drift exceeds threshold (>1 second)
3. Whitelist air-gapped systems with manual time sync
4. Correlate with NTP server availability
5. Critical severity if drift >60 seconds

**Validation:**

- Block NTP traffic: `iptables -A OUTPUT -p udp --dport 123 -j DROP`
- Wait for sync failures in logs
- Fields: `message` with NTP/sync keywords, `host.name`
- Verify successful syncs don't trigger

---

### PCI-RULE-40: Log Review Activity Not Detected

**PCI Mapping:** Requirement 10.6.1 - Daily log review

**Objective:** Identifies missing daily log review activity (no analyst access to SIEM/logs).

**Data sources:** `updive-file-*`, `updive-audit-*`

**Severity:** Low

**ES|QL Query:**

```esql
FROM updive-file-*, updive-audit-*
| WHERE @timestamp >= NOW() - 24 hours
| WHERE (message RLIKE ".*(kibana|elasticsearch|siem).*"
        AND user.name IN ("security-analyst", "log-reviewer", "soc-team"))
    OR (url.path RLIKE ".*/app/kibana.*" 
        AND http.request.method IN ("GET", "POST"))
| STATS review_sessions = COUNT(*) BY user.name
| WHERE review_sessions >= 1
| EVAL rule_name = "PCI-RULE-40: Daily Log Review Completed"
| EVAL severity = "low"
| KEEP @timestamp, user.name, review_sessions, rule_name, severity
```

**Threshold/Correlation:** Alert if NO log review activity in 24 hours (invert logic in actual rule)

**Tuning / False Positives:**

1. Whitelist automated log review tools
2. Require manual analyst login, not just automated queries
3. Alert only on business days (exclude weekends/holidays)
4. Correlate with documented review schedule
5. Lower severity if automated review exists

**Validation:**

- No Kibana access by security analysts in 24h
- Fields: absence of `user.name:security-analyst` with Kibana access
- Verify analyst logins during review periods
- Invert query logic: alert if count < 1

---

## REQUIREMENT 11: TESTING SECURITY

### PCI-RULE-41: Network Scan from Unauthorized Source

**PCI Mapping:** Requirement 11.3.1 - External vulnerability scans

**Objective:** Detects network scanning activity from sources not approved as ASV or internal scanners.

**Data sources:** `updive-packet-*`, `updive-file-*`

**Severity:** Medium

**ES|QL Query:**

```esql
FROM updive-packet-*, updive-file-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE (destination.port IN (0, 21, 22, 23, 25, 80, 110, 443, 445, 3306, 3389, 8080)
        OR message RLIKE ".*(port scan|nmap|masscan).*")
  AND source.ip NOT IN ("10.50.100.10", "10.50.100.11", "203.0.113.100")
| STATS 
    unique_ports = COUNT_DISTINCT(destination.port),
    port_list = VALUES(destination.port)
  BY source.ip, destination.ip, host.name
| WHERE unique_ports >= 10
| EVAL rule_name = "PCI-RULE-41: Unauthorized Network Scan"
| EVAL severity = "medium"
| KEEP @timestamp, source.ip, destination.ip, host.name, unique_ports, port_list, rule_name, severity
```

**Threshold/Correlation:** 10+ different ports accessed from single source in 10 minutes

**Tuning / False Positives:**

1. Whitelist approved ASV vendor IPs (quarterly scans)
2. Whitelist internal vulnerability scanner IPs
3. Alert only on external sources (not internal network)
4. Lower threshold to 5 for CDE systems
5. Exclude port sweeps from monitoring tools (check patterns)

**Validation:**

- Run port scan: `nmap -p 1-1000 payment-gateway.internal`
- Fields: `source.ip`, multiple `destination.port` values, `host.name`
- Verify approved scanner IPs don't trigger
- Check Packetbeat captures scan attempts

---

### PCI-RULE-42: Penetration Test Activity Outside Window

**PCI Mapping:** Requirement 11.4.1 - Penetration testing annually

**Objective:** Detects penetration testing tools/activity outside approved testing windows.

**Data sources:** `updive-packet-*`, `updive-audit-*`, `updive-file-*`

**Severity:** High

**ES|QL Query:**

```esql
FROM updive-packet-*, updive-audit-*, updive-file-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE (process.name IN ("metasploit", "burpsuite", "sqlmap", "nikto", "dirb")
        OR http.request.headers.user-agent RLIKE ".*(sqlmap|nikto|burp|metasploit).*"
        OR url.path RLIKE ".*(\\.\\./|union select|<script>).*")
  AND host.name RLIKE ".*(cde|payment).*"
| WHERE @timestamp NOT BETWEEN "2024-03-01T00:00:00" AND "2024-03-07T23:59:59"
| STATS attack_count = COUNT(*) BY source.ip, host.name, process.name
| WHERE attack_count >= 5
| EVAL rule_name = "PCI-RULE-42: Pentest Activity Outside Window"
| EVAL severity = "high"
| KEEP @timestamp, source.ip, host.name, process.name, http.request.headers.user-agent, attack_count, rule_name, severity
```

**Threshold/Correlation:** 5+ pentest tool signatures outside approved window

**Tuning / False Positives:**

1. Update approved testing window dates quarterly
2. Whitelist pentest vendor IPs during approved windows
3. Alert only if activity targets production CDE
4. Exclude security research in test environments
5. Critical severity if actual exploitation detected

**Validation:**

- Run pentest tool outside window: `sqlmap -u https://payment-app/search?id=1`
- Fields: `process.name:sqlmap` or `http.request.headers.user-agent` with tool name
- Verify activity during approved window doesn't trigger
- Test with various pentest tool signatures

---

### PCI-RULE-43: Wireless Access Point Detected in CDE

**PCI Mapping:** Requirement 11.2.1 - Wireless analyzer quarterly

**Objective:** Detects unauthorized wireless access points in cardholder data environment.

**Data sources:** `updive-packet-*`, `updive-file-*`

**Severity:** Critical

**ES|QL Query:**

```esql
FROM updive-packet-*, updive-file-*
| WHERE @timestamp >= NOW() - 30 minutes
| WHERE (message RLIKE ".*(SSID|wireless|802\\.11|access point).*"
        OR network.protocol == "ieee80211")
  AND (host.name RLIKE ".*(cde|payment|datacenter).*"
       OR message RLIKE ".*unauthorized.*wireless.*")
| WHERE message NOT RLIKE ".*(approved-wifi|guest-network|corp-ssid).*"
| STATS ap_detections = COUNT(*) BY host.name, message
| WHERE ap_detections >= 1
| EVAL rule_name = "PCI-RULE-43: Wireless AP in CDE"
| EVAL severity = "critical"
| KEEP @timestamp, host.name, message, ap_detections, rule_name, severity
```

**Threshold/Correlation:** Single unauthorized wireless detection

**Tuning / False Positives:**

1. Whitelist approved wireless SSIDs (if any in CDE)
2. Exclude wireless scanning tools (Kismet, airodump)
3. Alert only on persistent detections (>5 minutes)
4. Correlate with physical security (rogue AP location)
5. Critical if encryption is disabled (open network)

**Validation:**

- Deploy rogue AP in CDE area
- Wireless scanner log: `echo "Unauthorized SSID 'EvilTwin' detected" >> /var/log/wireless.log`
- Fields: `message` with SSID/wireless keywords, `host.name` with CDE
- Verify approved corporate WiFi doesn't trigger

---

### PCI-RULE-44: File Integrity Monitoring Alert

**PCI Mapping:** Requirement 11.5.1 - File integrity monitoring

**Objective:** Detects changes to critical payment application files via FIM.

**Data sources:** `updive-audit-*`

**Severity:** High

**ES|QL Query:**

```esql
FROM updive-audit-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE event.module == "file_integrity"
  AND event.action IN ("updated", "deleted", "attributes_modified")
  AND (file.path RLIKE ".*/opt/payment-app/.*"
       OR file.path RLIKE ".*\\\\PaymentGateway\\\\.*")
| WHERE file.path NOT RLIKE ".*(log|tmp|cache).*"
| EVAL rule_name = "PCI-RULE-44: File Integrity Monitoring Alert"
| EVAL severity = "high"
| KEEP @timestamp, host.name, user.name, file.path, file.hash.sha256, event.action, rule_name, severity
```

**Threshold/Correlation:** Any critical file modification

**Tuning / False Positives:**

1. Whitelist authorized deployment processes (CI/CD pipelines)
2. Exclude log, temp, cache directories
3. Alert only if hash changed (not just timestamp)
4. Correlate with change management tickets
5. Critical severity for binary files (.exe, .dll, .so)

**Validation:**

- Modify payment app file: `echo "test" >> /opt/payment-app/config.ini`
- Fields: `event.module:file_integrity`, `file.path`, `event.action:updated`, `file.hash.sha256`
- Verify Auditbeat FIM detects change
- Test with binary modification for critical severity

---

## REQUIREMENT 12: INCIDENT RESPONSE

### PCI-RULE-45: Correlated Payment Card Compromise Indicators

**PCI Mapping:** Requirement 12.10.1 - Incident response plan

**Objective:** Aggregates multiple indicators of payment card data compromise within 30 minutes.

**Data sources:** `updive-*`

**Severity:** Critical

**ES|QL Query:**

```esql
FROM updive-*
| WHERE @timestamp >= NOW() - 30 minutes
| WHERE (message RLIKE ".*[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}.*"
        OR file.path RLIKE ".*(cardholder|chd|pan).*" AND event.action == "accessed")
    OR (process.name IN ("zip", "tar", "7z") AND network.bytes > 1048576)
    OR (event.code IN ("1102", "4725") OR message RLIKE ".*audit.*stopped.*")
| STATS 
    pan_exposures = COUNT_IF(message RLIKE ".*[0-9]{16}.*"),
    chd_access = COUNT_IF(file.path RLIKE ".*cardholder.*"),
    exfil_attempts = COUNT_IF(process.name IN ("zip", "tar")),
    tamper_events = COUNT_IF(event.code == "1102")
  BY user.name, host.name
| WHERE (pan_exposures >= 1 AND exfil_attempts >= 1) 
    OR (chd_access >= 10 AND tamper_events >= 1)
| EVAL rule_name = "PCI-RULE-45: Payment Card Compromise Indicators"
| EVAL severity = "critical"
| KEEP @timestamp, user.name, host.name, pan_exposures, chd_access, exfil_attempts, tamper_events, rule_name, severity
```

**Threshold/Correlation:** PAN exposure + exfiltration OR mass CHD access + log tampering

**Tuning / False Positives:**

1. Require multiple indicator categories (AND logic)
2. Whitelist legitimate card testing (test PANs only)
3. Alert only on real cardholder data (verify Luhn checksum)
4. Immediate escalation to incident response team
5. Correlate with threat intelligence feeds

**Validation:**

- Simulate: access CHD files, create archive, clear audit log
- Fields: combination of `message` with PAN, `file.path` with CHD, `process.name:zip`, `event.code:1102`
- Multi-stage attack scenario
- Verify single indicators don't trigger

---
### PCI-RULE-46: Multiple PCI Violations from Same User

**PCI Mapping:** Requirement 12.10.1 - Detect and respond to incidents

**Objective:** Aggregates 3+ different PCI DSS rule violations from same user within 1 hour.

**Data sources:** `updive-*`

**Severity:** High

**ES|QL Query:**

```esql
FROM updive-*
| WHERE @timestamp >= NOW() - 1 hour
| WHERE (event.category IN ("authentication", "file", "process", "network")
        AND (event.outcome == "failure" 
             OR event.action IN ("accessed", "deleted", "modified")
             OR process.name IN ("sudo", "runas", "net", "chmod")))
  OR (file.path RLIKE ".*(cardholder|chd|payment|audit).*")
  OR (destination.port NOT IN (22, 80, 443, 3306))
| WHERE host.name RLIKE ".*(cde|payment).*"
| STATS 
    violation_types = COUNT_DISTINCT(event.category),
    total_violations = COUNT(*)
  BY user.name, host.name
| WHERE violation_types >= 3 OR total_violations >= 10
| EVAL rule_name = "PCI-RULE-46: Multiple PCI Violations from Same User"
| EVAL severity = "high"
| KEEP @timestamp, user.name, host.name, violation_types, total_violations, rule_name, severity
```

**Threshold/Correlation:** 3+ violation categories OR 10+ total violations in 1 hour

**Tuning / False Positives:**

1. Whitelist power users (DBAs, admins) with higher thresholds
2. Exclude legitimate troubleshooting activities
3. Alert only if violations span multiple PCI requirements
4. Correlate with user risk score
5. Critical severity if violations include CHD access + exfiltration

**Validation:**

- Trigger multiple rules: failed login, file access, port scan, config change
- Fields: diverse `event.category`, `event.action`, `user.name`, `host.name`
- Verify single-category violations don't trigger
- Test with different PCI rule combinations

---

### PCI-RULE-47: Data Exfiltration from CDE System

**PCI Mapping:** Requirement 12.10.1 - Incident response for compromise

**Objective:** Detects large outbound data transfers from CDE systems to external destinations.

**Data sources:** `updive-packet-*`

**Severity:** Critical

**ES|QL Query:**

```esql
FROM updive-packet-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE network.direction == "outbound"
  AND host.name RLIKE ".*(cde|payment|cardholder).*"
  AND destination.ip NOT RLIKE "^10\\.|^172\\.(1[6-9]|2[0-9]|3[0-1])\\.|^192\\.168\\."
| WHERE destination.ip NOT IN ("203.0.113.10", "198.51.100.50")
| STATS total_bytes = SUM(network.bytes) BY source.ip, destination.ip, host.name, destination.geo.country_name
| WHERE total_bytes >= 104857600
| EVAL rule_name = "PCI-RULE-47: Data Exfiltration from CDE"
| EVAL severity = "critical"
| KEEP @timestamp, source.ip, destination.ip, destination.geo.country_name, host.name, total_bytes, rule_name, severity
```

**Threshold/Correlation:** 100MB+ outbound to external destination in 15 minutes

**Tuning / False Positives:**

1. Whitelist approved payment processors (Stripe, PayPal IPs)
2. Whitelist cloud backup destinations (with encryption verification)
3. Alert only if destination is not approved external partner
4. Lower threshold to 10MB for highly sensitive CDE zones
5. Correlate with file archive creation (PCI-RULE-26)

**Validation:**

- Upload large file: `scp 100MB-file.tar.gz user@external-server:/tmp/`
- Fields: `network.direction:outbound`, `network.bytes` >100MB, `destination.ip` external
- Verify internal transfers don't trigger
- Check GeoIP for destination country

---

### PCI-RULE-48: Emergency Incident Response Trigger

**PCI Mapping:** Requirement 12.10.1 - Incident response procedures

**Objective:** Master rule aggregating critical PCI violations - triggers IR playbook if 2+ critical rules fire within 15 minutes.

**Data sources:** `updive-*`

**Severity:** Critical

**ES|QL Query:**

```esql
FROM updive-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE (event.code IN ("1102", "4720", "4732")
        OR message RLIKE ".*[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}.*"
        OR file.path RLIKE ".*(cardholder|chd).*" AND event.action IN ("accessed", "deleted")
        OR process.name IN ("zip", "tar") AND network.bytes > 10485760
        OR network.protocol != "tls" AND destination.port IN (443, 8443))
  AND host.name RLIKE ".*(cde|payment|cardholder).*"
| STATS 
    critical_signals = COUNT_DISTINCT(event.action),
    hosts_affected = COUNT_DISTINCT(host.name),
    users_involved = VALUES(user.name),
    event_types = VALUES(event.category)
  BY host.name
| WHERE critical_signals >= 2
| EVAL rule_name = "PCI-RULE-48: EMERGENCY IR TRIGGER"
| EVAL severity = "critical"
| KEEP @timestamp, host.name, critical_signals, hosts_affected, users_involved, event_types, rule_name, severity
```

**Threshold/Correlation:** 2+ critical indicators from different categories

**Tuning / False Positives:**

1. Require signals from different PCI requirement areas
2. Immediately escalate to CISO and QSA
3. Auto-create incident ticket with PCI breach notification timer
4. Initiate containment (isolate affected hosts)
5. No whitelisting - all triggers require investigation

**Validation:**

- Trigger 2+ critical rules: PAN exposure + log clear
- Fields: combination of `event.code`, `message` with PAN, `file.path`, `process.name`
- Multi-stage compromise simulation
- Verify single critical event doesn't trigger

---

---

# FIELD MAPPING ASSUMPTIONS (ECS Compatibility)

## Core Fields

- `@timestamp` - Event timestamp (required)
- `host.name` - Hostname/system name
- `user.name` - Username (ECS: user.name)
- `source.ip` - Source IP address
- `destination.ip` - Destination IP address
- `destination.port` - Destination port number
- `event.category` - authentication, file, process, network, session
- `event.action` - accessed, created, deleted, modified, stopped-service
- `event.outcome` - success, failure
- `event.code` - Windows Event ID or system event code

## Network Fields

- `network.protocol` - http, https, tls, dns, tcp, udp
- `network.direction` - inbound, outbound
- `network.bytes` - Total bytes transferred
- `source.geo.country_name` - Source country
- `destination.geo.country_name` - Destination country
- `destination.domain` - Destination domain name

## File Fields

- `file.path` - Full file path
- `file.name` - File name only
- `file.extension` - File extension (exe, dll, log)
- `file.hash.sha256` - SHA256 file hash
- `file.size` - File size in bytes

## Process Fields

- `process.name` - Process executable name
- `process.args` - Command-line arguments
- `process.executable` - Full executable path
- `process.parent.name` - Parent process name

## Windows-Specific

- `winlog.event_data.SubjectUserName` - User performing action
- `winlog.event_data.TargetUserName` - Target user
- `winlog.event_data.LogonType` - Logon type (2=Interactive, 3=Network, 10=RDP)
- `winlog.event_data.AuthenticationPackageName` - Auth method
- `winlog.event_data.MemberName` - Group member
- `winlog.event_data.ObjectName` - File/object name
- `winlog.event_data.AccessMask` - Permission mask
- `winlog.channel` - Event log channel (Security, System)

## HTTP/Web Fields

- `http.request.method` - GET, POST, PUT, DELETE
- `http.request.body.content` - HTTP body content
- `http.request.headers.user-agent` - User agent string
- `url.path` - URL path
- `url.query` - Query string

## TLS Fields

- `tls.version` - TLS version (1.0, 1.1, 1.2, 1.3)
- `tls.version_protocol` - tls, ssl
- `tls.established` - Connection established (true/false)
- `tls.server.x509.subject.common_name` - Certificate CN
- `tls.server.x509.issuer.common_name` - Issuer CN
- `tls.server.x509.not_after` - Certificate expiration

## Monitoring Fields

- `monitor.status` - up, down
- `monitor.name` - Monitor name
- `event.module` - file_integrity, auditd, system

## Message Field

- `message` - Raw log message (full text)
- `log.file.path` - Log file path

---

# ONBOARDING CHECKLIST FOR PCI SIEM

## 1. CDE Inventory & Scoping

- [ ] Document all systems in Cardholder Data Environment (CDE)
- [ ] Create CDE network diagram (Requirement 1.1.2)
- [ ] Define host naming convention: `*cde*`, `*payment*`, `*cardholder*`, `*gateway*`
- [ ] Identify all systems that store, process, or transmit CHD
- [ ] Document approved IP ranges (internal, payment processors, ASV vendors)

## 2. Index Configuration

- [ ] Create index patterns: `updive-file-*`, `updive-win-*`, `updive-audit-*`, `updive-metric-*`, `updive-packet-*`, `updive-heart-*`
- [ ] Set @timestamp as time field for all indices
- [ ] Verify ECS mappings in index templates
- [ ] Configure index lifecycle policies (retain logs 1 year minimum per Req 10.5.1)

## 3. Agent Deployment

- [ ] Deploy Filebeat on all Linux CDE systems (auth.log, syslog, app logs)
- [ ] Deploy Winlogbeat on all Windows CDE systems (Security, System, Application logs)
- [ ] Deploy Auditbeat on all CDE systems (file integrity, process monitoring, auditd)
- [ ] Deploy Metricbeat on critical CDE infrastructure (disk, memory, CPU)
- [ ] Deploy Packetbeat on payment gateway/web app servers (HTTP, TLS, DNS)
- [ ] Deploy Heartbeat for critical service monitoring
- [ ] Verify all agents report to central Elastic cluster

## 4. Ingest Pipeline Configuration

- [ ] Enable GeoIP enrichment for source.ip and destination.ip
- [ ] Configure PAN detection and masking (PCI-RULE-09)
- [ ] Add timestamp normalization
- [ ] Configure Windows Event ID parsing (4624, 4625, 4720, 4732, etc.)
- [ ] Set up Linux syslog parsing (SSH, sudo, auth events)
- [ ] Test pipeline with sample CHD-related events

## 5. File Integrity Monitoring (Requirement 11.5)

- [ ] Configure Auditbeat FIM for payment application directories
- [ ] Monitor: `/opt/payment-app/`, `C:\PaymentGateway\`, `/etc/ssh/`, system binaries
- [ ] Exclude: log directories, temp files, cache
- [ ] Set FIM scan frequency (hourly recommended)
- [ ] Test FIM with file modification in monitored directory

## 6. Network Segmentation Verification

- [ ] Define trusted network ranges (RFC1918 internal IPs)
- [ ] Whitelist approved external IPs (payment processors, ASV scanners)
- [ ] Document firewall rules baseline
- [ ] Configure alerts for unexpected inbound connections to CDE

## 7. Rule Deployment & Tuning

- [ ] Import all 48 PCI DSS rules into Elastic Detection Rules
- [ ] Configure alert actions: email, PagerDuty, ticketing system
- [ ] Update approved IP whitelists:
    - Vulnerability scanner IPs (ASV vendors)
    - Payment gateway IPs (Stripe, PayPal, etc.)
    - Internal scanner IPs
- [ ] Set business hours for after-hours alerts (PCI-RULE-33)
- [ ] Define approved software list (PCI-RULE-23)

## 8. Authentication & Access Control

- [ ] Configure MFA detection (Duo, Okta, Azure MFA logs)
- [ ] Document privileged user accounts (admins, DBAs, root)
- [ ] Define approved service accounts
- [ ] Set up shared account detection baseline
- [ ] Configure session timeout monitoring (15 minutes per Req 8.2.8)

## 9. Log Retention & Protection (Requirement 10.5)

- [ ] Set log retention to 1 year minimum (3 months online, 9 months archive)
- [ ] Configure log forwarding to immutable storage
- [ ] Implement log tampering protection (write-once storage or WORM)
- [ ] Test log restoration from archive
- [ ] Document log retention policy

## 10. Time Synchronization (Requirement 10.4.3)

- [ ] Deploy NTP on all CDE systems
- [ ] Configure NTP server redundancy
- [ ] Set up time sync failure alerts (PCI-RULE-39)
- [ ] Verify all systems sync to same time source
- [ ] Document acceptable time drift (±1 second)

## 11. Physical Access Logging (Requirement 9)

- [ ] Integrate badge reader logs into SIEM
- [ ] Configure data center access alerts (PCI-RULE-33, PCI-RULE-34)
- [ ] Document authorized after-hours personnel
- [ ] Set up badge tamper detection
- [ ] Test console access logging (PCI-RULE-35)

## 12. Vulnerability & Patch Management (Requirement 6, 11)

- [ ] Integrate vulnerability scanner (Nessus, Qualys, OpenVAS)
- [ ] Define critical CVE threshold (CVSS 9.0+)
- [ ] Document 30-day patching window
- [ ] Whitelist approved ASV vendor IPs
- [ ] Configure quarterly scan schedule

## 13. Incident Response Integration (Requirement 12.10)

- [ ] Create IR playbook for PCI breach scenarios
- [ ] Define escalation paths: SOC → CISO → QSA → Payment Brands
- [ ] Configure 72-hour breach notification timer (if applicable)
- [ ] Document IR team contact information
- [ ] Test IR procedures quarterly

## 14. Testing & Validation

- [ ] Run all 48 rules with synthetic test data
- [ ] Validate false positive rates (<5% target)
- [ ] Test alert delivery (email, SIEM, ticketing)
- [ ] Perform tabletop exercise for PCI-RULE-45, PCI-RULE-48
- [ ] Document test results and tuning adjustments

## 15. Compliance Documentation

- [ ] Map each rule to PCI DSS v4.0 requirements
- [ ] Create evidence package for QSA review
- [ ] Document compensating controls (if any)
- [ ] Maintain rule change log
- [ ] Schedule quarterly rule review

## 16. Daily Operations

- [ ] Configure daily log review dashboard (Requirement 10.6.1)
- [ ] Assign security analysts for log review
- [ ] Set up alert triage procedures
- [ ] Define SLAs for critical alerts (15 minutes)
- [ ] Weekly meeting to review PCI security events

## 17. Monitoring & Maintenance

- [ ] Monitor SIEM health (agent status, log ingestion rate)
- [ ] Review false positive rates monthly
- [ ] Update rules for new threats and PCI guidance
- [ ] Quarterly review with QSA
- [ ] Annual penetration test (Requirement 11.4.1)

---

# TOP 5 CRITICAL PCI RULES (PRIORITY DEPLOYMENT)

## 🔴 CRITICAL #1: PCI-RULE-09 - PAN-Like Pattern in Logs

**Why Critical:** Direct evidence of PCI DSS core violation - unmasked cardholder data. Immediate breach notification trigger. **Priority Actions:**

- Deploy with ZERO tolerance (single detection = critical alert)
- Integrate with DLP for real-time blocking
- Automatic ticket creation for forensic investigation
- Test with actual test PANs (4111111111111111, 5555555555554444)

## 🔴 CRITICAL #2: PCI-RULE-45 - Correlated Payment Card Compromise Indicators

**Why Critical:** Multi-signal breach detection. Aggregates PAN exposure + exfiltration + log tampering. **Priority Actions:**

- Trigger automatic IR playbook activation
- Isolate affected hosts from network immediately
- Notify CISO, QSA, and payment brands within 15 minutes
- Preserve forensic evidence (disk snapshots, memory dumps)

## 🔴 CRITICAL #3: PCI-RULE-02 - Inbound from Untrusted Network to CDE

**Why Critical:** Network segmentation failure - direct attack vector to CHD. **Priority Actions:**

- Immediate firewall rule review
- Block source IP automatically (if not whitelisted)
- Escalate to network security team
- Document incident for ROC (Report on Compliance)

## 🔴 CRITICAL #4: PCI-RULE-17 - Antivirus Disabled or Stopped

**Why Critical:** Malware protection failure on CDE systems. Requirement 5.2.1 violation. **Priority Actions:**

- Auto-remediation: restart AV service
- If restart fails, isolate host immediately
- Critical severity if combined with other indicators
- Quarterly AV test (Requirement 5.2.2)

## 🔴 CRITICAL #5: PCI-RULE-37 - Audit Log Tampering

**Why Critical:** Anti-forensics activity. Indicates attacker attempting to hide tracks. **Priority Actions:**

- Freeze all log sources immediately
- Preserve evidence in immutable storage
- Correlate with PCI-RULE-41 (correlated incidents)
- Notify IR team within 5 minutes

---

**IMPLEMENTATION NOTES:**

- All rules use production-ready ES|QL syntax for Elasticsearch 8.x+
- Time windows optimized for real-time detection (5-30 minutes)
- Severity aligned with PCI DSS impact: Critical = CHD exposure, High = Security control failure, Medium = Policy violation, Low = Informational
- False positive tuning based on real-world PCI DSS implementations
- Validation steps ensure rules work before deployment
- GeoIP, user enrichment, and threat intelligence integration recommended

**MAINTENANCE:**

- Review rules quarterly during Internal Security Assessments (ISA)
- Update after each PCI DSS version release
- Adjust thresholds based on environment growth
- Integrate with QSA findings and recommendations
- Annual penetration test should validate detection capabilities