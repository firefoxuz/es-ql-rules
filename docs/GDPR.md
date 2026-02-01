# GDPR Security Monitoring - ES|QL Rule Set

## Wazuh → Elastic SIEM Conversion

---

## RULE CATALOG (50 rules organized by category)

### (I) Access Control & Authentication Anomalies (8 rules)

1. **RULE-01** Multiple Failed Login Attempts (Brute Force)
2. **RULE-02** Admin Login from Unusual Host
3. **RULE-03** Disabled Account Login Attempt
4. **RULE-04** Successful Login After Multiple Failures
5. **RULE-05** Login Outside Business Hours (High-Privilege Account)
6. **RULE-06** Multiple Users Logged from Same Source IP
7. **RULE-07** First-Time Login from Geographic Location
8. **RULE-08** Concurrent Logins from Impossible Locations

### (II) Privilege Escalation & Account Changes (8 rules)

9. **RULE-09** New Local Administrator Account Created
10. **RULE-10** Sudoers File Modified
11. **RULE-11** Windows Administrators Group Membership Change
12. **RULE-12** Suspicious Service Creation (Persistence)
13. **RULE-13** UAC Bypass Attempt Detected
14. **RULE-14** Sudo Command Executed by Non-Standard User
15. **RULE-15** Password Policy Changed
16. **RULE-16** Scheduled Task Created with SYSTEM Privileges

### (III) Audit & Log Tampering (8 rules)

17. **RULE-17** Auditd Service Stopped or Disabled
18. **RULE-18** Windows Event Log Cleared (Event 1102)
19. **RULE-19** Log File Deletion in Critical Paths
20. **RULE-20** Elastic Agent/Beat Stopped Unexpectedly
21. **RULE-21** Syslog Service Interruption
22. **RULE-22** Log Rotation Policy Modified
23. **RULE-23** Mass Deletion of Log Files
24. **RULE-24** Auditd Rules Modified or Deleted

### (IV) Data Access & Exfiltration Indicators (8 rules)

25. **RULE-25** Mass File Access in Sensitive Directories
26. **RULE-26** Archive Tool Usage Followed by Network Transfer
27. **RULE-27** Unusual DNS Query Volume (Tunneling Indicator)
28. **RULE-28** Large Outbound Data Transfer to Rare Destination
29. **RULE-29** Database Bulk Export Detected
30. **RULE-30** Cloud Storage Sync Tools on Unauthorized Hosts
31. **RULE-31** USB Mass Storage Device Connected
32. **RULE-32** Email with Large Attachments to External Domain

### (V) Availability & Integrity (8 rules)

33. **RULE-33** Critical Service Down (Heartbeat Alert)
34. **RULE-34** Disk Space Critical on Log Storage
35. **RULE-35** File Integrity Change in System Binaries
36. **RULE-36** Unexpected System Reboot
37. **RULE-37** Memory Exhaustion on Critical Host
38. **RULE-38** Configuration File Modified (Unauthorized)
39. **RULE-39** Database Integrity Check Failure
40. **RULE-40** Certificate Expiration Imminent

### (VI) Breach Notification Readiness & Correlation (10 rules)

41. **RULE-41** Correlated Incident: Access + Exfil + Tamper (30min)
42. **RULE-42** Multiple GDPR-Relevant Events from Same User
43. **RULE-43** Ransomware Indicator Chain (File Rename + Encryption)
44. **RULE-44** Lateral Movement Pattern Detected
45. **RULE-45** Data Breach Indicators Aggregated (High Severity)
46. **RULE-46** Personal Data Access Outside Authorized Systems
47. **RULE-47** Unauthorized Data Processing Activity
48. **RULE-48** Data Retention Policy Violation (Old Data Accessed)
49. **RULE-49** Cross-Border Data Transfer Detected
50. **RULE-50** Emergency Breach Response Trigger (Multi-Signal)

---

# DETAILED RULE SPECIFICATIONS

## (I) ACCESS CONTROL & AUTHENTICATION ANOMALIES

### RULE-01: Multiple Failed Login Attempts (Brute Force)

**Objective:** Detects brute force login attempts by counting failed authentication events from the same source IP within 5 minutes.

**Data sources:** `winlogbeat-*`, `filebeat-*` (Linux auth.log)

**GDPR mapping:** Article 32(1)(b) - Ability to ensure confidentiality; Article 32(2) - Security of processing

**Severity:** Medium | **MITRE:** T1110 (Brute Force)

**Query (ES|QL):**

```esql
FROM winlogbeat-*, filebeat-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE event.category == "authentication" 
  AND event.outcome == "failure"
| STATS failed_attempts = COUNT(*) BY source.ip, user.name, host.name
| WHERE failed_attempts >= 5
| EVAL rule_name = "RULE-01: Multiple Failed Login Attempts"
| EVAL severity = "medium"
| KEEP @timestamp, source.ip, user.name, host.name, failed_attempts, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist known scanner IPs (vulnerability scanners, monitoring tools)
2. Increase threshold to 10 for VPN gateways or public-facing services
3. Exclude service accounts with known password rotation issues
4. Add time-of-day filter for legitimate after-hours maintenance windows
5. Create separate rule for privileged accounts with threshold = 3

**Validation:**

- Inject 6+ failed login events with same `source.ip` within 5 min
- Fields required: `event.category:authentication`, `event.outcome:failure`, `source.ip`, `user.name`
- Verify Windows Event ID 4625 or Linux `/var/log/auth.log` failed SSH entries

---

### RULE-02: Admin Login from Unusual Host

**Objective:** Identifies administrative account logins from hosts not previously seen in the last 30 days, indicating potential credential compromise.

**Data sources:** `winlogbeat-*`, `filebeat-*`

**GDPR mapping:** Article 32(1)(b) - Confidentiality controls; Article 25 - Data protection by design

**Severity:** High | **MITRE:** T1078.002 (Valid Accounts: Domain Accounts)

**Query (ES|QL):**

```esql
FROM winlogbeat-*, filebeat-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE event.category == "authentication" 
  AND event.outcome == "success"
  AND (user.name RLIKE ".*admin.*" OR user.name IN ("root", "administrator", "sysadmin"))
| STATS current_hosts = VALUES(host.name) BY user.name, source.ip
| EVAL rule_name = "RULE-02: Admin Login from Unusual Host"
| EVAL severity = "high"
| KEEP @timestamp, user.name, source.ip, current_hosts, rule_name, severity
```

**Tuning / False Positives:**

1. Maintain baseline of admin login patterns (use ML or historical STATS)
2. Whitelist known jump servers and PAM solutions
3. Correlate with HR data for new admin hires
4. Reduce severity if MFA was used (check `event.action` for MFA success)
5. Exclude cloud-based admin portals (Azure AD, Okta) with dynamic IPs

**Validation:**

- Create successful login event for admin user from new `host.name` not seen in 30d
- Fields: `user.name` matching admin pattern, `event.outcome:success`, `source.ip`, `host.name`
- Windows Event ID 4624 (Logon Type 3 or 10) or Linux SSH successful auth

---

### RULE-03: Disabled Account Login Attempt

**Objective:** Detects login attempts using disabled or expired accounts, indicating reconnaissance or compromise.

**Data sources:** `winlogbeat-*`

**GDPR mapping:** Article 32(1)(d) - Ability to restore availability; Article 5(1)(f) - Integrity and confidentiality

**Severity:** High | **MITRE:** T1078 (Valid Accounts)

**Query (ES|QL):**

```esql
FROM winlogbeat-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE event.code == "4625" 
  AND (winlog.event_data.SubStatusCode == "0xC0000072" 
       OR winlog.event_data.SubStatusCode == "0xC0000234")
| STATS attempt_count = COUNT(*) BY user.name, source.ip, host.name
| EVAL rule_name = "RULE-03: Disabled Account Login Attempt"
| EVAL severity = "high"
| KEEP @timestamp, user.name, source.ip, host.name, attempt_count, rule_name, severity
```

**Tuning / False Positives:**

1. Cross-check with Active Directory to confirm account status
2. Whitelist automated systems that may cache old credentials
3. Alert only if attempts > 2 to avoid single typos
4. Correlate with recent account disable events (Event 4725)
5. Exclude test/dev environments with frequent account churn

**Validation:**

- Generate Windows Event 4625 with SubStatus 0xC0000072 (disabled) or 0xC0000234 (locked)
- Fields: `event.code:4625`, `winlog.event_data.SubStatusCode`, `user.name`
- Simulate with `net user testuser /active:no` then attempt login

---

### RULE-04: Successful Login After Multiple Failures

**Objective:** Detects successful authentication following 3+ failed attempts within 10 minutes, indicating potential brute force success.

**Data sources:** `winlogbeat-*`, `filebeat-*`

**GDPR mapping:** Article 32(1)(b) - Confidentiality; Article 33 - Breach notification (early warning)

**Severity:** High | **MITRE:** T1110.001 (Password Guessing)

**Query (ES|QL):**

```esql
FROM winlogbeat-*, filebeat-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE event.category == "authentication"
| STATS 
    failures = COUNT_IF(event.outcome == "failure"),
    successes = COUNT_IF(event.outcome == "success"),
    max_time = MAX(@timestamp)
  BY source.ip, user.name, host.name
| WHERE failures >= 3 AND successes >= 1
| EVAL rule_name = "RULE-04: Successful Login After Multiple Failures"
| EVAL severity = "high"
| KEEP max_time, source.ip, user.name, host.name, failures, successes, rule_name, severity
```

**Tuning / False Positives:**

1. Increase failure threshold to 5 for users with known password issues
2. Whitelist legitimate password reset flows (check for reset token usage)
3. Reduce alert if success happens >15min after last failure
4. Correlate with helpdesk ticket systems (password reset requests)
5. Exclude service accounts with automated retry logic

**Validation:**

- Inject 3+ `event.outcome:failure` followed by 1 `event.outcome:success` from same IP
- Fields: `event.category:authentication`, `event.outcome`, `source.ip`, `user.name`
- Test with SSH (3 wrong passwords, 1 correct) or RDP attempts

---

### RULE-05: Login Outside Business Hours (High-Privilege Account)

**Objective:** Alerts on privileged account logins during non-business hours (22:00-06:00 weekdays, all weekend).

**Data sources:** `winlogbeat-*`, `filebeat-*`

**GDPR mapping:** Article 32(1) - Security measures; Article 5(1)(f) - Confidentiality

**Severity:** Medium | **MITRE:** T1078 (Valid Accounts)

**Query (ES|QL):**

```esql
FROM winlogbeat-*, filebeat-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE event.category == "authentication" AND event.outcome == "success"
| WHERE user.name RLIKE ".*(admin|root|sysadmin).*"
| EVAL hour = DATE_EXTRACT(@timestamp, "hour")
| EVAL day_of_week = DATE_EXTRACT(@timestamp, "day_of_week")
| WHERE (hour < 6 OR hour >= 22) OR (day_of_week IN (6, 7))
| EVAL rule_name = "RULE-05: Login Outside Business Hours"
| EVAL severity = "medium"
| KEEP @timestamp, user.name, source.ip, host.name, hour, day_of_week, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist on-call engineers with documented schedules
2. Exclude global teams with legitimate 24/7 operations
3. Cross-reference with change management calendar (approved maintenance)
4. Adjust time windows per timezone and business model
5. Lower severity if MFA is confirmed

**Validation:**

- Create login event with `@timestamp` between 22:00-06:00 or on Saturday/Sunday
- Fields: `user.name` with admin keyword, `event.outcome:success`, `@timestamp`
- Manually set system clock or inject historical event

---

### RULE-06: Multiple Users Logged from Same Source IP

**Objective:** Detects multiple unique user accounts authenticating from a single source IP within 5 minutes, indicating session hijacking or shared credentials.

**Data sources:** `winlogbeat-*`, `filebeat-*`

**GDPR mapping:** Article 32(1)(b) - Confidentiality; Article 25 - Accountability

**Severity:** Medium | **MITRE:** T1078 (Valid Accounts)

**Query (ES|QL):**

```esql
FROM winlogbeat-*, filebeat-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE event.category == "authentication" AND event.outcome == "success"
| STATS unique_users = COUNT_DISTINCT(user.name) BY source.ip, host.name
| WHERE unique_users >= 5
| EVAL rule_name = "RULE-06: Multiple Users from Same Source IP"
| EVAL severity = "medium"
| KEEP @timestamp, source.ip, host.name, unique_users, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist NAT gateways and corporate proxy IPs
2. Whitelist shared terminal servers (Citrix, RDS)
3. Increase threshold to 10 for VPN concentrators
4. Exclude service desk computers with shared access
5. Lower threshold to 3 for external/internet-facing IPs

**Validation:**

- Generate 5+ successful logins with different `user.name` from same `source.ip` within 5min
- Fields: `event.outcome:success`, `source.ip`, `user.name`
- Simulate with multiple SSH/RDP sessions from single client

---

### RULE-07: First-Time Login from Geographic Location

**Objective:** Identifies first-ever successful login from a new country/region for a user account.

**Data sources:** `winlogbeat-*`, `filebeat-*`

**GDPR mapping:** Article 32(1) - Security measures; Article 44 - International data transfers

**Severity:** Medium | **MITRE:** T1078 (Valid Accounts)

**Query (ES|QL):**

```esql
FROM winlogbeat-*, filebeat-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE event.category == "authentication" AND event.outcome == "success"
| WHERE source.geo.country_name IS NOT NULL
| STATS countries = VALUES(source.geo.country_name) BY user.name
| WHERE LENGTH(countries) >= 2
| EVAL rule_name = "RULE-07: First-Time Login from Geographic Location"
| EVAL severity = "medium"
| KEEP @timestamp, user.name, source.ip, source.geo.country_name, countries, rule_name, severity
```

**Tuning / False Positives:**

1. Maintain historical baseline of user locations (30d+)
2. Whitelist employees with known travel schedules
3. Reduce severity for VPN users (check `network.protocol` or VPN markers)
4. Alert only if new country + impossible travel time from last login
5. Exclude cloud service IPs with dynamic geo-location

**Validation:**

- Ensure GeoIP enrichment is enabled in Elastic ingest pipeline
- Create login from new `source.geo.country_name` not in user's history
- Fields: `source.geo.country_name`, `user.name`, `event.outcome:success`

---

### RULE-08: Concurrent Logins from Impossible Locations

**Objective:** Detects logins from two different geographic locations within 1 hour where travel is physically impossible (>500km apart).

**Data sources:** `winlogbeat-*`, `filebeat-*`

**GDPR mapping:** Article 32(1)(b) - Confidentiality; Article 33 - Breach early warning

**Severity:** High | **MITRE:** T1078 (Valid Accounts)

**Query (ES|QL):**

```esql
FROM winlogbeat-*, filebeat-*
| WHERE @timestamp >= NOW() - 1 hour
| WHERE event.category == "authentication" AND event.outcome == "success"
| WHERE source.geo.location IS NOT NULL
| STATS 
    locations = VALUES(source.geo.location),
    countries = VALUES(source.geo.country_name),
    time_span = MAX(@timestamp) - MIN(@timestamp)
  BY user.name
| WHERE LENGTH(countries) >= 2 AND time_span < 3600000
| EVAL rule_name = "RULE-08: Concurrent Logins from Impossible Locations"
| EVAL severity = "high"
| KEEP @timestamp, user.name, countries, locations, time_span, rule_name, severity
```

**Tuning / False Positives:**

1. Calculate actual distance between geo.location coordinates (use Painless script in ingest)
2. Whitelist VPN IPs (often show false geo-location)
3. Exclude cloud service providers with multi-region presence
4. Require minimum distance threshold (500km+)
5. Cross-reference with user travel calendar/expense reports

**Validation:**

- Create 2 login events with different `source.geo.country_name` within 1 hour
- Fields: `source.geo.location`, `source.geo.country_name`, `user.name`, `@timestamp`
- Simulate with VPN hop or manual IP spoofing in test environment

---

## (II) PRIVILEGE ESCALATION & ACCOUNT CHANGES

### RULE-09: New Local Administrator Account Created

**Objective:** Detects creation of new local administrator accounts on Windows or Unix systems.

**Data sources:** `winlogbeat-*`, `filebeat-*`, `auditbeat-*`

**GDPR mapping:** Article 32(1) - Access control; Article 5(1)(f) - Integrity and confidentiality

**Severity:** High | **MITRE:** T1136.001 (Create Account: Local Account)

**Query (ES|QL):**

```esql
FROM winlogbeat-*, filebeat-*, auditbeat-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE (event.code == "4720" AND winlog.event_data.MemberSid RLIKE ".*-500") 
    OR (event.action == "added-user-account" AND user.name RLIKE ".*(admin|root).*")
    OR (process.name == "useradd" AND process.args RLIKE ".*-G (sudo|wheel|admin).*")
| EVAL rule_name = "RULE-09: New Local Administrator Account Created"
| EVAL severity = "high"
| KEEP @timestamp, host.name, user.name, event.action, process.name, process.args, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist authorized provisioning systems (Ansible, Puppet, SCCM)
2. Correlate with change tickets in ITSM system
3. Alert only if creator is not in approved admin list
4. Exclude automated onboarding workflows with known service accounts
5. Require manual approval for alerts during business hours

**Validation:**

- Windows: Event 4720 (account created) + Event 4732 (added to Administrators group)
- Linux: `useradd` command with `-G sudo` or `/etc/sudoers` modification
- Fields: `event.code:4720`, `process.name:useradd`, `process.args`, `user.name`

---

### RULE-10: Sudoers File Modified

**Objective:** Detects unauthorized modifications to `/etc/sudoers` or `/etc/sudoers.d/` files on Linux systems.

**Data sources:** `auditbeat-*`, `filebeat-*`

**GDPR mapping:** Article 32(1) - Access control; Article 25 - Secure by design

**Severity:** High | **MITRE:** T1548.003 (Abuse Elevation Control: Sudo)

**Query (ES|QL):**

```esql
FROM auditbeat-*, filebeat-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE file.path RLIKE ".*/etc/sudoers.*" 
  AND (event.action IN ("modified", "created", "deleted") 
       OR event.type == "change")
| EVAL rule_name = "RULE-10: Sudoers File Modified"
| EVAL severity = "high"
| KEEP @timestamp, host.name, user.name, file.path, event.action, process.name, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist configuration management tools (Chef, Ansible) by process hash
2. Require change ticket correlation via CMDB API
3. Alert only if modifier is not root or authorized admin
4. Exclude read-only access (`event.action:accessed`)
5. Create separate low-severity rule for visudo (legitimate editor)

**Validation:**

- Modify `/etc/sudoers` file and verify auditd generates file change event
- Fields: `file.path:/etc/sudoers`, `event.action:modified`, `user.name`, `process.name`
- Test: `echo "testuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/test`

---

### RULE-11: Windows Administrators Group Membership Change

**Objective:** Detects additions or removals from the local Administrators group on Windows systems.

**Data sources:** `winlogbeat-*`

**GDPR mapping:** Article 32(1) - Access control; Article 5(2) - Accountability

**Severity:** High | **MITRE:** T1098 (Account Manipulation)

**Query (ES|QL):**

```esql
FROM winlogbeat-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE event.code IN ("4732", "4733") 
  AND winlog.event_data.TargetUserName == "Administrators"
| EVAL action = CASE(event.code == "4732", "added", event.code == "4733", "removed")
| EVAL rule_name = "RULE-11: Administrators Group Membership Change"
| EVAL severity = "high"
| KEEP @timestamp, host.name, winlog.event_data.MemberName, action, winlog.event_data.SubjectUserName, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist Group Policy updates from domain controllers
2. Correlate with HR onboarding/offboarding workflows
3. Alert only if change made by non-admin account
4. Exclude scheduled automated account provisioning
5. Cross-check with Active Directory sync events

**Validation:**

- Windows Event 4732 (member added to security-enabled local group)
- Windows Event 4733 (member removed from security-enabled local group)
- Fields: `event.code`, `winlog.event_data.TargetUserName:Administrators`, `winlog.event_data.MemberName`
- Test: `net localgroup Administrators testuser /add`

---

### RULE-12: Suspicious Service Creation (Persistence)

**Objective:** Detects creation of Windows services with suspicious characteristics (e.g., unusual paths, command-line arguments).

**Data sources:** `winlogbeat-*`

**GDPR mapping:** Article 32(1)(d) - Ability to restore availability; Article 32(2) - Regular testing

**Severity:** High | **MITRE:** T1543.003 (Create or Modify System Process: Windows Service)

**Query (ES|QL):**

```esql
FROM winlogbeat-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE event.code == "7045"
| WHERE winlog.event_data.ImagePath RLIKE ".*(temp|appdata|programdata|public).*"
    OR winlog.event_data.ServiceName RLIKE ".*(update|defender|chrome|svchost).*"
| EVAL rule_name = "RULE-12: Suspicious Service Creation"
| EVAL severity = "high"
| KEEP @timestamp, host.name, winlog.event_data.ServiceName, winlog.event_data.ImagePath, winlog.event_data.ServiceType, user.name, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist known software installers by service name hash
2. Exclude legitimate updater services (verify code signature)
3. Alert only if ImagePath is unsigned or in writable directory
4. Correlate with recent file creation in ImagePath location
5. Lower severity for services with manual start type

**Validation:**

- Windows Event 7045 (service installed)
- Fields: `event.code:7045`, `winlog.event_data.ServiceName`, `winlog.event_data.ImagePath`
- Test: `sc create TestSvc binPath= "C:\Windows\Temp\malicious.exe"`

---

### RULE-13: UAC Bypass Attempt Detected

**Objective:** Identifies attempts to bypass User Account Control (UAC) using known techniques.

**Data sources:** `winlogbeat-*`, `auditbeat-*`

**GDPR mapping:** Article 32(1) - Access control; Article 25 - Privacy by design

**Severity:** High | **MITRE:** T1548.002 (Abuse Elevation Control: Bypass UAC)

**Query (ES|QL):** 
```
FROM winlogbeat-*, auditbeat-* | WHERE @timestamp >= NOW() - 15 minutes | WHERE (process.name IN ("fodhelper.exe", "eventvwr.exe", "computerdefaults.exe") AND process.parent.name != "explorer.exe") OR (registry.path RLIKE "._\mscfile\shell\open\command._" AND event.action == "modified") OR (event.code == "4688" AND process.command_line RLIKE "._bypassuac._") | EVAL rule_name = "RULE-13: UAC Bypass Attempt Detected" | EVAL severity = "high" | KEEP @timestamp, host.name, user.name, process.name, process.parent.name, process.command_line, registry.path, rule_name, severity

````

**Tuning / False Positives:**
1. Whitelist legitimate admin tools launched from scripts
2. Verify process integrity level (should not be elevated without UAC prompt)
3. Correlate with recent user login (exclude service accounts)
4. Check process code signature validity
5. Exclude authorized elevation from privileged access management tools

**Validation:**
- Event 4688 (process creation) with suspicious parent/child relationship
- Registry modification in HKCU\Software\Classes\mscfile\shell\open\command
- Fields: `process.name`, `process.parent.name`, `registry.path`, `event.action`
- Test: Run `fodhelper.exe` from cmd.exe with registry key set

---

### RULE-14: Sudo Command Executed by Non-Standard User

**Objective:** Detects sudo usage by users not in approved administrator list.

**Data sources:** `filebeat-*`, `auditbeat-*`

**GDPR mapping:** Article 32(1) - Access control; Article 5(1)(f) - Integrity

**Severity:** Medium | **MITRE:** T1548.003 (Sudo and Sudo Caching)

**Query (ES|QL):**
```esql
FROM filebeat-*, auditbeat-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE (process.name == "sudo" OR message RLIKE ".*sudo:.*COMMAND.*")
| WHERE user.name NOT IN ("sysadmin", "root", "ansible", "puppet")
| STATS sudo_count = COUNT(*) BY user.name, host.name, process.args
| WHERE sudo_count >= 1
| EVAL rule_name = "RULE-14: Sudo Command Executed by Non-Standard User"
| EVAL severity = "medium"
| KEEP @timestamp, user.name, host.name, process.args, sudo_count, rule_name, severity
````

**Tuning / False Positives:**

1. Maintain dynamic whitelist from LDAP/AD groups (sudo_users)
2. Exclude legitimate sudo usage during documented maintenance
3. Alert only if command is high-risk (su, visudo, passwd)
4. Lower severity for read-only commands (cat, ls)
5. Correlate with recent privilege escalation requests

**Validation:**

- Linux auth.log entry: `sudo: user : TTY=pts/0 ; PWD=/home/user ; COMMAND=/bin/bash`
- Auditd execve event for sudo process
- Fields: `process.name:sudo`, `user.name`, `process.args`, `message`
- Test: Non-admin user runs `sudo ls /root`

---

### RULE-15: Password Policy Changed

**Objective:** Detects modifications to domain or local password policy settings.

**Data sources:** `winlogbeat-*`

**GDPR mapping:** Article 32(1)(b) - Confidentiality; Article 25 - Security by design

**Severity:** High | **MITRE:** T1201 (Password Policy Discovery)

**Query (ES|QL):**

```esql
FROM winlogbeat-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE event.code IN ("4713", "4739", "4670")
| EVAL rule_name = "RULE-15: Password Policy Changed"
| EVAL severity = "high"
| KEEP @timestamp, host.name, user.name, event.code, winlog.event_data.SubjectUserName, winlog.event_data.DomainPolicyChanged, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist Group Policy updates from authorized domain controllers
2. Require change ticket reference in alert notification
3. Alert only if changed by non-Domain Admin account
4. Exclude read-only policy queries (Event 4798)
5. Correlate with recent security audit findings

**Validation:**

- Event 4713 (Kerberos policy changed)
- Event 4739 (domain policy changed)
- Event 4670 (permissions on an object changed)
- Fields: `event.code`, `winlog.event_data.DomainPolicyChanged`, `user.name`
- Test: `gpupdate /force` after modifying Default Domain Policy

---

### RULE-16: Scheduled Task Created with SYSTEM Privileges

**Objective:** Detects scheduled tasks created with SYSTEM account privileges, common persistence mechanism.

**Data sources:** `winlogbeat-*`

**GDPR mapping:** Article 32(1) - Access control; Article 32(2) - Regular testing

**Severity:** High | **MITRE:** T1053.005 (Scheduled Task/Job)

**Query (ES|QL):**

```esql
FROM winlogbeat-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE event.code == "4698"
| WHERE winlog.event_data.TaskContent RLIKE ".*<UserId>S-1-5-18</UserId>.*"
    OR winlog.event_data.TaskContent RLIKE ".*<UserId>SYSTEM</UserId>.*"
| EVAL rule_name = "RULE-16: Scheduled Task Created with SYSTEM Privileges"
| EVAL severity = "high"
| KEEP @timestamp, host.name, winlog.event_data.TaskName, winlog.event_data.SubjectUserName, winlog.event_data.TaskContent, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist known system maintenance tasks by TaskName
2. Exclude tasks created by SCCM or other management tools
3. Alert only if task action includes suspicious paths (temp, appdata)
4. Correlate with recent software installation events
5. Verify task signature/author is from trusted publisher

**Validation:**

- Event 4698 (scheduled task created)
- Fields: `event.code:4698`, `winlog.event_data.TaskName`, `winlog.event_data.TaskContent`
- TaskContent XML contains `<UserId>S-1-5-18</UserId>` (SYSTEM)
- Test: `schtasks /create /tn TestTask /tr calc.exe /sc once /st 00:00 /ru SYSTEM`

---

## (III) AUDIT & LOG TAMPERING

### RULE-17: Auditd Service Stopped or Disabled

**Objective:** Detects when the Linux audit daemon (auditd) is stopped or disabled, indicating potential log tampering.

**Data sources:** `filebeat-*`, `auditbeat-*`

**GDPR mapping:** Article 5(1)(f) - Integrity; Article 32(1)(d) - Ability to restore; Article 33 - Breach notification

**Severity:** Critical | **MITRE:** T1562.001 (Impair Defenses: Disable or Modify Tools)

**Query (ES|QL):**

```esql
FROM filebeat-*, auditbeat-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE (message RLIKE ".*(auditd.*stopped|audit.*disabled).*" 
        OR process.args RLIKE ".*(systemctl stop auditd|service auditd stop).*"
        OR event.action == "stopped-service" AND process.name RLIKE ".*audit.*")
| EVAL rule_name = "RULE-17: Auditd Service Stopped or Disabled"
| EVAL severity = "critical"
| KEEP @timestamp, host.name, user.name, process.name, process.args, message, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist scheduled maintenance windows with change tickets
2. Exclude legitimate system updates that restart auditd
3. Alert immediately without aggregation (critical event)
4. Correlate with other log tampering indicators within 5 minutes
5. Verify via heartbeat that agent is still reporting

**Validation:**

- Syslog message: "Stopping auditd" or "auditd stopped"
- Auditd event: service_stop for auditd.service
- Fields: `process.args`, `message`, `event.action:stopped-service`
- Test: `systemctl stop auditd` and check syslog/audit.log

---

### RULE-18: Windows Event Log Cleared (Event 1102)

**Objective:** Detects when Windows Security event log is cleared, a classic anti-forensics technique.

**Data sources:** `winlogbeat-*`

**GDPR mapping:** Article 5(1)(f) - Integrity; Article 32(1) - Security measures; Article 33 - Breach notification

**Severity:** Critical | **MITRE:** T1070.001 (Indicator Removal: Clear Windows Event Logs)

**Query (ES|QL):**

```esql
FROM winlogbeat-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE event.code == "1102"
| EVAL rule_name = "RULE-18: Windows Event Log Cleared"
| EVAL severity = "critical"
| KEEP @timestamp, host.name, user.name, winlog.event_data.SubjectUserName, winlog.channel, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist authorized log archival processes (documented procedures)
2. Alert immediately without threshold
3. Correlate with logon events from same user in previous 30 minutes
4. Verify log clear was not part of scheduled cleanup policy
5. Cross-check with physical access logs if on-premises

**Validation:**

- Event 1102 in Security log
- Fields: `event.code:1102`, `winlog.event_data.SubjectUserName`, `winlog.channel:Security`
- Test: `wevtutil cl Security` (requires admin privileges)

---

### RULE-19: Log File Deletion in Critical Paths

**Objective:** Detects deletion of log files in /var/log or C:\Windows\System32\winevt\Logs.

**Data sources:** `auditbeat-*`, `winlogbeat-*`

**GDPR mapping:** Article 5(1)(f) - Integrity; Article 32(1) - Security measures; Article 5(2) - Accountability

**Severity:** High | **MITRE:** T1070.004 (Indicator Removal: File Deletion)

**Query (ES|QL):**

```esql
FROM auditbeat-*, winlogbeat-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE event.action IN ("deleted", "file_deletion") 
  AND (file.path RLIKE ".*/var/log/.*" OR file.path RLIKE ".*Windows.*winevt.*Logs.*")
| EVAL rule_name = "RULE-19: Log File Deletion in Critical Paths"
| EVAL severity = "high"
| KEEP @timestamp, host.name, user.name, file.path, process.name, event.action, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist log rotation tools (logrotate, Windows Event Log service)
2. Exclude automated archival scripts with documented schedules
3. Alert only if deletion is manual (not via scheduled task)
4. Lower severity for deletion of .old or .gz rotated logs
5. Correlate with disk space alerts (legitimate cleanup)

**Validation:**

- Auditd file deletion event in /var/log
- Windows Event 4663 (file delete) for .evtx files
- Fields: `file.path`, `event.action:deleted`, `user.name`, `process.name`
- Test: `rm /var/log/auth.log.1` or `del C:\Windows\System32\winevt\Logs\Security.evtx`

---

### RULE-20: Elastic Agent/Beat Stopped Unexpectedly

**Objective:** Detects when Elastic Agent or Beats services stop outside of maintenance windows.

**Data sources:** `metricbeat-*`, `filebeat-*`

**GDPR mapping:** Article 5(1)(f) - Integrity; Article 32(1)(d) - Ability to restore

**Severity:** High | **MITRE:** T1562.001 (Impair Defenses)

**Query (ES|QL):**

```esql
FROM metricbeat-*, filebeat-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE (monitor.status == "down" AND monitor.name RLIKE ".*(elastic-agent|filebeat|winlogbeat).*")
    OR (message RLIKE ".*(elastic-agent|beat).*stopped.*" AND event.action == "stopped-service")
| STATS down_count = COUNT(*) BY host.name, monitor.name
| WHERE down_count >= 1
| EVAL rule_name = "RULE-20: Elastic Agent/Beat Stopped Unexpectedly"
| EVAL severity = "high"
| KEEP @timestamp, host.name, monitor.name, monitor.status, down_count, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist planned maintenance windows from CMDB
2. Correlate with system reboot events (legitimate)
3. Alert only if down for >5 minutes
4. Verify via alternative monitoring (SNMP, ping)
5. Escalate if multiple hosts stop simultaneously

**Validation:**

- Heartbeat monitor status changes to "down"
- Syslog: "elastic-agent service stopped"
- Fields: `monitor.status:down`, `monitor.name`, `event.action:stopped-service`
- Test: `systemctl stop elastic-agent` or `Stop-Service Elastic Agent`

---

### RULE-21: Syslog Service Interruption

**Objective:** Detects when syslog/rsyslog service stops on Linux systems.

**Data sources:** `filebeat-*`, `auditbeat-*`

**GDPR mapping:** Article 5(1)(f) - Integrity; Article 32(1) - Security measures

**Severity:** High | **MITRE:** T1562.001 (Impair Defenses)

**Query (ES|QL):**

```esql
FROM filebeat-*, auditbeat-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE (message RLIKE ".*(rsyslogd|syslog).*stopped.*" 
        OR process.args RLIKE ".*(systemctl stop rsyslog|service rsyslog stop).*")
| EVAL rule_name = "RULE-21: Syslog Service Interruption"
| EVAL severity = "high"
| KEEP @timestamp, host.name, user.name, process.name, process.args, message, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist system update processes
2. Exclude legitimate service restarts (check for subsequent start event)
3. Alert only if service stays down >10 minutes
4. Correlate with disk space issues (logs may fill disk)
5. Verify log forwarding to central syslog server continues

**Validation:**

- Syslog message: "rsyslogd stopped"
- Auditd execve: `systemctl stop rsyslog`
- Fields: `message`, `process.args`, `event.action`
- Test: `systemctl stop rsyslog`

---

### RULE-22: Log Rotation Policy Modified

**Objective:** Detects changes to log rotation configuration files (logrotate.conf, logrotate.d).

**Data sources:** `auditbeat-*`, `filebeat-*`

**GDPR mapping:** Article 5(1)(f) - Integrity; Article 32(1) - Security measures

**Severity:** Medium | **MITRE:** T1070 (Indicator Removal)

**Query (ES|QL):**

```esql
FROM auditbeat-*, filebeat-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE file.path RLIKE ".*/etc/logrotate.*" 
  AND event.action IN ("modified", "created", "deleted")
| EVAL rule_name = "RULE-22: Log Rotation Policy Modified"
| EVAL severity = "medium"
| KEEP @timestamp, host.name, user.name, file.path, event.action, process.name, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist configuration management tools (Ansible, Puppet)
2. Require change ticket correlation
3. Alert only if modifier is non-admin user
4. Exclude package manager updates (apt, yum)
5. Lower severity for additions (new app log configs)

**Validation:**

- Auditd file modification event for /etc/logrotate.conf
- Fields: `file.path:/etc/logrotate`, `event.action:modified`, `user.name`
- Test: `echo "rotate 1" >> /etc/logrotate.conf`

---

### RULE-23: Mass Deletion of Log Files

**Objective:** Detects deletion of 10+ log files within 5 minutes.

**Data sources:** `auditbeat-*`, `winlogbeat-*`

**GDPR mapping:** Article 5(1)(f) - Integrity; Article 33 - Breach notification

**Severity:** Critical | **MITRE:** T1070.004 (File Deletion)

**Query (ES|QL):**

```esql
FROM auditbeat-*, winlogbeat-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE event.action IN ("deleted", "file_deletion")
  AND (file.path RLIKE ".*\\.log$" OR file.extension == "log" OR file.extension == "evtx")
| STATS deleted_count = COUNT(*) BY user.name, host.name
| WHERE deleted_count >= 10
| EVAL rule_name = "RULE-23: Mass Deletion of Log Files"
| EVAL severity = "critical"
| KEEP @timestamp, user.name, host.name, deleted_count, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist automated log archival jobs
2. Exclude log rotation (check for corresponding .gz creation)
3. Lower threshold to 5 for production servers
4. Alert only if deletions are in rapid succession (<1 min)
5. Correlate with suspicious authentication events

**Validation:**

- Multiple auditd file deletion events with .log extension
- Windows Event 4663 (delete) for multiple .evtx files
- Fields: `event.action:deleted`, `file.path`, `file.extension:log`, `user.name`
- Test: `rm /var/log/*.log.1` or delete multiple .evtx files

---

### RULE-24: Auditd Rules Modified or Deleted

**Objective:** Detects changes to auditd rules in /etc/audit/audit.rules or via auditctl.

**Data sources:** `auditbeat-*`, `filebeat-*`

**GDPR mapping:** Article 5(1)(f) - Integrity; Article 32(1) - Security measures

**Severity:** Critical | **MITRE:** T1562.001 (Impair Defenses)

**Query (ES|QL):**

```esql
FROM auditbeat-*, filebeat-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE (file.path RLIKE ".*/etc/audit/.*" AND event.action IN ("modified", "deleted"))
    OR (process.name == "auditctl" AND process.args RLIKE ".* -D .*")
| EVAL rule_name = "RULE-24: Auditd Rules Modified or Deleted"
| EVAL severity = "critical"
| KEEP @timestamp, host.name, user.name, file.path, process.name, process.args, event.action, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist authorized security team changes
2. Require change ticket reference
3. Alert immediately (no aggregation)
4. Correlate with recent suspicious activity
5. Verify rules are restored after alert

**Validation:**

- Auditd event for /etc/audit/audit.rules modification
- Process execution: `auditctl -D` (delete all rules)
- Fields: `file.path:/etc/audit/`, `process.name:auditctl`, `process.args`, `event.action`
- Test: `auditctl -D` or `echo "" > /etc/audit/audit.rules`

---

## (IV) DATA ACCESS & EXFILTRATION INDICATORS

### RULE-25: Mass File Access in Sensitive Directories

**Objective:** Detects when a user accesses 50+ files in directories containing sensitive data within 10 minutes.

**Data sources:** `auditbeat-*`, `winlogbeat-*`

**GDPR mapping:** Article 32(1)(b) - Confidentiality; Article 33 - Breach notification; Article 5(1)(c) - Data minimization

**Severity:** High | **MITRE:** T1005 (Data from Local System)

**Query (ES|QL):**

```esql
FROM auditbeat-*, winlogbeat-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE event.action IN ("accessed", "read", "file_read")
  AND (file.path RLIKE ".*(personal|confidential|hr|finance|customer).*" 
       OR file.path RLIKE ".*Documents.*")
| STATS file_count = COUNT_DISTINCT(file.path) BY user.name, host.name
| WHERE file_count >= 50
| EVAL rule_name = "RULE-25: Mass File Access in Sensitive Directories"
| EVAL severity = "high"
| KEEP @timestamp, user.name, host.name, file_count, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist backup software and antivirus scanners
2. Exclude indexing services (Windows Search, Spotlight)
3. Reduce threshold to 20 for high-security zones
4. Correlate with user's normal access patterns (baseline)
5. Alert only if access is outside user's department

**Validation:**

- Auditd file read events for 50+ unique files
- Windows Event 4663 (object access) with READ permission
- Fields: `event.action:accessed`, `file.path`, `user.name`
- Test: `for i in {1..60}; do cat /path/to/sensitive/file$i; done`

---

### RULE-26: Archive Tool Usage Followed by Network Transfer

**Objective:** Detects compression tools (zip, tar, 7z) followed by network connections within 5 minutes, indicating data exfiltration.

**Data sources:** `auditbeat-*`, `metricbeat-*`, `winlogbeat-*`

**GDPR mapping:** Article 32(1)(b) - Confidentiality; Article 33 - Breach notification

**Severity:** Critical | **MITRE:** T1560.001 (Archive via Utility) + T1041 (Exfiltration Over C2)

**Query (ES|QL):**

```esql
FROM auditbeat-*, metricbeat-*, winlogbeat-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE process.name IN ("zip", "tar", "7z", "rar", "gzip", "7z.exe", "WinRAR.exe")
    OR network.protocol IN ("http", "https", "ftp") AND network.bytes > 1048576
| STATS 
    archive_count = COUNT_IF(process.name IN ("zip", "tar", "7z", "rar")),
    network_count = COUNT_IF(network.protocol IS NOT NULL),
    total_bytes = SUM(network.bytes)
  BY user.name, host.name
| WHERE archive_count >= 1 AND network_count >= 1
| EVAL rule_name = "RULE-26: Archive Tool + Network Transfer"
| EVAL severity = "critical"
| KEEP @timestamp, user.name, host.name, archive_count, network_count, total_bytes, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist legitimate backup jobs (check destination IP)
2. Exclude software deployment tools (SCCM, Ansible)
3. Alert only if destination is external/internet
4. Lower severity for internal file shares
5. Correlate with DLP policies and approved cloud services

**Validation:**

- Process execution: `tar -czf data.tar.gz /sensitive/*`
- Network flow: large outbound transfer (>1MB) via HTTP/FTP
- Fields: `process.name:tar`, `network.protocol:http`, `network.bytes`, `user.name`
- Test: Create archive, then `scp` to external server

---

### RULE-27: Unusual DNS Query Volume (Tunneling Indicator)

**Objective:** Detects abnormally high DNS query count (100+ in 5 minutes) from single host, potential DNS tunneling.

**Data sources:** `metricbeat-*`

**GDPR mapping:** Article 32(1)(b) - Confidentiality; Article 33 - Breach notification

**Severity:** High | **MITRE:** T1071.004 (Application Layer Protocol: DNS)

**Query (ES|QL):**

```esql
FROM metricbeat-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE network.protocol == "dns" OR destination.port == 53
| STATS 
    dns_count = COUNT(*),
    unique_domains = COUNT_DISTINCT(dns.question.name)
  BY source.ip, host.name
| WHERE dns_count >= 100
| EVAL rule_name = "RULE-27: Unusual DNS Query Volume"
| EVAL severity = "high"
| KEEP @timestamp, source.ip, host.name, dns_count, unique_domains, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist DNS servers and recursive resolvers
2. Exclude legitimate high-volume services (CDN, proxies)
3. Alert only if query names are unusually long (>50 chars)
4. Check for TXT record queries (common in tunneling)
5. Correlate with known malicious DNS tunnel tools

**Validation:**

- Packetbeat DNS events with high volume
- Fields: `network.protocol:dns`, `dns.question.name`, `source.ip`
- Test: Run `dnscat2` or `iodine` DNS tunnel tool

---

### RULE-28: Large Outbound Data Transfer to Rare Destination

**Objective:** Detects outbound transfers >100MB to destinations not seen in past 30 days.

**Data sources:** `metricbeat-*`

**GDPR mapping:** Article 32(1)(b) - Confidentiality; Article 33 - Breach notification; Article 44 - International transfers

**Severity:** High | **MITRE:** T1041 (Exfiltration Over C2 Channel)

**Query (ES|QL):**

```esql
FROM metricbeat-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE network.direction == "outbound" OR source.ip RLIKE "^10\\.|^172\\.16\\.|^192\\.168\\."
| STATS total_bytes = SUM(network.bytes) BY destination.ip, source.ip, host.name
| WHERE total_bytes >= 104857600
| EVAL rule_name = "RULE-28: Large Outbound Transfer to Rare Destination"
| EVAL severity = "high"
| KEEP @timestamp, source.ip, destination.ip, destination.geo.country_name, host.name, total_bytes, rule_name, severity
```

**Tuning / False Positives:**

1. Maintain baseline of known external services (AWS, Azure, SaaS)
2. Whitelist approved cloud backup destinations
3. Alert only if destination is not in corporate IP ranges
4. Lower severity for transfers to known CDNs
5. Correlate with user role (developers may have legitimate large transfers)

**Validation:**

- Packetbeat network flow with large `network.bytes` sum
- Fields: `network.bytes`, `destination.ip`, `network.direction:outbound`
- Test: Upload 100MB file to unknown external server

---

### RULE-29: Database Bulk Export Detected

**Objective:** Detects bulk database export commands (mysqldump, pg_dump) or large SELECT queries.

**Data sources:** `auditbeat-*`, `filebeat-*`

**GDPR mapping:** Article 32(1)(b) - Confidentiality; Article 33 - Breach notification; Article 5(1)(c) - Data minimization

**Severity:** High | **MITRE:** T1530 (Data from Cloud Storage)

**Query (ES|QL):**

```esql
FROM auditbeat-*, filebeat-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE process.name IN ("mysqldump", "pg_dump", "mongodump", "sqlcmd", "psql")
    OR process.args RLIKE ".*(SELECT.*FROM|COPY.*TO|BACKUP DATABASE).*"
| EVAL rule_name = "RULE-29: Database Bulk Export Detected"
| EVAL severity = "high"
| KEEP @timestamp, host.name, user.name, process.name, process.args, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist scheduled backup jobs by user/cron
2. Exclude legitimate data warehouse ETL processes
3. Alert only if export is to unusual path (e.g., /tmp, user home)
4. Correlate with DBA change tickets
5. Lower severity for exports to approved backup storage

**Validation:**

- Auditd process execution: `mysqldump -u root -p database > /tmp/export.sql`
- Fields: `process.name:mysqldump`, `process.args`, `user.name`
- Test: Run database export command

---

### RULE-30: Cloud Storage Sync Tools on Unauthorized Hosts

**Objective:** Detects installation or execution of cloud sync tools (Dropbox, Google Drive, OneDrive) on unapproved hosts.

**Data sources:** `auditbeat-*`, `winlogbeat-*`

**GDPR mapping:** Article 32(1)(b) - Confidentiality; Article 28 - Processor obligations; Article 44 - International transfers

**Severity:** Medium | **MITRE:** T1567.002 (Exfiltration to Cloud Storage)

**Query (ES|QL):**

```esql
FROM auditbeat-*, winlogbeat-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE process.name RLIKE ".*(dropbox|googledrive|onedrive|box|mega).*"
    OR file.path RLIKE ".*(Dropbox|Google Drive|OneDrive).*"
| WHERE host.name NOT IN ("approved-workstation-001", "approved-workstation-002")
| EVAL rule_name = "RULE-30: Cloud Storage Sync Tools on Unauthorized Hosts"
| EVAL severity = "medium"
| KEEP @timestamp, host.name, user.name, process.name, file.path, rule_name, severity
```

**Tuning / False Positives:**

1. Maintain whitelist of approved cloud services per department
2. Exclude executive/sales teams with documented approval
3. Alert only if process connects to cloud service (check network)
4. Lower severity for read-only access
5. Correlate with CASB policies

**Validation:**

- Process execution: Dropbox.exe or dropbox daemon
- File creation in cloud sync folder
- Fields: `process.name`, `file.path`, `host.name`
- Test: Install Dropbox on unapproved host

---

### RULE-31: USB Mass Storage Device Connected

**Objective:** Detects connection of USB mass storage devices on endpoints.

**Data sources:** `winlogbeat-*`, `auditbeat-*`

**GDPR mapping:** Article 32(1)(b) - Confidentiality; Article 25 - Data protection by design

**Severity:** Medium | **MITRE:** T1091 (Replication Through Removable Media)

**Query (ES|QL):**

```esql
FROM winlogbeat-*, auditbeat-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE (event.code == "2003" OR event.code == "2100")
    OR (message RLIKE ".*USB.*mass storage.*" AND event.action == "device-connected")
| EVAL rule_name = "RULE-31: USB Mass Storage Device Connected"
| EVAL severity = "medium"
| KEEP @timestamp, host.name, user.name, event.code, winlog.event_data.DeviceName, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist approved USB devices by serial number
2. Exclude IT team during authorized operations
3. Alert only if large file transfers occur after connection
4. Lower severity for read-only USB devices
5. Correlate with endpoint DLP policies

**Validation:**

- Windows Event 2003 (Plug and Play device installed)
- Linux udev event for USB storage
- Fields: `event.code:2003`, `winlog.event_data.DeviceName`, `user.name`
- Test: Insert USB flash drive

---

### RULE-32: Email with Large Attachments to External Domain

**Objective:** Detects emails sent with attachments >10MB to external domains.

**Data sources:** `filebeat-*`, `metricbeat-*`

**GDPR mapping:** Article 32(1)(b) - Confidentiality; Article 33 - Breach notification

**Severity:** Medium | **MITRE:** T1048.002 (Exfiltration Over Alternative Protocol: Email)

**Query (ES|QL):**

```esql
FROM filebeat-*, metricbeat-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE (network.protocol == "smtp" AND network.bytes > 10485760)
    OR (message RLIKE ".*attachment.*size.*" AND message RLIKE ".*external.*")
| WHERE destination.domain NOT IN ("company.com", "company.net")
| EVAL rule_name = "RULE-32: Email with Large Attachments to External Domain"
| EVAL severity = "medium"
| KEEP @timestamp, user.name, source.ip, destination.domain, network.bytes, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist approved external partners
2. Exclude sales/marketing teams with legitimate large file sends
3. Alert only if attachment contains sensitive keywords (PII, financial)
4. Lower threshold to 5MB for high-security departments
5. Correlate with email DLP policies

**Validation:**

- SMTP traffic with large payload
- Email server logs showing attachment size
- Fields: `network.protocol:smtp`, `network.bytes`, `destination.domain`, `user.name`
- Test: Send email with 15MB attachment to Gmail

---

## (V) AVAILABILITY & INTEGRITY

### RULE-33: Critical Service Down (Heartbeat Alert)

**Objective:** Detects when a critical service (database, web server, etc.) fails heartbeat check.

**Data sources:** `metricbeat-*`

**GDPR mapping:** Article 32(1)(c) - Resilience; Article 32(1)(d) - Ability to restore

**Severity:** High | **MITRE:** T1499 (Endpoint Denial of Service)

**Query (ES|QL):**

```esql
FROM metricbeat-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE monitor.status == "down"
  AND monitor.name IN ("database-prod", "web-app", "api-gateway", "auth-service")
| STATS down_duration = MAX(@timestamp) - MIN(@timestamp) BY monitor.name, host.name
| WHERE down_duration >= 300000
| EVAL rule_name = "RULE-33: Critical Service Down"
| EVAL severity = "high"
| KEEP @timestamp, monitor.name, host.name, monitor.status, down_duration, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist planned maintenance windows
2. Alert only if service is down >5 minutes continuously
3. Escalate if multiple services down simultaneously
4. Correlate with infrastructure monitoring (Nagios, Zabbix)
5. Lower severity for non-prod environments

**Validation:**

- Heartbeat monitor returns status "down"
- Fields: `monitor.status:down`, `monitor.name`, `@timestamp`
- Test: Stop critical service and verify heartbeat fails

---

### RULE-34: Disk Space Critical on Log Storage

**Objective:** Detects disk usage >90% on partitions storing logs, risking log loss.

**Data sources:** `metricbeat-*`

**GDPR mapping:** Article 5(1)(f) - Integrity; Article 32(1)(d) - Ability to restore

**Severity:** High | **MITRE:** T1499 (Resource Exhaustion)

**Query (ES|QL):**

```esql
FROM metricbeat-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE system.filesystem.mount_point RLIKE ".*(var|log|audit).*"
| EVAL disk_used_pct = system.filesystem.used.pct * 100
| WHERE disk_used_pct >= 90
| EVAL rule_name = "RULE-34: Disk Space Critical on Log Storage"
| EVAL severity = "high"
| KEEP @timestamp, host.name, system.filesystem.mount_point, disk_used_pct, rule_name, severity
```

**Tuning / False Positives:**

1. Adjust threshold per environment (85% for small disks)
2. Exclude temporary spikes (require 3 consecutive alerts)
3. Correlate with log rotation policies
4. Alert only if usage increases >10% in 1 hour
5. Whitelist test/dev systems with known space issues

**Validation:**

- Metricbeat filesystem metrics showing high usage
- Fields: `system.filesystem.used.pct`, `system.filesystem.mount_point`, `host.name`
- Test: Fill /var/log partition to >90%

---

### RULE-35: File Integrity Change in System Binaries

**Objective:** Detects modifications to critical system binaries (/bin, /sbin, C:\Windows\System32).

**Data sources:** `auditbeat-*`

**GDPR mapping:** Article 32(1) - Security measures; Article 32(2) - Regular testing; Article 25 - Security by design

**Severity:** Critical | **MITRE:** T1565.001 (Data Manipulation: Stored Data)

**Query (ES|QL):**

```esql
FROM auditbeat-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE event.module == "file_integrity"
  AND (file.path RLIKE ".*(\/bin\/|\/sbin\/|Windows\\\\System32\\\\).*"
       OR file.path RLIKE ".*\\.(exe|dll|so|dylib)$")
  AND event.action IN ("updated", "created", "attributes_modified")
| EVAL rule_name = "RULE-35: File Integrity Change in System Binaries"
| EVAL severity = "critical"
| KEEP @timestamp, host.name, file.path, file.hash.sha256, event.action, user.name, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist package manager updates (apt, yum, Windows Update)
2. Exclude legitimate software installations (verify signature)
3. Alert only if hash changed (not just timestamp)
4. Correlate with change management tickets
5. Maintain baseline of known-good file hashes

**Validation:**

- Auditbeat file integrity module detects change
- Fields: `event.module:file_integrity`, `file.path`, `file.hash.sha256`, `event.action`
- Test: Modify a file in /bin or C:\Windows\System32

---

### RULE-36: Unexpected System Reboot

**Objective:** Detects system reboots not preceded by documented maintenance.

**Data sources:** `winlogbeat-*`, `filebeat-*`

**GDPR mapping:** Article 32(1)(c) - Resilience; Article 32(1)(d) - Ability to restore

**Severity:** Medium | **MITRE:** T1529 (System Shutdown/Reboot)

**Query (ES|QL):**

```esql
FROM winlogbeat-*, filebeat-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE (event.code == "1074" OR event.code == "6008")
    OR (message RLIKE ".*(system.*reboot|shutdown -r).*" AND event.action == "shutdown")
| EVAL rule_name = "RULE-36: Unexpected System Reboot"
| EVAL severity = "medium"
| KEEP @timestamp, host.name, user.name, event.code, winlog.event_data.Reason, message, rule_name, severity
```

**Tuning / False Positives:**

1. Correlate with change management system (approved reboots)
2. Exclude Windows Update automatic reboots (check Reason field)
3. Alert only if reboot reason is manual or unexpected
4. Lower severity during off-hours maintenance windows
5. Escalate if multiple hosts reboot simultaneously

**Validation:**

- Windows Event 1074 (system shutdown/restart) or 6008 (unexpected shutdown)
- Linux syslog: "system rebooted" or shutdown command
- Fields: `event.code`, `winlog.event_data.Reason`, `message`, `user.name`
- Test: `shutdown -r now` or restart from Windows

---

### RULE-37: Memory Exhaustion on Critical Host

**Objective:** Detects memory usage >95% on critical production hosts.

**Data sources:** `metricbeat-*`

**GDPR mapping:** Article 32(1)(c) - Resilience; Article 32(1)(d) - Ability to restore

**Severity:** High | **MITRE:** T1499 (Resource Exhaustion)

**Query (ES|QL):**

```esql
FROM metricbeat-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE system.memory.actual.used.pct >= 0.95
  AND host.name IN ("db-prod-01", "web-prod-01", "app-prod-01")
| EVAL memory_used_pct = system.memory.actual.used.pct * 100
| EVAL rule_name = "RULE-37: Memory Exhaustion on Critical Host"
| EVAL severity = "high"
| KEEP @timestamp, host.name, memory_used_pct, system.memory.actual.used.bytes, rule_name, severity
```

**Tuning / False Positives:**

1. Adjust threshold per host (90% for large memory systems)
2. Exclude memory caching (Linux uses memory for cache)
3. Alert only if sustained >5 minutes
4. Correlate with process metrics (identify memory leak)
5. Whitelist known high-memory applications

**Validation:**

- Metricbeat system memory metrics
- Fields: `system.memory.actual.used.pct`, `host.name`, `@timestamp`
- Test: Run memory stress tool (stress-ng)

---

### RULE-38: Configuration File Modified (Unauthorized)

**Objective:** Detects modifications to critical configuration files without authorization.

**Data sources:** `auditbeat-*`

**GDPR mapping:** Article 32(1) - Security measures; Article 25 - Data protection by design

**Severity:** High | **MITRE:** T1565.001 (Data Manipulation)

**Query (ES|QL):**

```esql
FROM auditbeat-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE event.module == "file_integrity"
  AND file.path RLIKE ".*(\.conf|\.config|\.ini|\.yaml|\.yml|\.xml)$"
  AND file.path RLIKE ".*(etc|config|nginx|apache|mysql).*"
  AND event.action IN ("updated", "created")
| EVAL rule_name = "RULE-38: Configuration File Modified"
| EVAL severity = "high"
| KEEP @timestamp, host.name, user.name, file.path, event.action, file.hash.sha256, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist configuration management tools (Ansible, Chef)
2. Correlate with change tickets
3. Alert only if modified by non-admin user
4. Exclude application-owned config files (e.g., cache)
5. Verify file signature if available

**Validation:**

- Auditbeat file integrity event for config file
- Fields: `event.module:file_integrity`, `file.path`, `event.action:updated`
- Test: Modify /etc/nginx/nginx.conf

---

### RULE-39: Database Integrity Check Failure

**Objective:** Detects database integrity check failures indicating corruption or tampering.

**Data sources:** `filebeat-*`

**GDPR mapping:** Article 5(1)(f) - Integrity; Article 32(1) - Security measures

**Severity:** Critical | **MITRE:** T1565.001 (Data Manipulation)

**Query (ES|QL):**

```esql
FROM filebeat-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE message RLIKE ".*(integrity check failed|corruption detected|checksum mismatch).*"
    OR (process.name IN ("mysqlcheck", "pg_checksums") AND message RLIKE ".*error.*")
| EVAL rule_name = "RULE-39: Database Integrity Check Failure"
| EVAL severity = "critical"
| KEEP @timestamp, host.name, message, process.name, rule_name, severity
```

**Tuning / False Positives:**

1. Exclude transient errors (require 2+ consecutive failures)
2. Correlate with recent system crashes or power loss
3. Alert DBA team immediately
4. Lower severity for non-production databases
5. Verify with manual integrity check

**Validation:**

- Database log messages indicating corruption
- Process output from integrity check tools
- Fields: `message`, `process.name`, `host.name`
- Test: Run `mysqlcheck --all-databases` and inject error

---

### RULE-40: Certificate Expiration Imminent

**Objective:** Detects SSL/TLS certificates expiring within 7 days.

**Data sources:** `metricbeat-*`, `filebeat-*`

**GDPR mapping:** Article 32(1)(b) - Confidentiality; Article 32(1)(c) - Resilience

**Severity:** Medium | **MITRE:** N/A (Operational)

**Query (ES|QL):**

```esql
FROM metricbeat-*, filebeat-*
| WHERE @timestamp >= NOW() - 24 hours
| WHERE tls.server.x509.not_after IS NOT NULL
| EVAL days_until_expiry = (tls.server.x509.not_after - NOW()) / 86400000
| WHERE days_until_expiry <= 7 AND days_until_expiry >= 0
| EVAL rule_name = "RULE-40: Certificate Expiration Imminent"
| EVAL severity = "medium"
| KEEP @timestamp, tls.server.x509.subject.common_name, tls.server.x509.not_after, days_until_expiry, destination.ip, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist self-signed certs in test environments
2. Alert only for public-facing services
3. Escalate to critical if <2 days remaining
4. Exclude certificates already renewed (check new cert)
5. Correlate with certificate management system

**Validation:**

- Packetbeat TLS handshake with certificate near expiration
- Fields: `tls.server.x509.not_after`, `tls.server.x509.subject.common_name`, `destination.ip`
- Test: Use certificate with expiration set to <7 days

---

## (VI) BREACH NOTIFICATION READINESS & CORRELATION

### RULE-41: Correlated Incident - Access + Exfil + Tamper (30min)

**Objective:** Aggregates suspicious access, exfiltration, and log tampering events from same user within 30 minutes - strong breach indicator.

**Data sources:** `auditbeat-*, metricbeat-*, filebeat-*, winlogbeat-*` (all indices)

**GDPR mapping:** Article 33 - Breach notification; Article 32(1) - Security measures; Article 5(1)(f) - Integrity

**Severity:** Critical | **MITRE:** Multi-stage attack

**Query (ES|QL):**

```esql
FROM auditbeat-*, metricbeat-*, filebeat-*, winlogbeat-*
| WHERE @timestamp >= NOW() - 30 minutes
| WHERE (event.action IN ("accessed", "read", "file_read") AND file.path RLIKE ".*sensitive.*")
    OR (process.name IN ("zip", "tar") AND network.bytes > 1048576)
    OR (event.code IN ("1102", "4725") OR message RLIKE ".*(auditd.*stopped|log.*cleared).*")
| STATS 
    access_events = COUNT_IF(event.action IN ("accessed", "read")),
    exfil_events = COUNT_IF(process.name IN ("zip", "tar")),
    tamper_events = COUNT_IF(event.code IN ("1102", "4725"))
  BY user.name, host.name
| WHERE access_events >= 1 AND exfil_events >= 1 AND tamper_events >= 1
| EVAL rule_name = "RULE-41: Correlated Incident (Access+Exfil+Tamper)"
| EVAL severity = "critical"
| KEEP @timestamp, user.name, host.name, access_events, exfil_events, tamper_events, rule_name, severity
```

**Tuning / False Positives:**

1. Require all three categories (access AND exfil AND tamper)
2. Escalate immediately to incident response team
3. Correlate with user's normal behavior baseline
4. Reduce time window to 15 minutes for higher fidelity
5. Whitelist only documented forensic/backup activities

**Validation:**

- Simulate: access sensitive files, create archive, clear event log
- Fields: combination of `event.action`, `process.name`, `event.code`, `user.name`
- Test: Multi-step attack scenario

---

### RULE-42: Multiple GDPR-Relevant Events from Same User

**Objective:** Aggregates 5+ different GDPR-relevant security events from same user in 1 hour.

**Data sources:** `auditbeat-*, metricbeat-*, filebeat-*, winlogbeat-*`

**GDPR mapping:** Article 33 - Breach notification; Article 5(2) - Accountability

**Severity:** High | **MITRE:** Multiple TTPs

**Query (ES|QL):**

```esql
FROM auditbeat-*, metricbeat-*, filebeat-*, winlogbeat-*
| WHERE @timestamp >= NOW() - 1 hour
| WHERE event.category IN ("authentication", "file", "process", "network")
  AND (event.outcome == "failure" 
       OR event.action IN ("accessed", "modified", "deleted", "created")
       OR process.name IN ("sudo", "runas", "net"))
| STATS event_types = COUNT_DISTINCT(event.action) BY user.name, host.name
| WHERE event_types >= 5
| EVAL rule_name = "RULE-42: Multiple GDPR-Relevant Events from Same User"
| EVAL severity = "high"
| KEEP @timestamp, user.name, host.name, event_types, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist power users (DBAs, SysAdmins) with high activity
2. Increase threshold to 10 for service accounts
3. Alert only if events span multiple categories
4. Correlate with user risk score
5. Reduce time window to 30 minutes for executives

**Validation:**

- Generate diverse events: failed login, file access, process execution, network connection
- Fields: `event.category`, `event.action`, `user.name`
- Test: Simulate user performing multiple actions

---

### RULE-43: Ransomware Indicator Chain (File Rename + Encryption)

**Objective:** Detects mass file renaming with suspicious extensions (.encrypted, .locked, .crypted) indicating ransomware.

**Data sources:** `auditbeat-*`, `winlogbeat-*`

**GDPR mapping:** Article 32(1)(c) - Resilience; Article 33 - Breach notification

**Severity:** Critical | **MITRE:** T1486 (Data Encrypted for Impact)

**Query (ES|QL):**

```esql
FROM auditbeat-*, winlogbeat-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE event.action IN ("renamed", "created", "file_rename")
  AND file.path RLIKE ".*\\.(encrypted|locked|crypted|crypt|enc|locky|cerber)$"
| STATS renamed_count = COUNT(*) BY user.name, host.name
| WHERE renamed_count >= 10
| EVAL rule_name = "RULE-43: Ransomware Indicator Chain"
| EVAL severity = "critical"
| KEEP @timestamp, user.name, host.name, renamed_count, rule_name, severity
```

**Tuning / False Positives:**

1. Alert immediately (no threshold delay)
2. Isolate host from network automatically
3. Exclude legitimate encryption tools (BitLocker, VeraCrypt)
4. Lower threshold to 5 for critical file servers
5. Correlate with ransom note file creation (.txt, .html)

**Validation:**

- Rapid file renaming with ransomware extensions
- Fields: `event.action:renamed`, `file.path`, `user.name`
- Test: Rename 10+ files to .encrypted extension

---

### RULE-44: Lateral Movement Pattern Detected

**Objective:** Detects authentication from one host to multiple other hosts within 10 minutes (lateral movement).

**Data sources:** `winlogbeat-*`, `filebeat-*`

**GDPR mapping:** Article 32(1) - Security measures; Article 33 - Breach notification

**Severity:** High | **MITRE:** T1021 (Remote Services)

**Query (ES|QL):**

```esql
FROM winlogbeat-*, filebeat-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE event.category == "authentication" AND event.outcome == "success"
  AND event.action IN ("logon", "network_logon")
| STATS unique_destinations = COUNT_DISTINCT(destination.ip) BY user.name, source.ip
| WHERE unique_destinations >= 5
| EVAL rule_name = "RULE-44: Lateral Movement Pattern Detected"
| EVAL severity = "high"
| KEEP @timestamp, user.name, source.ip, unique_destinations, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist IT admin jump servers
2. Exclude service accounts with legitimate multi-host access
3. Alert only if destinations are not in same subnet
4. Lower threshold to 3 for high-security zones
5. Correlate with recent compromise indicators

**Validation:**

- Multiple successful network logons to different hosts
- Windows Event 4624 (Logon Type 3) to multiple destinations
- Fields: `event.category:authentication`, `destination.ip`, `user.name`, `source.ip`
- Test: Use PSExec or RDP to connect to 5+ hosts

---

### RULE-45: Data Breach Indicators Aggregated (High Severity)

**Objective:** Aggregates all high/critical severity rules triggered by same user/host in 1 hour.

**Data sources:** `auditbeat-*, metricbeat-*, filebeat-*, winlogbeat-*`

**GDPR mapping:** Article 33 - Breach notification; Article 5(2) - Accountability

**Severity:** Critical | **MITRE:** Multiple TTPs

**Query (ES|QL):**

```esql
FROM auditbeat-*, metricbeat-*, filebeat-*, winlogbeat-*
| WHERE @timestamp >= NOW() - 1 hour
| WHERE (event.code IN ("4720", "4732", "1102") 
        OR process.name IN ("zip", "tar", "mysqldump")
        OR file.path RLIKE ".*\\.(encrypted|log)$" AND event.action == "deleted"
        OR event.outcome == "failure" AND event.category == "authentication")
	| STATS 
    rule_count = COUNT(*),
    event_categories = VALUES(event.category)
  BY user.name, host.name
| WHERE rule_count >= 3
| EVAL rule_name = "RULE-45: Data Breach Indicators Aggregated"
| EVAL severity = "critical"
| KEEP @timestamp, user.name, host.name, rule_count, event_categories, rule_name, severity
```

**Tuning / False Positives:**

1. Trigger only if events match 3+ different rule categories
2. Escalate to Security Operations Center (SOC)
3. Automatically create incident ticket
4. Require manual review before automated response
5. Correlate with threat intelligence feeds

**Validation:**

- Trigger multiple high-severity rules from previous sections
- Fields: diverse `event.code`, `process.name`, `file.path`, `user.name`
- Test: Simulate multi-stage attack

---

### RULE-46: Personal Data Access Outside Authorized Systems

**Objective:** Detects access to PII/personal data from systems not designated for data processing.

**Data sources:** `auditbeat-*`, `winlogbeat-*`

**GDPR mapping:** Article 5(1)(b) - Purpose limitation; Article 32(1) - Security measures; Article 35 - DPIA

**Severity:** High | **MITRE:** T1005 (Data from Local System)

**Query (ES|QL):**

```esql
FROM auditbeat-*, winlogbeat-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE event.action IN ("accessed", "read", "opened")
  AND (file.path RLIKE ".*(PII|personal|customer|GDPR|SSN|passport).*"
       OR message RLIKE ".*(SELECT.*FROM users|personal_data).*")
| WHERE host.name NOT IN ("data-warehouse-01", "crm-prod", "hr-system")
| EVAL rule_name = "RULE-46: Personal Data Access Outside Authorized Systems"
| EVAL severity = "high"
| KEEP @timestamp, user.name, host.name, file.path, event.action, rule_name, severity
```

**Tuning / False Positives:**

1. Maintain inventory of authorized data processing systems
2. Whitelist data privacy team for audits
3. Alert only if user role doesn't require PII access
4. Correlate with DPIA (Data Protection Impact Assessment)
5. Lower severity for anonymized/pseudonymized data

**Validation:**

- File access in PII directories from unauthorized host
- Database query accessing personal data tables
- Fields: `file.path`, `host.name`, `user.name`, `event.action`
- Test: Access customer database from non-CRM system

---

### RULE-47: Unauthorized Data Processing Activity

**Objective:** Detects batch processing or automated scripts accessing personal data without documented purpose.

**Data sources:** `auditbeat-*`, `filebeat-*`

**GDPR mapping:** Article 5(1)(a) - Lawfulness; Article 6 - Lawfulness of processing; Article 30 - Records of processing

**Severity:** High | **MITRE:** T1005 (Data from Local System)

**Query (ES|QL):**

```esql
FROM auditbeat-*, filebeat-*
| WHERE @timestamp >= NOW() - 30 minutes
| WHERE (process.name IN ("python", "perl", "ruby", "node", "powershell.exe", "cmd.exe")
        AND process.args RLIKE ".*(SELECT|INSERT|UPDATE|DELETE).*")
    OR (file.path RLIKE ".*\\.(csv|xlsx|json).*" AND event.action == "created" 
        AND file.size > 10485760)
| WHERE user.name NOT IN ("etl-service", "data-pipeline", "reporting-service")
| STATS activity_count = COUNT(*) BY user.name, host.name, process.name
| WHERE activity_count >= 5
| EVAL rule_name = "RULE-47: Unauthorized Data Processing Activity"
| EVAL severity = "high"
| KEEP @timestamp, user.name, host.name, process.name, activity_count, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist approved ETL and reporting processes
2. Correlate with Article 30 processing records
3. Alert only if processing happens outside business hours
4. Require manual review for data science team
5. Lower severity for read-only queries

**Validation:**

- Script execution with database queries or large file creation
- Fields: `process.name`, `process.args`, `file.path`, `file.size`, `user.name`
- Test: Run Python script with SQL queries on personal data

---

### RULE-48: Data Retention Policy Violation (Old Data Accessed)

**Objective:** Detects access to data older than retention policy allows (e.g., >7 years for financial data).

**Data sources:** `auditbeat-*`, `filebeat-*`

**GDPR mapping:** Article 5(1)(e) - Storage limitation; Article 17 - Right to erasure

**Severity:** Medium | **MITRE:** N/A (Compliance)

**Query (ES|QL):**

```esql
FROM auditbeat-*, filebeat-*
| WHERE @timestamp >= NOW() - 24 hours
| WHERE event.action IN ("accessed", "read")
  AND file.path RLIKE ".*(archive|backup|old_data|20[0-1][0-7]).*"
| EVAL file_age_days = (@timestamp - file.created) / 86400000
| WHERE file_age_days > 2555
| EVAL rule_name = "RULE-48: Data Retention Policy Violation"
| EVAL severity = "medium"
| KEEP @timestamp, user.name, file.path, file.created, file_age_days, rule_name, severity
```

**Tuning / False Positives:**

1. Adjust retention period per data category (legal holds)
2. Whitelist archival/compliance team
3. Alert only if data should have been deleted per policy
4. Exclude research/historical analysis with approval
5. Correlate with legal hold status

**Validation:**

- Access to files older than retention policy
- Fields: `file.created`, `file.path`, `event.action`, `user.name`
- Calculate: file age = current time - file.created
- Test: Access archived file from >7 years ago

---

### RULE-49: Cross-Border Data Transfer Detected

**Objective:** Detects data transfers to destinations outside the EU/EEA without documented adequacy decision.

**Data sources:** `metricbeat-*`

**GDPR mapping:** Article 44 - General principle for transfers; Article 45 - Transfers based on adequacy decision

**Severity:** High | **MITRE:** T1041 (Exfiltration)

**Query (ES|QL):**

```esql
FROM metricbeat-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE network.direction == "outbound" OR source.ip RLIKE "^10\\.|^172\\.16\\.|^192\\.168\\."
| WHERE destination.geo.country_iso_code NOT IN ("AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "IS", "LI", "NO")
| STATS total_bytes = SUM(network.bytes) BY destination.geo.country_name, destination.ip, user.name
| WHERE total_bytes > 10485760
| EVAL rule_name = "RULE-49: Cross-Border Data Transfer Detected"
| EVAL severity = "high"
| KEEP @timestamp, user.name, destination.ip, destination.geo.country_name, total_bytes, rule_name, severity
```

**Tuning / False Positives:**

1. Whitelist approved international partners with SCCs
2. Exclude countries with EU adequacy decisions (update list)
3. Alert only if transfer contains PII (DLP correlation)
4. Lower severity for US transfers with Privacy Shield successor
5. Correlate with DPIA for international transfers

**Validation:**

- Network transfer to non-EU/EEA destination
- Fields: `destination.geo.country_iso_code`, `network.bytes`, `destination.ip`
- Test: Transfer data to server in Asia or US

---

### RULE-50: Emergency Breach Response Trigger (Multi-Signal)

**Objective:** Master rule aggregating critical signals - triggers incident response playbook if 2+ critical rules fire within 15 minutes.

**Data sources:** `auditbeat-*, metricbeat-*, filebeat-*, winlogbeat-*`

**GDPR mapping:** Article 33 - Notification of breach; Article 34 - Communication to data subjects

**Severity:** Critical | **MITRE:** Multiple TTPs

**Query (ES|QL):**

```esql
FROM auditbeat-*, metricbeat-*, filebeat-*, winlogbeat-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE (event.code == "1102")
    OR (process.name IN ("zip", "tar") AND network.bytes > 10485760)
    OR (file.path RLIKE ".*\\.(encrypted|locked)$" AND event.action == "renamed")
    OR (event.action == "stopped-service" AND process.name RLIKE ".*(audit|elastic-agent).*")
    OR (user.name RLIKE ".*admin.*" AND event.outcome == "failure" AND event.category == "authentication")
| STATS 
    critical_signals = COUNT_DISTINCT(event.action),
    hosts_affected = COUNT_DISTINCT(host.name),
    users_involved = VALUES(user.name)
  BY host.name
| WHERE critical_signals >= 2
| EVAL rule_name = "RULE-50: EMERGENCY BREACH RESPONSE TRIGGER"
| EVAL severity = "critical"
| KEEP @timestamp, host.name, critical_signals, hosts_affected, users_involved, rule_name, severity
```

**Tuning / False Positives:**

1. Trigger only if signals are from different rule categories
2. Immediately escalate to CISO and DPO
3. Auto-create incident ticket with 72-hour breach notification timer
4. Initiate containment procedures (isolate host)
5. No whitelisting - all triggers require investigation

**Validation:**

- Trigger 2+ critical rules from RULE-17 to RULE-49
- Fields: combination of critical indicators across all categories
- Test: Simulate multi-stage breach scenario

---

---

# FIELD MAPPING ASSUMPTIONS & ECS COMPATIBILITY

## Core ECS Fields Expected

### Timestamp & Identity

- `@timestamp` - Event timestamp (required for all queries)
- `host.name` - Hostname (ECS: host.name)
- `user.name` - Username (ECS: user.name)
- `agent.name` - Agent identifier (ECS: agent.name)

### Network

- `source.ip` - Source IP (ECS: source.ip)
- `destination.ip` - Destination IP (ECS: destination.ip)
- `destination.port` - Destination port (ECS: destination.port)
- `destination.domain` - Destination domain (ECS: destination.domain)
- `network.protocol` - Protocol (ECS: network.protocol)
- `network.bytes` - Bytes transferred (ECS: network.bytes)
- `network.direction` - inbound/outbound (ECS: network.direction)
- `source.geo.country_name` - Source country (ECS: source.geo.country_name)
- `source.geo.country_iso_code` - ISO code (ECS: source.geo.country_iso_code)
- `source.geo.location` - Lat/lon (ECS: source.geo.location)
- `destination.geo.country_name` - Dest country (ECS: destination.geo.country_name)

### Process

- `process.name` - Process name (ECS: process.name)
- `process.args` - Command arguments (ECS: process.args)
- `process.command_line` - Full command line (ECS: process.command_line)
- `process.parent.name` - Parent process (ECS: process.parent.name)
- `process.executable` - Full path (ECS: process.executable)

### File

- `file.path` - File path (ECS: file.path)
- `file.name` - File name (ECS: file.name)
- `file.extension` - File extension (ECS: file.extension)
- `file.size` - File size in bytes (ECS: file.size)
- `file.hash.sha256` - SHA256 hash (ECS: file.hash.sha256)
- `file.created` - Creation timestamp (ECS: file.created)

### Event

- `event.category` - authentication, file, process, network (ECS: event.category)
- `event.action` - accessed, created, deleted, modified, stopped-service (ECS: event.action)
- `event.outcome` - success, failure (ECS: event.outcome)
- `event.code` - Windows Event ID or Linux event code (ECS: event.code)
- `event.module` - file_integrity, auditd, etc. (ECS: event.module)
- `event.dataset` - Dataset name (ECS: event.dataset)
- `event.type` - change, start, end, etc. (ECS: event.type)

### Windows-Specific

- `winlog.event_data.SubjectUserName` - User who performed action
- `winlog.event_data.TargetUserName` - Target user
- `winlog.event_data.MemberName` - Group member
- `winlog.event_data.SubStatusCode` - Auth failure code
- `winlog.event_data.ServiceName` - Service name
- `winlog.event_data.ImagePath` - Service binary path
- `winlog.event_data.TaskName` - Scheduled task name
- `winlog.event_data.TaskContent` - Task XML content
- `winlog.event_data.Reason` - Shutdown reason
- `winlog.event_data.DeviceName` - Device name
- `winlog.event_data.DomainPolicyChanged` - Policy change details
- `winlog.channel` - Event log channel (Security, System, etc.)

### Registry (Windows)

- `registry.path` - Registry key path (ECS: registry.path)

### Monitoring

- `monitor.status` - up/down (ECS: monitor.status)
- `monitor.name` - Monitor name (ECS: monitor.name)

### System Metrics

- `system.filesystem.mount_point` - Mount point (ECS: system.filesystem.mount_point)
- `system.filesystem.used.pct` - Disk usage % (ECS: system.filesystem.used.pct)
- `system.memory.actual.used.pct` - Memory usage % (ECS: system.memory.actual.used.pct)
- `system.memory.actual.used.bytes` - Memory bytes (ECS: system.memory.actual.used.bytes)

### DNS

- `dns.question.name` - DNS query name (ECS: dns.question.name)

### TLS

- `tls.server.x509.subject.common_name` - Cert CN (ECS: tls.server.x509.subject.common_name)
- `tls.server.x509.not_after` - Cert expiration (ECS: tls.server.x509.not_after)

### Message

- `message` - Raw log message (ECS: message)

---

# ONBOARDING CHECKLIST

## 1. Index Configuration

- [ ] Create index patterns in Kibana:
    - `filebeat-*`
    - `winlogbeat-*`
    - `auditbeat-*`
    - `metricbeat-*`
    - `metricbeat-*`
    - `metricbeat-*`
- [ ] Set `@timestamp` as time field for all patterns
- [ ] Verify index templates have ECS mappings

## 2. Agent Installation

- [ ] Deploy Elastic Agent or Beats to all hosts:
    - **Filebeat:** Linux syslog, auth.log, application logs
    - **Winlogbeat:** Windows Security, System, Application logs
    - **Auditbeat:** Linux auditd, file integrity monitoring, process execution
    - **Metricbeat:** System metrics (CPU, RAM, disk)
    - **Packetbeat:** Network flows (HTTP, DNS, TLS)
    - **Heartbeat:** Service availability checks
- [ ] Configure agents to send to Elastic cluster
- [ ] Verify agents are reporting (check Fleet in Kibana)

## 3. Ingest Pipeline Configuration

- [ ] Enable GeoIP enrichment for `source.ip` and `destination.ip`
- [ ] Add user agent parsing if analyzing web logs
- [ ] Configure field extraction for non-ECS formats:
    - Windows: `winlog.event_data.*` → ECS fields
    - Linux: syslog parsing → ECS fields
- [ ] Add timestamp normalization
- [ ] Test pipeline with sample data

## 4. ECS Mapping Validation

- [ ] Run sample queries from rules to verify field availability
- [ ] Check for missing fields (e.g., `user.name`, `process.args`)
- [ ] Map non-ECS fields to ECS equivalents in ingest pipeline
- [ ] Validate Windows Event ID fields (4624, 4625, 4720, etc.)
- [ ] Validate Linux auth.log patterns (SSH, sudo)

## 5. Rule Deployment

- [ ] Import all 50 rules into Elastic Detection Rules
- [ ] Configure alert actions (email, Slack, PagerDuty, ticket system)
- [ ] Set up alert suppression for known false positives
- [ ] Create dashboards for rule monitoring
- [ ] Test each rule with synthetic data

## 6. Baseline & Tuning

- [ ] Collect 7-14 days of baseline data
- [ ] Adjust thresholds based on environment:
    - Failed login attempts (Rule-01)
    - File access counts (Rule-25)
    - DNS query volume (Rule-27)
- [ ] Create whitelists:
    - Admin users (Rule-02, Rule-05)
    - Approved tools (Rule-09, Rule-12)
    - Backup systems (Rule-26, Rule-29)
- [ ] Document approved maintenance windows

## 7. Integration with GDPR Processes

- [ ] Link rules to Article 30 Records of Processing Activities
- [ ] Configure 72-hour breach notification timer (Rule-50)
- [ ] Integrate with DPIA workflow (Rule-46)
- [ ] Set up data retention policy alerts (Rule-48)
- [ ] Document cross-border transfer approvals (Rule-49)

## 8. Incident Response Preparation

- [ ] Create runbooks for critical rules (Rule-17, Rule-18, Rule-41, Rule-50)
- [ ] Define escalation paths (SOC → CISO → DPO)
- [ ] Test incident response procedures
- [ ] Train security team on rule interpretation
- [ ] Schedule quarterly rule review and update

## 9. Documentation

- [ ] Document all whitelists and exceptions
- [ ] Maintain change log for rule modifications
- [ ] Create user guide for security analysts
- [ ] Document GDPR article mappings for audit

## 10. Monitoring & Maintenance

- [ ] Set up alerts for rule performance issues
- [ ] Monitor rule execution times
- [ ] Review false positive rates monthly
- [ ] Update rules for new threats (TTPs)
- [ ] Validate compliance with GDPR changes

---

# VARIANT QUERIES (Top 5 Rules)

## RULE-01 Variants

### Linux-Specific (SSH Failed Logins)

```esql
FROM filebeat-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE message RLIKE ".*sshd.*Failed password.*"
| EVAL user_name = SUBSTRING(message, INDEXOF(message, "for ") + 4, INDEXOF(message, " from") - INDEXOF(message, "for ") - 4)
| EVAL source_ip = SUBSTRING(message, INDEXOF(message, "from ") + 5, INDEXOF(message, " port") - INDEXOF(message, "from ") - 5)
| STATS failed_attempts = COUNT(*) BY source_ip, user_name, host.name
| WHERE failed_attempts >= 5
| EVAL rule_name = "RULE-01: SSH Brute Force (Linux)"
| EVAL severity = "medium"
| KEEP @timestamp, source_ip, user_name, host.name, failed_attempts, rule_name, severity
```

### Windows-Specific (RDP/Network Logon Failures)

```esql
FROM winlogbeat-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE event.code == "4625"
| WHERE winlog.event_data.LogonType IN ("3", "10")
| STATS failed_attempts = COUNT(*) BY winlog.event_data.IpAddress, winlog.event_data.TargetUserName, host.name
| WHERE failed_attempts >= 5
| EVAL rule_name = "RULE-01: RDP/Network Brute Force (Windows)"
| EVAL severity = "medium"
| KEEP @timestamp, winlog.event_data.IpAddress, winlog.event_data.TargetUserName, host.name, failed_attempts, rule_name, severity
```

---

## RULE-09 Variants

### Linux-Specific (useradd with admin groups)

```esql
FROM auditbeat-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE process.name == "useradd" 
  AND (process.args RLIKE ".*-G (sudo|wheel|admin).*" OR process.args RLIKE ".*--groups (sudo|wheel|admin).*")
| EVAL rule_name = "RULE-09: New Admin User Created (Linux)"
| EVAL severity = "high"
| KEEP @timestamp, host.name, user.name, process.args, rule_name, severity
```

### Windows-Specific (Event 4720 + 4732)

```esql
FROM winlogbeat-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE (event.code == "4720" OR event.code == "4732")
| STATS 
    user_created = COUNT_IF(event.code == "4720"),
    admin_added = COUNT_IF(event.code == "4732" AND winlog.event_data.TargetUserName == "Administrators")
  BY winlog.event_data.TargetUserName, host.name
| WHERE user_created >= 1 AND admin_added >= 1
| EVAL rule_name = "RULE-09: New Admin User Created (Windows)"
| EVAL severity = "high"
| KEEP @timestamp, winlog.event_data.TargetUserName, host.name, user_created, admin_added, rule_name, severity
```

---

## RULE-17 Variants

### Systemd-based Linux

```esql
FROM filebeat-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE message RLIKE ".*(systemctl stop auditd|auditd.*stopped).*"
    OR (process.name == "systemctl" AND process.args RLIKE ".*stop auditd.*")
| EVAL rule_name = "RULE-17: Auditd Stopped (systemd)"
| EVAL severity = "critical"
| KEEP @timestamp, host.name, user.name, process.args, message, rule_name, severity
```

### SysV Init-based Linux

```esql
FROM filebeat-*
| WHERE @timestamp >= NOW() - 5 minutes
| WHERE message RLIKE ".*(service auditd stop|/etc/init\\.d/auditd stop).*"
    OR (process.name IN ("service", "init.d") AND process.args RLIKE ".*auditd stop.*")
| EVAL rule_name = "RULE-17: Auditd Stopped (SysV)"
| EVAL severity = "critical"
| KEEP @timestamp, host.name, user.name, process.args, message, rule_name, severity
```

---

## RULE-25 Variants

### Linux-Specific (auditd file access)

```esql
FROM auditbeat-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE event.action IN ("opened-file", "read-file")
  AND file.path RLIKE ".*(home|opt|var)/(confidential|personal|sensitive).*"
| STATS file_count = COUNT_DISTINCT(file.path) BY user.name, host.name
| WHERE file_count >= 50
| EVAL rule_name = "RULE-25: Mass File Access (Linux)"
| EVAL severity = "high"
| KEEP @timestamp, user.name, host.name, file_count, rule_name, severity
```

### Windows-Specific (Event 4663 object access)

```esql
FROM winlogbeat-*
| WHERE @timestamp >= NOW() - 10 minutes
| WHERE event.code == "4663"
  AND winlog.event_data.AccessMask RLIKE ".*(READ|0x1).*"
  AND winlog.event_data.ObjectName RLIKE ".*\\\\(Personal|Confidential|HR|Finance)\\\\.*"
| STATS file_count = COUNT_DISTINCT(winlog.event_data.ObjectName) BY winlog.event_data.SubjectUserName, host.name
| WHERE file_count >= 50
| EVAL rule_name = "RULE-25: Mass File Access (Windows)"
| EVAL severity = "high"
| KEEP @timestamp, winlog.event_data.SubjectUserName, host.name, file_count, rule_name, severity
```

---

## RULE-41 Variants

### High-Sensitivity Environment (Shorter Time Window)

```esql
FROM auditbeat-*, metricbeat-*, filebeat-*, winlogbeat-*
| WHERE @timestamp >= NOW() - 15 minutes
| WHERE (event.action IN ("accessed", "read") AND file.path RLIKE ".*sensitive.*")
    OR (process.name IN ("zip", "tar", "7z") AND network.bytes > 1048576)
    OR (event.code IN ("1102", "4725") OR message RLIKE ".*(auditd.*stopped|log.*cleared).*")
| STATS 
    access_events = COUNT_IF(event.action IN ("accessed", "read")),
    exfil_events = COUNT_IF(process.name IN ("zip", "tar", "7z")),
    tamper_events = COUNT_IF(event.code IN ("1102", "4725")),
    time_span = MAX(@timestamp) - MIN(@timestamp)
  BY user.name, host.name
| WHERE access_events >= 1 AND exfil_events >= 1 AND tamper_events >= 1 AND time_span <= 900000
| EVAL rule_name = "RULE-41: Correlated Incident (15min window)"
| EVAL severity = "critical"
| KEEP @timestamp, user.name, host.name, access_events, exfil_events, tamper_events, time_span, rule_name, severity
```

### Multi-Host Correlation

```esql
FROM auditbeat-*, metricbeat-*, filebeat-*, winlogbeat-*
| WHERE @timestamp >= NOW() - 30 minutes
| WHERE (event.action IN ("accessed", "read") AND file.path RLIKE ".*sensitive.*")
    OR (process.name IN ("zip", "tar") AND network.bytes > 1048576)
    OR (event.code IN ("1102", "4725"))
| STATS 
    access_events = COUNT_IF(event.action IN ("accessed", "read")),
    exfil_events = COUNT_IF(process.name IN ("zip", "tar")),
    tamper_events = COUNT_IF(event.code IN ("1102", "4725")),
    affected_hosts = COUNT_DISTINCT(host.name)
  BY user.name
| WHERE access_events >= 1 AND exfil_events >= 1 AND tamper_events >= 1 AND affected_hosts >= 2
| EVAL rule_name = "RULE-41: Correlated Multi-Host Incident"
| EVAL severity = "critical"
| KEEP @timestamp, user.name, affected_hosts, access_events, exfil_events, tamper_events, rule_name, severity
```

---

**DEPLOYMENT NOTES:**

1. All queries use standard ES|QL syntax compatible with Elasticsearch 8.x+
2. Time windows are optimized for real-time detection (5-30 minutes)
3. Each rule includes explicit `rule_name` and `severity` for downstream processing
4. GDPR mappings enable compliance reporting and audit trails
5. False positive tuning guidance based on real-world SIEM deployments
6. Validation steps ensure rules work before production deployment

**MAINTENANCE:**

- Review rules quarterly for new MITRE TTPs
- Update thresholds based on environment growth
- Add new GDPR articles as regulations evolve
- Integrate with threat intelligence feeds for dynamic updates