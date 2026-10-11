# SSH Brute-Force Attack Detection Using Splunk

A beginner-friendly cybersecurity project that monitors SSH authentication logs and detects repeated failed login attempts using Splunk Enterprise, Splunk Universal Forwarder, Kali Linux, and Parrot OS.

## 📌 Project Overview

SSH (Secure Shell) is commonly used to access Linux systems remotely. Repeated failed SSH login attempts may indicate password guessing or brute-force activity.

This project demonstrates how to collect Linux authentication logs, forward them to Splunk, and use Splunk Search Processing Language (SPL) to investigate failed login attempts and identify suspicious activity.

## 🎯 Objectives

- Monitor SSH authentication logs in real time.
- Collect logs using Splunk Universal Forwarder.
- Forward log events to Splunk Enterprise.
- Identify failed SSH login attempts.
- Extract source IP addresses and count failed logins.
- Detect repeated failures within a five-minute time window.
- Learn basic SIEM monitoring and security event analysis.

## 🛠️ Tools and Technologies

| Tool | Purpose |
|---|---|
| Kali Linux | Target system and Splunk host |
| Parrot OS | Controlled SSH test client |
| Splunk Enterprise | Log indexing, searching, and analysis |
| Splunk Universal Forwarder | Log collection and forwarding |
| OpenSSH | SSH authentication testing |
| SPL | Security event detection and analysis |

## 🏗️ Lab Architecture

```text
+-----------------------+
|       Parrot OS       |
|   Test SSH Attempts   |
|   192.168.56.4        |
+-----------+-----------+
            |
            | SSH - TCP 22
            v
+-----------------------+
|      Kali Linux       |
|   SSH Server          |
|   /var/log/auth.log   |
|   192.168.56.3        |
+-----------+-----------+
            |
            v
+-----------------------+
| Splunk Universal      |
| Forwarder             |
| TCP Destination 9997  |
+-----------+-----------+
            |
            v
+-----------------------+
|   Splunk Enterprise   |
|   Receive and Index   |
|   Search and Detect   |
+-----------------------+
```

**Note:** These IP addresses represent the example lab configuration. Update them if your network uses different addresses.

## ⚙️ Configuration

### 1. Check SSH Service

On Kali Linux:

```bash
sudo systemctl status ssh
```

Check whether SSH is listening:

```bash
sudo ss -lntp | grep ':22'
```

### 2. Verify Network Connectivity

From Parrot OS:

```bash
ping -c 4 192.168.56.3
```

Check SSH connectivity:

```bash
nc -vz -w 3 192.168.56.3 22
```

### 3. Monitor Authentication Logs

On Kali Linux:

```bash
sudo tail -f /var/log/auth.log
```

Search for authentication failures:

```bash
sudo grep -Ei \
'Failed password|Invalid user|authentication failure' \
/var/log/auth.log
```

### 4. Configure Splunk Receiving

In Splunk Web:

1. Open `http://127.0.0.1:8000`.
2. Navigate to **Settings → Forwarding and receiving**.
3. Select **Configure receiving**.
4. Add receiving port `9997`.

Ensure the receiver is configured before forwarding events.

### 5. Start Splunk Universal Forwarder

```bash
sudo /opt/splunkforwarder/bin/splunk start
```

Check its status:

```bash
sudo /opt/splunkforwarder/bin/splunk status
```

Configure the forwarding destination for a same-host setup:

```bash
sudo /opt/splunkforwarder/bin/splunk add forward-server 127.0.0.1:9997
```

Monitor the authentication log:

```bash
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log -index main -sourcetype auth
```

Check the destination status:

```bash
sudo /opt/splunkforwarder/bin/splunk list forward-server
```

Check monitored files:

```bash
sudo /opt/splunkforwarder/bin/splunk list monitor
```

**Important:** If Splunk Enterprise already monitors the same file, avoid duplicate ingestion. Ensure the Forwarder can read the log file and that its destination index exists.

## 🔎 Splunk Detection Queries

Open **Splunk Web → Search & Reporting** and run the following queries.

### Query 1: Verify Indexed Authentication Events

```spl
index=* source="/var/log/auth.log"
| stats count by index host source sourcetype
```

Purpose: Identify the index containing authentication events.

### Query 2: Find Failed SSH Login Attempts

```spl
index=* source="/var/log/auth.log" "Failed password"
| table _time host _raw
| sort - _time
```

Purpose: Display failed SSH password authentication events.

### Query 3: Investigate a Specific Source IP

```spl
index=* source="/var/log/auth.log" "192.168.56.4"
| table _time host _raw
| sort - _time
```

Purpose: Investigate events associated with the test client IP.

### Query 4: Count Failed Attempts by Source IP

```spl
index=* source="/var/log/auth.log" "Failed password"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count AS failed_attempts by src_ip
| sort - failed_attempts
```

Purpose: Count failed login events associated with each source IP address.

### Query 5: Detect Repeated Failures Within Five Minutes

```spl
index=* source="/var/log/auth.log" "Failed password"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| bin _time span=5m
| stats count AS failed_attempts by _time src_ip
| where failed_attempts >= 3
| sort - failed_attempts
```

Purpose: Flag source IP addresses with three or more matching failed login events in a five-minute time bucket.

**Detection rule:** Three or more failed attempts in five minutes.

This is a basic detection rule. It may produce false positives and does not independently prove malicious activity.

### Query 6: Compare Failed and Successful Password Logins

```spl
index=* source="/var/log/auth.log"
("Failed password" OR "Accepted password")
| rex "(?:Failed|Accepted) password for (?:invalid user )?(?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| eval status=if(like(_raw,"%Failed password%"),"Failed","Successful")
| stats count by src_ip username status
| sort - count
```

Purpose: Summarize failed and successful password authentication events.

## 📊 Expected Results

During controlled testing, the following outcomes are expected:

- SSH authentication events appear in `/var/log/auth.log`.
- Failed login events contain the `Failed password` message.
- Invalid username attempts may contain the `Invalid user` message.
- The source IP identifies the machine initiating the test.
- SPL queries calculate failure counts by IP.
- The five-minute detection query flags IP addresses that meet the configured threshold.

Actual results depend on successful log collection, indexing, and the selected search time range.

## 🛡️ Security Recommendations

- Use SSH key-based authentication where appropriate.
- Disable password authentication when operationally suitable.
- Restrict SSH access to trusted networks.
- Use strong passwords and appropriate account policies.
- Monitor repeated authentication failures.
- Tune alert thresholds to reduce false positives.
- Investigate successful logins following repeated failures.
- Keep operating systems and security tools updated.

## ⚠️ Limitations

- This is a basic lab implementation.
- The detection threshold is static.
- Legitimate users can trigger false positives.
- Distributed attempts may require additional correlation rules.
- The project does not automatically block IP addresses.
- Successful event ingestion must be verified in Splunk.

## 🚀 Future Enhancements

- Create a Splunk dashboard for SSH activity.
- Configure scheduled alerts for repeated failures.
- Correlate failed and successful authentication events.
- Monitor multiple Linux systems.
- Enrich events with threat intelligence.
- Implement controlled incident response workflows.

## 📸 Screenshots

Add screenshots from your own completed lab:

1. SSH service status.
2. Network connectivity between Kali and Parrot.
3. Failed login events in `auth.log`.
4. Splunk receiving port configuration.
5. Universal Forwarder connection status.
6. Authentication events indexed in Splunk.
7. Failed-login SPL query results.
8. Source IP failure counts.
9. Five-minute detection query results.

Suggested repository folder:

```text
screenshots/
├── ssh-service.png
├── network-connectivity.png
├── auth-log.png
├── forwarder-status.png
├── splunk-events.png
├── failed-logins.png
└── brute-force-detection.png
```

Only include screenshots you have actually captured.

## 📚 References

- [Splunk Documentation](https://docs.splunk.com/)
- [Splunk Universal Forwarder Documentation](https://docs.splunk.com/Documentation/Forwarder)
- [OpenSSH Manual](https://www.openssh.com/manual.html)
- [MITRE ATT&CK: Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK: SSH (T1021.004)](https://attack.mitre.org/techniques/T1021/004/)

## ⚖️ Disclaimer

This project is intended for educational and authorized security testing in an isolated lab environment. Perform SSH testing only on systems you own or have explicit permission to assess.

## 👨‍💻 Author

**Name:** Your Name

**GitHub:** [Your GitHub Profile](https://github.com/your-username)

**Project:** SSH Brute-Force Attack Detection Using Splunk
