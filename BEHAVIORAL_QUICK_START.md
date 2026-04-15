# Interactive Behavioral Analytics - Quick Reference

## What Changed
Your **Behavioral Analytics** dashboard now has **interactive tooltips**, **unit labels**, **axis scales**, and **explanatory legends** on all three charts.

---

## 🎯 What to Look For

### THREAT LEVEL TREND
```
Sample Tooltip on Hover:
┌─────────────────────┐
│ Threat Score        │  ← Title (blue)
│ 67.3 / 100          │  ← Value (green) + unit
│ Aggregate security  │  ← Explanation
│ threat level        │
│ assessment          │
└─────────────────────┘

Y-Axis Shows: 0 → 25 → 50 → 75 → 100 (THREAT SCORE)
Legend: Blue line = Status quo threat assessment
```

**Quick Interpretation:**
- Line at bottom (0-20) = ✅ Safe
- Line in middle (40-60) = ⚠️ Watch carefully  
- Line at top (80+) = 🚨 Threat detected

---

### COMMAND FREQUENCY ANALYSIS
```
Sample Tooltip on Bar Hover:
┌──────────────────────┐
│ Command: curl        │  
│ 45 times executed    │
│ Total invocations of │
│ this command in pods │
└──────────────────────┘

Bar Heights = Relative frequency
Darkest (top) = Most executed
```

**Quick Interpretation:**
✅ **Normal**: ls, cat, curl, echo, python
⚠️ **Suspect**: chmod, wget, nc, bash
🚨 **Critical**: /etc/passwd, /etc/shadow, docker, nc -l

---

### ANOMALY SCORE HEATMAP  
```
Sample Tooltip on Event Bar:
┌────────────────────────────┐
│ ⚠️ ANOMALY EVENT           │  ← Red bar
│ 82.1 / 100 threat          │
│ /bin/bash -i >& /dev/tcp...│
│ Pod: web-app-1             │
│ 14:32:45                   │
└────────────────────────────┘

OR

✓ NORMAL EVENT              ← Green bar
75.3 / 100 threat
ls -la /etc
Pod: dashboard-0
10:15:22

Bar Height = Threat Score (0-100)
🟩 Green = Safe | 🟥 Red = Anomaly
```

**Quick Interpretation:**
- Mostly 🟩 green = Healthy
- Mix of colors = Some concerns  
- Mostly 🟥 red = Active attack

---

## 🖱️ How to Use

### **Step 1:** Navigate to "Behavioral" Tab
Click the **chart icon** in the left sidebar

### **Step 2:** Find a Chart
You'll see three sections:
1. Threat Level Trend (line graph)
2. Command Frequency Analysis (bar chart)
3. Anomaly Score Heatmap (colorful bars)

### **Step 3:** Hover to Reveal
Simply **move your mouse** over any element and a tooltip with **units, values, and explanations** will appear

### **Step 4:** Read the Information
```
Tooltip structure:
Title          ← What is this? (blue text)
Value          ← The number (large, green)
Unit           ← What does it measure? (gray)
Description    ← What does it mean? (lighter text)
```

---

## 📊 Understanding the Scales

### Threat Score (0-100)
| Score | Level | Color | Action |
|-------|-------|-------|--------|
| 0-20 | Safe | 🟢 Green | Monitor normally |
| 21-50 | Caution | 🟡 Yellow | Watch for patterns |
| 51-80 | Alert | 🟠 Orange | Investigate |
| 81+ | Critical | 🔴 Red | Take action NOW |

### Execution Count  
Just the number of times a command ran. More = more activity by that command.

Example: `curl 45 times executed` means the curl command was invoked 45 times total.

### Heatmap Bars
- **Height**: Threat severity (0-100)
- **Color**: Type of event
  - 🟩 Green = Normal operation
  - 🟥 Red = Security anomaly detected

---

## 🚀 Quick Troubleshooting

### "Collecting telemetry..."
→ Dashboard needs 10-20 seconds of data before showing graphs. **Wait a moment.**

### No bars in heatmap?
→ No events occurring yet. **Run a test command** via the Shared Kernel simulator.

### Can't see the tooltip?
→ Move mouse toward **center of the chart**, not too close to edges.

### Charts look blank after tab switch?
→ Click the **"Refresh"** button in the top-right.

---

## 💡 Pro Tips

1. **Watch the Threat Line** - Sharp spikes = sudden anomaly (bad)
2. **Check Top Commands** - Unknown commands in top 5 = suspicious
3. **Monitor Heatmap Color** - More red than usual = investigate
4. **Read the Timestamp** - Know when threats began for correlation
5. **Cross-reference Pods** - Same pod in multiple events = targeted?

---

## 🎓 Example Readings

### Healthy Production Cluster
```
Threat Level: Hovering around 15-25 (low)
Top Commands: curl, python, node, git
Heatmap: ~95% green, occasional yellow
→ ✅ Everything looks normal
```

### Suspicious Activity
```
Threat Level: Suddenly jumped from 20 → 75
Top Commands: bash, nc, wget, chmod (NEW)
Heatmap: Several red bars in 30-second window
→ 🚨 Potential attack - investigate immediately
```

### Planned Maintenance (DevOps Activity)
```
Threat Level: Gradual increase 40 → 55
Top Commands: cmake, gcc, make, git clone
Heatmap: Yellow/orange bars, some red anomalies (expected)
→ ⚠️ Verify with ops team that this is scheduled work
```

---

## 📚 More Help
See **BEHAVIORAL_TOOLTIPS_GUIDE.md** for detailed information about:
- Threat scoring factors
- MITRE ATT&CK mapping
- Advanced interpretation
- Full troubleshooting guide

---

**Your dashboard is now ready! Open http://127.0.0.1:5050 → Click Behavioral → Hover over charts to explore!**
