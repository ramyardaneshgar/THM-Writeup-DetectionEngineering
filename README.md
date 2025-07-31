e# DetectionEngineering
Detection Engineering - identifying suspicious PowerShell activity using Palantir’s Alerting and Detection Strategy (ADS) Framework.

By Ramyar Daneshgar 


In this lab, I developed a detection strategy for identifying suspicious PowerShell activity using Palantir’s **Alerting and Detection Strategy (ADS) Framework**. The goal was to catch adversaries loading PowerShell (`system.management.automation.dll`) into unexpected processes, a tactic often seen in advanced attacks. Below is a detailed breakdown of the technical process.

---

### **Objective**

detect when PowerShell is loaded into non-native host processes (not `powershell.exe`). Attackers use this method to blend malicious activity into legitimate processes, making it harder to spot. For example, loading PowerShell into `notepad.exe` or `svchost.exe` allows them to execute commands without raising immediate suspicion.

This tactic falls under the **Execution** category in the **MITRE ATT&CK framework**, specifically **T1059.001: PowerShell**. The idea was to identify this behavior early and trigger actionable alerts.

---

### **Breaking Down the Framework**

#### **1. Goal**
The detection goal was to flag processes loading the PowerShell DLL that don’t align with typical usage patterns. This behavior often indicates post-exploitation activity, where an attacker injects PowerShell into another process to:
- Execute encoded commands.
- Establish persistence.
- Move laterally across the environment.

By focusing on these anomalies, the detection strategy aimed to address misconfigurations that might introduce risk.

---

#### **2. Categorization**
This detection was mapped to the **Execution tactic** in the **MITRE ATT&CK framework**, with a focus on behaviors linked to PowerShell abuse. Mapping to MITRE helps analysts correlate this detection with broader attack patterns and understand where it fits in the kill chain.

---

#### **3. Strategy Abstract**
The strategy involved the following steps:
1. **Monitoring Module Loads**:
   - Track the loading of `system.management.automation.dll` across all processes using tools like **Sysmon (Event ID 7)**.
   - Focus specifically on processes other than `powershell.exe`.
2. **Reducing False Positives**:
   - Add enrichment data such as process metadata, command-line arguments, and digital signatures.
   - Maintain a whitelist of legitimate processes known to load PowerShell.
3. **Alert Tuning**:
   - Tune alerts to prioritize behavior indicative of misuse, such as obfuscated commands or non-interactive execution.

The result was a detection strategy built to scale across dynamic environments while remaining actionable for the SOC team.

---

#### **4. Technical Context**
PowerShell, being a native Windows tool, is commonly used for both legitimate administrative tasks and malicious activity. Adversaries favor it because:
- It’s built into Windows, making it trusted by default.
- It supports remote execution, obfuscation, and script-based attacks.

In this case, the focus was on **DLL injections**:
- The PowerShell engine (`system.management.automation.dll`) is the heart of its scripting capabilities.
- Unusual hosts for this DLL, like `explorer.exe` or `svchost.exe`, often indicate malicious intent.

Key tools for implementation:
- **Sysmon**: Captures module load events and provides rich telemetry.
- **SIEMs (e.g., Splunk, ELK)**: Aggregate logs for correlation and alerting.
- **EDR Solutions (e.g., CrowdStrike)**: Offer visibility into process behavior and help identify anomalies.

---

#### **5. Blind Spots & Assumptions**
Detection strategies are only as good as the environment they’re built for. Some key assumptions and blind spots for this strategy included:
- **Assumptions**:
  - Endpoint monitoring tools are functioning correctly, with logs being forwarded to the SIEM without delays or losses.
  - Whitelists are up to date and reflect legitimate activity in the environment.
- **Blind Spots**:
  - Dynamic environments (e.g., cloud workloads) might trigger false positives due to rapid changes.
  - Misconfigured tools or missing logs could leave gaps in visibility.

These blind spots underscore the importance of ongoing validation and tuning.

---

#### **6. False Positives**
Legitimate processes, such as custom automation tools or IT management software, can occasionally load PowerShell modules. These situations generate noise that must be filtered out.

For example:
- A software deployment tool using PowerShell scripts might appear suspicious but is actually benign.
- Regular updates to baseline configurations could also mimic malicious behavior.

To address this:
- A **whitelist** was maintained for known, legitimate processes that frequently load PowerShell.
- Digital signatures and command-line arguments were used to differentiate benign activity from malicious use cases.

---

#### **7. Validation**
Validation is critical in any detection strategy. To test this rule, I simulated a real-world scenario using the following commands:

```powershell
Copy-Item C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Destination C:\windows\temp\unusual-powershell-host-process-test.exe -Force
Start-Process C:\windows\temp\unusual-powershell-host-process-test.exe -ArgumentList '-NoProfile','-NonInteractive','-Windowstyle Hidden','-Command {Get-Date}'
Remove-Item 'C:\windows\temp\unusual-powershell-host-process-test.exe' -Force -ErrorAction SilentlyContinue
```

- **What This Did**:
  1. Cloned `powershell.exe` to a new location (`C:\windows\temp`).
  2. Executed the cloned binary with arguments mimicking attacker behavior (e.g., no profile, hidden window).
  3. Removed the file to simulate attacker cleanup.

- **Outcome**:
  - The detection successfully flagged this activity as an anomaly.
  - Logs from Sysmon and the SIEM provided context, including the process ID, parent process, and command-line arguments, confirming the rule’s accuracy.

---

#### **8. Priority**
This alert was assigned a **medium priority**. While unusual PowerShell activity is often a sign of advanced attacks, false positives from legitimate administrative activity can dilute its criticality. The priority could be elevated in environments with high-risk assets or recent targeted campaigns.

---

#### **9. Response**
Once an alert is triggered, the response involves:
1. **Whitelist Comparison**:
   - Check if the flagged process is in the approved list of legitimate binaries.
2. **Digital Signature Validation**:
   - Verify the binary’s signature to ensure it hasn’t been tampered with.
3. **Command-Line Analysis**:
   - Review arguments passed to the process for signs of obfuscation or encoded payloads (e.g., `-EncodedCommand`).

Tools used for response:
- **Sysmon Event ID 1**: Captures process creation events, providing parent-child process relationships.
- **Process Explorer**: Provides real-time visibility into running processes and loaded modules.
- **Splunk Dashboards**: Correlates logs to identify the extent of the threat.

---

### **Detection as Code (DaC)**
To make this detection scalable, I adopted **Detection as Code (DaC)** principles:
- **Sigma Rules**: Created reusable rules for identifying DLL injections, compatible with multiple SIEMs and EDRs.
- **Automation**: Leveraged CI/CD pipelines to test and deploy detection logic, ensuring rapid updates.
- **Version Control**: Used Git to track changes in detection rules and their effectiveness.

---

### **Takeaways**

1. **Behavior-Based Detection**: Targeting DLL injections and TTPs makes the detection resilient against changes in attacker infrastructure.
2. **Scalability**: Using tools like Sigma and DaC ensures that detection logic can be reused and adapted across environments.
3. **Real-World Validation**: Simulating attacker behavior is essential for verifying detection efficacy and minimizing noise.

