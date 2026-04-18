# JMemoryAnalyser v1.0.0

Production Memory Triage Engine and Browser-Based Forensics Workbench  
For Windows Running Process Dumps (.DMP)

---

## Author

Kennedy Aikohi  
Website: https://kennedy-aikohi.com  
GitHub: https://github.com/kennedy-aikohi  
LinkedIn: https://linkedin.com/in/aikohikennedy  
Role: DFIR | Malware Analyst | Purple Team Engineer  

---

## Interface Preview

![JMAnalyser UI](assets/images/jmanalyser-ui.png)

---

## Overview

JMemoryAnalyser is designed to answer a critical question in incident response:

What was this process doing in memory at the time of capture?

When a Windows process dump (.DMP) is collected, it contains a snapshot of:
- Loaded modules
- API imports and dynamically resolved functions
- Memory regions and protection flags
- Threads and execution context
- Strings and embedded indicators

JMemoryAnalyser parses and surfaces these artifacts to support rapid triage and investigation.

---

## Purpose

This tool was built to support fast decision-making during incident response.

Instead of starting with heavy frameworks, JMemoryAnalyser provides immediate visibility into:
- Process behavior
- Injection indicators
- Suspicious API usage
- Memory anomalies

This reduces time between detection and containment, supporting faster recovery and business continuity.

---

## GUI Workbench

Launch using:

```powershell
.\scripts\Launch-JMA-GUI.ps1