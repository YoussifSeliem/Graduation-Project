## Execution (TA0002): The Activation of Malicious Actions

Execution in MITRE ATT&CK encompasses techniques that result in the execution of adversary-controlled code on a local or remote system. Once attackers have established initial access, the next critical step is to run malicious code to achieve their objectives. Execution is essential for attackers to carry out their intended actions, whether they aim to steal data, disrupt operations, or establish deeper control within the network.

MITRE ATT&CK details a variety of techniques that attackers use for Execution. Common techniques include:

**Command and Scripting Interpreter:** Attackers use interpreters like PowerShell, Bash, or Python to execute commands and scripts that facilitate malicious activities. These tools offer flexibility and can often bypass security controls.

**User Execution:** This technique relies on tricking users into running malicious files or programs. Examples include double-clicking on infected email attachments or downloading and running software from untrusted sources.

**Inter-Process Communication:** Attackers exploit mechanisms that allow processes to communicate and share data, such as Dynamic Data Exchange (DDE) or Component Object Model (COM) objects, to execute malicious code.

**Native API:** Leveraging system APIs allows attackers to run code with the same privileges as the compromised application, often evading detection.

**Scheduled Task/Job:** Malicious tasks are scheduled to run at specific times or intervals, using built-in system utilities like Task Scheduler or cron jobs.

**Exploitation for Execution:** Attackers exploit software vulnerabilities to execute arbitrary code. This includes buffer overflow attacks, where malicious code is injected into a vulnerable program's memory.

**Third-Party Software:** Compromising and utilizing legitimate software to execute malicious actions. Attackers may inject code into commonly used applications or replace legitimate executables with malicious versions.

By successfully executing malicious code, attackers can perform a wide range of harmful actions, including data exfiltration, system manipulation, and the establishment of persistence mechanisms. Execution is a pivotal step that enables attackers to progress their operations and achieve their ultimate goals.

The technique we used from this tactic is `Command and Scripting Interpreter: PowerShell` which is actually a sub technique of  `Command and Scripting Interpreter`  

## Command and Scripting Interpreter: PowerShell (T1059.001)

PowerShell is a versatile and powerful scripting language and command-line shell used predominantly in Windows environments for task automation and configuration management. Due to its extensive capabilities and deep integration with the Windows operating system, PowerShell is often leveraged by attackers to execute malicious code, automate tasks, and manipulate systems. This makes it an effective tool for executing a wide range of malicious activities.

MITRE ATT&CK details several techniques attackers use with PowerShell. Common techniques include:

**Remote Command Execution:** Attackers can execute commands on remote systems using PowerShell, allowing them to control multiple machines from a single interface. This is often achieved through Windows Remote Management (WinRM) or other remote execution methods.

**Script Execution:** PowerShell scripts, typically with the .ps1 extension, automate complex tasks. Attackers use scripts to download additional payloads, modify system configurations, or exfiltrate data. These scripts can be run directly from the command line or embedded in other files.

**Fileless Malware:** PowerShell is frequently utilized in fileless malware attacks, where malicious code is executed directly in memory without writing to the disk. This reduces the footprint of the attack and complicates detection and forensic analysis.

**Obfuscation:** Attackers often obfuscate PowerShell scripts to evade detection by security tools. Techniques include encoding scripts in Base64, using aliases, or employing complex variable names to make the script difficult to read and analyze.

**Persistence:** PowerShell can establish persistence on a compromised system. This can be done by creating scheduled tasks, modifying registry keys, or using Windows Management Instrumentation (WMI) to ensure the malicious code runs on system startup.

**Living off the Land:** PowerShell's native presence on Windows systems allows attackers to use it without needing to download additional tools. This minimizes the footprint of their activities and reduces the likelihood of detection.

**Data Exfiltration:** PowerShell scripts can collect and exfiltrate sensitive data from a compromised system. Attackers leverage built-in cmdlets for network communication to send data to an attacker-controlled server.

By leveraging PowerShell, attackers can perform a wide range of malicious actions with minimal detection. The flexibility and power of PowerShell make it an attractive tool for adversaries seeking to execute code, automate tasks, and maintain control over compromised systems.

## Steps for execution

A single simple payload is used, where the command `whoami` is just used to get info which user has fallen to the `phishing` attack and try to gather more info about this account privileges and what files does he has access to in case we need to `exfiltrate` any files.

After getting the reverse shell from the malicious document all we need to do is execute the `whoami` command

![](02.png)


## Preparing for the detection

The same steps from the `initial access` preparation is required, if done then move to the next step. If not go back to the previous chapter.

## Constructing the detection rule

The same steps from the `initial access` constructing the detection rule is used, if done then move to the next step. If not go back to the previous chapter.