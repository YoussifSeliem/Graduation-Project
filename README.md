# Adversary Simulation


### Abstraction
Cyberattacks often exploit vulnerabilities in systems, leading to severe consequences such as data breaches, financial loss, and reputational damage. 
Traditional defense strategies primarily focus on reactive measures, which may not be sufficient to counter evolving threats. The dynamic and complex nature of cyber threats requires organizations to adopt a more proactive stance.

One of the critical issues is the lack of visibility into sophisticated attack techniques until after they have occurred. 
This knowledge gap leaves security teams struggling to keep pace with adversaries who constantly evolve their methods. Additionally, many organizations face challenges in translating threat intelligence into actionable defense measures. 
This gap underscores the need for a more comprehensive understanding of how attacks unfold within enterprise environments and how they can be detected and mitigated in real-time.

Our project addresses these problems by simulating a variety of attack scenarios to generate valuable insights and develop more effective detection mechanisms. By viewing cybersecurity from the attacker's perspective, we aim to identify weak points in current defenses and propose enhancements that preemptively counteract potential threats.

### Environment
Our Lab consists of an Attacker Kali Linux machine in the same network with the victim Domain Controller machine and machine contains splunk for mentoring events.

On the Domain controller has splunk forwarder to forward the logs in the domain controller machine to the machine containing splunk.
On the Kali linux machine The attacking scripts will be run to do different attacks on the domain controller.

<img src="/Assets/imgs/network_topology.PNG" alt="network topology">

### Steps
In the attacking side we will follow some techniques from MITRE ATT&CK as a reference and we will try to create a detection rules on splunk for these attacks as a defensive side

The Steps we will follow:
- Reconnaissance
    - Active Scanning
    - Gathering Victim's Identity Information
- Initial Access
    - phishing
- Execution
    - Command and Scripting Interpreter
- Persistence
    - Create User
    - Task Scheduling
- Deception (Defensive part only)
    - Honeypots