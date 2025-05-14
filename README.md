# Zero - HackMyVM (Easy)
 
![Zero.png](Zero.png)

## Übersicht

*   **VM:** Zero
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Zero)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 29. Mai 2024
*   **Original-Writeup:** https://alientec1908.github.io/Zero_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "Zero"-Challenge war die Erlangung von User- und System-Rechten auf einem Windows Domain Controller (Windows Server 2016). Der Weg begann mit der Enumeration von Active Directory Benutzern mittels `kerbrute`, wobei `administrator` als gültiger Benutzer identifiziert wurde. Ein umfassender `nmap`-Scan zeigte typische AD-Dienste (Kerberos, LDAP, SMB etc.) und identifizierte den Host als DC01 der Domäne `zero.hmv`. Wichtig war die Feststellung, dass SMBv1 aktiv war. Anonyme LDAP-Abfragen und SMB-Null-Sessions scheiterten oder lieferten keine nützlichen Informationen. Ein Passwort-Bruteforce-Angriff auf `administrator` via WinRM war erfolglos. Ein gezielter `nmap`-Scan mit dem Skript `smb-vuln-ms17-010` bestätigte, dass das System anfällig für die MS17-010 (EternalBlue/EternalRomance) Schwachstelle war. Zur Ausnutzung wurde ein Standalone-Exploit von GitHub geklont und eine Windows Reverse TCP Shell (`ms17-010.exe`) mit `msfvenom` erstellt. Der bereitgestellte Log dokumentiert die Vorbereitung des Exploits, aber nicht dessen erfolgreiche Ausführung oder das Erlangen der Shell und der Flags. Es wird angenommen, dass MS17-010 ausgenutzt wurde, um SYSTEM-Rechte zu erlangen.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `kerbrute`
*   `nmap`
*   `ldapsearch` (versucht)
*   `enum4linux` (versucht)
*   `crackmapexec`
*   `msfconsole` (Metasploit Framework, für Suche und Vorbereitung)
*   `smbmap` (versucht)
*   `git`
*   `msfvenom`
*   Standard Windows-Befehle (impliziert für Flag-Auslesen: `type`)
*   Standard Linux-Befehle (`cd`, `ll`, `python3 http.server` - nicht im Log gezeigt, aber oft Teil des Prozesses)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Zero" gliederte sich in folgende Phasen:

1.  **Reconnaissance (AD Enumeration & Port Scanning):**
    *   *Ein initialer `arp-scan` wurde im Original-Writeup erwähnt, aber für diese Readme wird `kerbrute` als Startpunkt genommen, da es sich um ein AD-Szenario handelt.*
    *   `kerbrute userenum -d zero.hmv --dc 192.168.2.111 [userlist]` identifizierte `administrator` als gültigen Benutzer.
    *   `nmap -sS -sV -A -T5 192.168.2.111 -p-` offenbarte zahlreiche offene Ports, typisch für einen Windows DC (DNS, Kerberos, LDAP, SMB, RPC, WinRM etc.). Hostname `DC01.zero.hmv`, OS Windows Server 2016. SMB Signing war erforderlich, SMBv1 aktiv.

2.  **Further Enumeration Attempts (weitgehend erfolglos):**
    *   LDAP-Abfragen (`ldapsearch`) ohne gültige Credentials scheiterten.
    *   `enum4linux -a 192.168.2.111` scheiterte an der Enumeration von Benutzern (SAMR) und Passwortrichtlinien aufgrund von Zugriffsverweigerung (Null-Session eingeschränkt).
    *   `crackmapexec winrm 192.168.2.111 -u administrator -p rockyou.txt` (WinRM Brute-Force) war erfolglos.
    *   Anonyme SMB-Verbindungen (`smbmap`) scheiterten.

3.  **Vulnerability Scanning & Exploitation Preparation (MS17-010):**
    *   `nmap --script "vuln and safe" -p445 zero.hmv` bestätigte, dass das System **VULNERABLE** für MS17-010 (EternalBlue/EternalRomance, CVE-2017-0143) war.
    *   Metasploit wurde verwendet, um nach MS17-010-Modulen zu suchen (`search ms17`), und `exploit/windows/smb/ms17_010_psexec` wurde ausgewählt.
    *   Ein Standalone-Exploit für MS17-010 wurde von GitHub geklont (`git clone https://github.com/c0d3cr4f73r/MS17-010_CVE-2017-0143.git`).
    *   Eine Windows Reverse TCP Shell (`windows/shell_reverse_tcp`) wurde mit `msfvenom` als `ms17-010.exe` erstellt (LHOST: `192.168.2.199`, LPORT: `4444`).

4.  **Exploitation (MS17-010) & Initial Access (SYSTEM):**
    *   *Der genaue Schritt der Ausführung des MS17-010 Exploits (entweder über Metasploit oder den Standalone-Exploit) und das Erhalten der SYSTEM-Shell sind im bereitgestellten Log nicht dokumentiert.*
    *   Es wird angenommen, dass die MS17-010-Schwachstelle erfolgreich ausgenutzt wurde, um die `ms17-010.exe` auszuführen und eine Reverse Shell mit `NT AUTHORITY\SYSTEM`-Rechten zu erhalten.
    *   User-Flag `HMV{D0nt_r3us3_p4$$w0rd5!}` wurde von `C:\Users\Administrator\Desktop\user.txt` gelesen.
    *   Root-Flag (System-Flag) `HMV{Z3r0_l0g0n_!s_Pr3tty_D4ng3r0u$}` wurde von `C:\Users\Administrator\Desktop\root.txt` gelesen.
    *   Zusätzlich wurden NTLM-Hashes mittels Meterpreter `hashdump` extrahiert, und ein Pass-the-Hash-Angriff mit `smbclient` wurde demonstriert.

## Wichtige Schwachstellen und Konzepte

*   **Active Directory Benutzer-Enumeration (Kerbrute):** Identifizierung gültiger Benutzernamen.
*   **MS17-010 (EternalBlue/EternalRomance, CVE-2017-0143):** Eine kritische RCE-Schwachstelle in SMBv1, die die Übernahme des Systems mit SYSTEM-Rechten ermöglichte.
*   **SMBv1 aktiviert:** Eine Voraussetzung für die Ausnutzung von MS17-010.
*   **Credential Dumping (NTLM Hashes):** Extraktion von Passwort-Hashes aus der SAM-Datenbank ermöglichte Pass-the-Hash.
*   **Pass-the-Hash (PtH):** Authentifizierung mittels NTLM-Hash anstelle eines Passworts.

## Flags

*   **User Flag (`C:\Users\Administrator\Desktop\user.txt`):** `HMV{D0nt_r3us3_p4$$w0rd5!}` (Erlangungsmethode nicht detailliert im Log)
*   **Root Flag (`C:\Users\Administrator\Desktop\root.txt`):** `HMV{Z3r0_l0g0n_!s_Pr3tty_D4ng3r0u$}` (Erlangungsmethode nicht detailliert im Log)

## Tags

`HackMyVM`, `Zero`, `Easy`, `Windows`, `Active Directory`, `Kerbrute`, `MS17-010`, `EternalBlue`, `SMBv1`, `Metasploit`, `msfvenom`, `RCE`, `Privilege Escalation`, `Hashdump`, `Pass-the-Hash`
