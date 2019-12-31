# Nimo-Awesome_repo

<h2><b><u>Usefull Docker Images</u></b></h2>
<ul><p1><b>Vulnerable Apps</b></p1>
<li>https://github.com/citizen-stig/dockermutillidae</li>
<li>https://hub.docker.com/r/opendns/security-ninjas/</li>
<li>https://github.com/remotephone/dvwa-lamp</li>
<li>https://hub.docker.com/r/ismisepaul/securityshepherd/</li>
<li>https://hub.docker.com/r/danmx/docker-owasp-webgoat/</li>
<li>https://github.com/bkimminich/juice-shop</li>
  <li>https://github.com/payatu/Tiredful-API</li>
  <li>jackhammer - One Security vulnerability assessment/management tool: https://github.com/olacabs/jackhammer/blob/master/docker-build.sh</li>
 <li>owtf - Offensive Web Testing Framework: https://github.com/owtf/owtf/tree/develop/docker</li>
 <li>docker-blackeye - container for running the phishing attack using Blackeye: https://github.com/vishnudxb/docker-blackeye </li>
 <li>h8mail - Powerful and user-friendly password finder: https://github.com/khast3x/h8mail/blob/master/Dockerfile</li>
 <li>Instatbox -  a project that spins up temporary Linux systems with instant webshell access from any browser: https://github.com/instantbox/instantbox/blob/master/Dockerfile</li>
  <br>

<p1 class="lead"><b>Misc Docker</b></p1>
<li>https://hub.docker.com/r/blacktop/cuckoo/    https://github.com/blacktop/docker-cuckoo </li>
<li>Script to check docker security(CIS) - https://hub.docker.com/r/diogomonica/docker-bench-security/ </li>
  <li>clair - static analysis of vulnerabilities in application containers: https://github.com/coreos/clair</li>
  <li>WebMap - A Web Dashbord for Nmap XML Report: https://github.com/Rev3rseSecurity/WebMap/tree/v2.1/master/docker</li>
  <li>anchore - centralized service for inspection, analysis and certification of container images: https://github.com/anchore/anchore-engine</li>
<li>https://hub.docker.com/r/ahannigan/docker-arachni/</li>
<li>https://hub.docker.com/r/menzo/sn1per-docker/builds/bqez3h7hwfun4odgd2axvn4/</li>
<li> Portainer - Docker manager - http://portainer.io/install.html</li>
  <ul ul style="list-style-type:circle">
  <li> Connect to local host with persistance : <b>docker run -d -p 9000:9000 -v /var/run/docker.sock:/var/run/docker.sock -v /path/on/host/data:/data portainer/portainer</b></li>
  </ul>
  <li> Kali linux base + web tools installation: https://hub.docker.com/r/kalilinux/kali-linux-docker/
  <ul style="list-style-type:circle">
  <li>apt-get -y install kali-linux-web && apt-get purge</li>
  </ul>
  <li>Malware sample downloader - https://hub.docker.com/r/remnux/maltrieve/ </li>
  <li> Awesome docker repo: https://github.com/veggiemonk/awesome-docker </li>
  <li> OWASP Security Knowledge Framework: https://github.com/blabla1337/skf-flask <br>
  <b>docker run -ti -p 127.0.0.1:443:5443 blabla1337/skf-flask</b></li>
  <li>OWASP security Shepard: https://hub.docker.com/r/ismisepaul/securityshepherd/<br>
  <b>docker run -i -p 80:80 -p 443:443 -t ismisepaul/securityshepherd /bin/bash /usr/bin/mysqld_safe & service tomcat7 start </b><br>
If you don't have authbind installed and configured on your host machine e.g. on Ubuntu you'll need to do the following:
<b><br> 
sudo apt-get install authbind  <br> 
touch /etc/authbind/byport/80  <br> 
touch /etc/authbind/byport/443  <br> 
chmod 550 /etc/authbind/byport/80  <br> 
chmod 550 /etc/authbind/byport/443  <br> 
chown tomcat7 /etc/authbind/byport/80  <br> 
chown tomcat7 /etc/authbind/byport/443</b></li>
</ul>
<li>Whaler - reverse engineer a Docker Image into the Dockerfile: https://github.com/P3GLEG/Whaler</li>
<li>ntopng - https://github.com/lucaderi/ntopng-docker</li>
<li>goca - a FOCA fork written in Go: https://github.com/gocaio/goca</li>
<li>Mondoo - docker image scanner: https://github.com/mondoolabs/mondoo</li>


<p2><b>Misc Usefull Stuff</b></p2>
<ul>
<li>Bypass application whitelisting: http://www.blackhillsinfosec.com/?p=5633</li>
<li>Malcious outlook rules: https://silentbreaksecurity.com/malicious-outlook-rules/ </li>
<li>Great cheatsheets https://highon.coffee/blog/cheat-sheet/ </li>
<li>Headless Browseres https://github.com/dhamaniasad/HeadlessBrowsers </li>
  <li>Linode Linux useful IP commands: https://www.linode.com/docs/networking/linux-static-ip-configuration </li>
  <li>netdata - system for distributed real-time performance and health monitoring: https://github.com/firehol/netdata </li>
  <li>yamot - Yet Another Monitoring Tool: https://github.com/knrdl/yamot</li>
  <li>NSIS (Nullsoft Scriptable Install System) is a professional open source system to create Windows installers: https://sourceforge.net/projects/nsis/</li>
  <li>awesome-pentest: https://github.com/enaqx/awesome-pentest </li>
</ul>

<h2><strong><u>Threat Hunting && Simulation</u></strong></h2>

  <h3><b>Adversary/Threat Simulation</b></h3>
  <ul>
    <p3>
    <span>
   <li>Uber metta: https://github.com/uber-common/metta </li>
  <li> SANS HELK Part 1: https://isc.sans.edu/forums/diary/Threat+Hunting+Adversary+Emulation+The+HELK+vs+APTSimulator+Part+1/23525/ </li>
  <li> SANS HELK Part 2: <font size="1"> https://isc.sans.edu/forums/diary/Threat+Hunting+Adversary+Emulation+The+HELK+vs+APTSimulator+Part+2/23529/ </font></li>
  <li> CALDERA: https://github.com/mitre/caldera </li>
  <li> Infection Monkey: https://github.com/guardicore/monkey || https://www.guardicore.com/infectionmonkey/</li>
    <li>APTSimulator: https://github.com/NextronSystems/APTSimulator</li>
  <li>atomic-red-team: https://github.com/redcanaryco/atomic-red-team </li>
  <li>Red Team Automation(RTA): https://github.com/endgameinc/RTA </li>
  <li>Network Flight Simulator: https://github.com/alphasoc/flightsim </li>
  <li>Redhunt - Virtual Machine for Adversary Emulation and Threat Hunting: https://github.com/redhuntlabs/RedHunt-OS </li>
  <li> Blue Team Training Kit: https://www.bt3.no/ </li>
  <li>UBoat - POC HTTP Botnet designed to replicate a full weaponised commercial botnet: https://github.com/Souhardya/UBoat</li>
  <li>FireProx - FireProx leverages the AWS API Gateway to create pass-through proxies that rotate the source IP address with every request: https://github.com/ustayready/fireprox</li>

</span>
  </p3>
  </ul>
  <h3><b>Payloads / RATS</b></h3>
    <ul>
      <p3>
        <span>
   <li>The Axer - Automatic msfvenom payload generator: https://github.com/ceh-tn/The-Axer </li>
            <li>pwnJS - JS payloads: https://github.com/theori-io/pwnjs </li>
            <li>SpookFlare: https://github.com/hlldz/SpookFlare </li>
          <li>Sharpshooter - payload creation framework for the retrieval and execution of arbitrary CSharp source code: https://www.mdsec.co.uk/2018/03/payload-generation-using-sharpshooter/ || https://github.com/mdsecactivebreach/SharpShooter </li>
          <li>CACTUSTORCH - A JavaScript and VBScript shellcode launcher: https://github.com/mdsecactivebreach/CACTUSTORCH </li>
          <li>DotNetToJScript - A tool to generate a JScript which bootstraps an arbitrary .NET Assembly and class: https://github.com/tyranid/DotNetToJScript </li>
            <li>Fancy Bear - flatl1ne repo: https://github.com/FlatL1neAPT </li>
          <li>ShellPop - generate easy and sofisticated reverse or bind shell commands: https://github.com/0x00-0x00/ShellPop</li>
          <li>Vayne-Rat - C# RAT: https://github.com/TheM4hd1/Vayne-RaT</li>
          <li>avet - AntiVirus Evasion Tool: https://github.com/govolution/avet</li>
          <li>ph0neutria - malware zoo builder that sources samples straight from the wild: https://github.com/phage-nz/ph0neutria</li>
          <li>GreatSCT - tool designed to generate metasploit payloads that bypass common anti-virus solutions and application whitelisting solutions: https://github.com/GreatSCT/GreatSCT</li>
          <li>ASWCrypter - An Bash&Python Script For Generating Payloads that Bypasses Antivirus: https://github.com/AbedAlqaderSwedan1/ASWCrypter </li>
        <li>WePWNise - generates architecture independent VBA code to be used in Office documents or templates and automates bypassing application control and exploit mitigation software: https://github.com/mwrlabs/wePWNise </li>
      <li>BYOB - is an open-source project that provides a framework for security researchers and developers to build and operate a basic botnet to deepen their understanding of the sophisticated malware that infects millions of devices every year and spawns modern botnets:
          https://github.com/malwaredllc/byob </li> 
          <li>Androspy - Backdoor Crypter & Creator with Automatic IP Poisener: https://github.com/TunisianEagles/Androspy </li>
          <li>Phantom-Evasion - an interactive antivirus evasion tool written in python capable to generate (almost) FUD executable even with the most common 32 bit msfvenom payload (lower detection ratio with 64 bit payloads): https://github.com/oddcod3/Phantom-Evasion</li>
          <li>Kage - designed for Metasploit RPC Server to interact with meterpreter sessions and generate payloads: https://github.com/WayzDev/Kage </li>
          <li>pypykatz_server - This is the server part of a server-agent model credential acquiring tool(mimikatz) based on pypykatz: https://github.com/skelsec/pypykatz_server</li>
          <li>macro pack - a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format: https://github.com/sevagas/macro_pack </li>
          <li>Evil Clippy - a cross-platform assistant for creating malicious MS Office documents: https://github.com/outflanknl/EvilClippy</li>
          <li>pixload - Set of tools for creating/injecting payload into images: https://github.com/chinarulezzz/pixload </li>
          <li>Pown.js - is a security testing and exploitation toolkit built on top of Node.js and NPM. Unlike traditional security tools like Metasploits, Pown.js considers frameworks to be an anti-pattern: https://github.com/pownjs/pown/blob/master/README.md </li>
          <li>nodeCrypto - is a linux Ransomware written in NodeJs that encrypt predefined files: https://github.com/atmoner/nodeCrypto</li>
      </span>
     </p3>
          </ul>
            <h3><b>Stealthy Communication / Covert Channel</b></h3>
    <ul>
      <p3>
        <span>
          <li>PowerDNS: https://www.mdsec.co.uk/2017/07/powershell-dns-delivery-with-powerdns/ || https://github.com/mdsecactivebreach/PowerDNS </li>
          <li>Demiguise - generate .html files that contain an encrypted HTA: file:https://github.com/nccgroup/demiguise </li>
          <li>EmbedInHTML - Embed and hide any file in HTML: https://github.com/Arno0x/EmbedInHTML </li>
            <li> DNSCAT2: https://github.com/iagox86/dnscat2 </li>
            <li>DNS-Shell - an interactive Shell over DNS channel: https://github.com/sensepost/DNS-Shell</li>
            <li>Sensepost Data exfiltration Toolkit(DET): https://github.com/sensepost/DET </li>
  <li>Pyexfil: https://github.com/ytisf/PyExfil </li>
            <li>DoxuCannon: https://github.com/audibleblink/doxycannon </li>
          <li>Grok-backdoor: https://github.com/deepzec/Grok-backdoor </li>
          <li>foxtrot C2 - C&C to deliver content and shuttle command execution instructions: https://github.com/dsnezhkov/foxtrot</li>
          <li>Invisi-Shell - bypasses all of Powershell security features (ScriptBlock logging, Module logging, Transcription, AMSI) by hooking .Net assemblies: https://github.com/OmerYa/Invisi-Shell</li>
          <li>SILENTTRINITY: https://github.com/byt3bl33d3r/SILENTTRINITY </li>
          <li>PowerHub - A web application to transfer PowerShell modules, executables, snippets and files while bypassing AV and application whitelisting: https://github.com/AdrianVollmer/PowerHub</li>
          <li>FruityC2 - post-exploitation framework based on the deployment of agents on compromised machines: https://github.com/xtr4nge/FruityC2</li>
          <li>hershell - Simple TCP reverse shell written in Go: https://github.com/lesnuages/hershell</li>
          <li>Reverse Shell Cheat Sheet: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md </li>
          <li>Silver - a general purpose cross-platform implant framework that supports C2 over Mutual-TLS, HTTP(S), and DNS: https://github.com/BishopFox/sliver/blob/master/README.md </li>
          <li>Slackor - A Golang implant that uses Slack as a command and control channel: https://github.com/Coalfire-Research/Slackor </li>
          <li>FudgeC2 - a campaign orientated Powershell C2 framework built on Python3/Flask - Designed for team collaboration, client interaction, campaign timelining, and usage visibility: https://github.com/Ziconius/FudgeC2 </li>
          <li>HRShell - an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities: https://github.com/chrispetrou/HRShell</li>
          <li>DNS-Shell - is an interactive Shell over DNS channel: https://github.com/sensepost/DNS-Shell </li>
          </p3>
        </span>
 </ul>
     
  <h3><b>Post Exploitation</b></h3>
  <ul>
    <p3>
    <span>
      <li>PowerLurk - PowerShell toolset for building malicious WMI Event Subsriptions: https://github.com/Sw4mpf0x/PowerLurk</li>
      <li>Merlin - cross-platform post-exploitation HTTP/2 Command & Control  server and agent written in golang: https://github.com/Ne0nd0g/merlin </li>
      <li>phpsploit - a remote control framework, aiming to provide a stealth interactive shell-like connection over HTTP between client and web server: https://github.com/nil0x42/phpsploit</li>
      <li>PE-Linux - Linux Privilege Escalation Tool: https://github.com/WazeHell/PE-Linux</li>
      <li>bad-Pdf - reate malicious PDF to steal NTLM(NTLMv1/NTLMv2) Hashes from windows machines: https://github.com/deepzec/Bad-Pdf</li>
      <li>novahot - webshell framework for penetration testers: https://github.com/chrisallenlane/novahot</li>
      <li>Windows-Exploit-Suggester - This tool compares a targets patch levels against the Microsoft vulnerability database in order to detect potential missing patches on the target: https://github.com/GDSSecurity/Windows-Exploit-Suggester</li>
      <li>LOLBAS - Living Off The Land Binaries And Scripts - https://github.com/LOLBAS-Project/LOLBAS | https://lolbas-project.github.io/#</li>
      <li>Koadic - COM Command & Control, is a Windows post-exploitation rootkit.Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript): https://github.com/zerosum0x0/koadic </li>
      <li>0xsp-Mongoose - Linux Privilege Escalation intelligent Enumeration Toolkit: https://github.com/lawrenceamer/0xsp-Mongoose </li>
      <li>wmigen - generate Batch, C, C++, C#, Delphi, F#, Java, JScript, KiXtart, Lua, Object Pascal, (Open) Object Rexx, Perl, PHP, PowerShell, Python, Ruby, Tcl, VB .NET or VBScript code for menu selected WMI queries: https://www.robvanderwoude.com/wmigen.php</li>
      <li>CryptonDie - a ransomware developed for study purposes: https://github.com/zer0dx/cryptondie </li>
      <li>CQTools - This toolkit allows to deliver complete attacks within the infrastructure, starting with sniffing and spoofing activities, going through information extraction, password extraction, custom shell generation, custom payload generation, hiding code from antivirus solutions, various keyloggers and leverage this information to deliver attacks: https://4f2bcn3u2m2u2z7ghc17a5jm-wpengine.netdna-ssl.com/wp-content/uploads/2019/03/cqtools-the-new-ultimate-hacking-toolkit-black-hat-asia-2019-2.7z | password: CQUREAcademy#123! | Documentation: https://i.blackhat.com/asia-19/Thu-March-28/bh-asia-Januszkiewicz-CQTools-New-Ultimate-Hacking-Toolkit-wp.pdf </li> 
      </span>
  </p3>
  </ul>
  <h3><b>Social Engineering</b></h3>
  <ul>
    <p3>
      <span>
          <li>blackeye - Phishing Tool, with 32 templates: https://github.com/thelinuxchoice/blackeye</li>
          <li>Phishing-API: https://github.com/curtbraz/Phishing-API</li>
          <li>Social Phish - https://github.com/UndeadSec/SocialFish</li>
          <li>Modlishka is a flexible and powerful reverse proxy, that will take your phishing campaigns to the next level: https://github.com/drk1wi/Modlishka</li>
          <li>The Social-Engineer Toolkit: https://github.com/trustedsec/social-engineer-toolkit</li>
          <li>HiddenEye - Modern Phishing Tool With Advanced Functionality: https://github.com/DarkSecDevelopers/HiddenEye</li>
          <li>o365-attack-toolkit - allows operators to perform an OAuth phishing attack and later on use the Microsoft Graph API to extract interesting information: https://github.com/mdsecactivebreach/o365-attack-toolkit</li>
          <li>Phishing Simulation - mainly aims to increase phishing awareness by providing an intuitive tutorial and customized assessment: https://github.com/jenyraval/Phishing-Simulation</li>
          <li>ShellPhish - Phishing Tool for Instagram, Facebook, Twitter, Snapchat, Github, Yahoo and more: https://github.com/thelinuxchoice/shellphish</li>
      </span>
    </p3>
    </ul><br>

  <h3><b>AIO Tools / Frameworks</b></h3>
  <ul>
    <p3>
    <span>
      <li>PowerSploit - A PowerShell Post-Exploitation Framework: https://github.com/PowerShellMafia/PowerSploit </li>
      <li>Empire: https://www.powershellempire.com/ </li>
      <li>Empire GUI: https://github.com/EmpireProject/Empire-GUI </li>
      <li>One-Lin3r - consists of various one-liners that aids in penetration testing operations: https://github.com/D4Vinci/One-Lin3r</li>
      <li>mad-metasploit - Metasploit custom modules, plugins, resource script: https://github.com/hahwul/mad-metasploit </li>
      <li>EasySploit - Metasploit automation: https://github.com/KALILINUXTRICKSYT/easysploit </li>
      </span>
  </p3>
  </ul><br>
  <h3><b>Hunting Guides / Forensics / MISC</b></h3>
  <ul>
  <p3>
    <span>
  <li>Hunt for C&C channels using bro and rita: https://www.blackhillsinfosec.com/how-to-hunt-command-and-control-channels-using-bro-ids-and-rita/ </li>
  <li>sqrrl hunting email headers: https://sqrrl.com/hunting-email-headers/?utm_source=hs_email&utm_medium=email&utm_content=57387063&_hsenc=p2ANqtz-_PrKGdn4tPttGcvrdPzUazcpHci98ldPOXBJPNG3MssLSS9Ch1xwHq7p6Kq-5NiUlLnTBBasLoM1WT8zUdpLEnKGeFAA&_hsmi=57386424 </li>
      <li> Ultimate AppLocker Bypass List: https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/README.md</li>
       <li>List of binaries and scripts that can be used for other purposes than they are designed to: https://github.com/api0cradle/LOLBAS </li>
  <li> Endgame Malware BEnchmark for Research (ember): https://github.com/endgameinc/ember </li>
      <li>snake - malware storage, centralised and unified storage solution for malicious samples: https://github.com/countercept/snake</li>
      <li>rastrea2r - multi-platform open source tool that allows incident responders and SOC analysts to triage suspect systems and hunt for Indicators of Compromise (IOCs): https://github.com/rastrea2r/rastrea2r </li>
      <li>operative-framework-HD - digital investigation framework, you can interact with websites, email address, company, people, ip address,etc :https://github.com/graniet/operative-framework-HD</li>
      <li>THRecon - Collect endpoint information for use in incident response triage / threat hunting / live forensics: https://github.com/TonyPhipps/THRecon</li>
    <li>Active Directory Kill Chain Attack & Defense: https://github.com/infosecn1nja/AD-Attack-Defense</li>
    <li>Free Blocklists of Suspected Malicious IPs and URLs: https://zeltser.com/malicious-ip-blocklists/</li>
    <li>Endgame event query language(EQL): https://github.com/endgameinc/eql/blob/master/README.md </li>
    <li>Awesome YARA - curated list of awesome YARA rules, tools, and resources: https://github.com/InQuest/awesome-yara/blob/master/README.md </li>
    <li>DeepBlueCLI - PowerShell Module for Threat Hunting via Windows Event Logs: https://github.com/sans-blue-team/DeepBlueCLI </li>
    <li>JA3 - a method for creating SSL/TLS client fingerprints that should be easy to produce on any platform and can be easily shared for threat intelligence: https://github.com/salesforce/ja3/blob/master/README.md
    <li>zBang - is a special risk assessment tool that detects potential privileged account threats in the scanned network: https://github.com/cyberark/zBang/blob/master/README.md</li>
    <li>Pentesting with certutil: https://www.hackingarticles.in/windows-for-pentester-certutil/ </li>
    <li>Tool-X - is a Kali Linux hacking tools installer for Termux and linux system: https://github.com/Rajkumrdusad/Tool-X</li>
    <li>jpcertcc - This site summarizes the results of examining logs recorded in Windows upon execution of the 49 tools which are likely to be used by the attacker that has infiltrated a network: https://jpcertcc.github.io/ToolAnalysisResultSheet/#</li>
    </span>
  </p3>
  </ul>
       <h3><b>Blue Teams - Honeypots / IDS / Traps</b></h3>
    <ul>
      <p3>
        <span>
          <li>honeybits - spread breadcrumbs & honeytokens: https://github.com/0x4D31/honeybits</li>
          <li>DTAG(T-Pot creators) https://github.com/dtag-dev-sec </li>
          <li> rockNSM(IDS) installation notes from SANS: https://isc.sans.edu/diary/rss/22832 </li>
            <li>unfetter: https://github.com/unfetter-analytic/unfetter </li>
             <li>portspoof: https://github.com/drk1wi/portspoof </li>
          <li>GeoLogonalyzer - a utility to perform location and metadata lookups on source IP addresses of remote access logs: https://github.com/fireeye/GeoLogonalyzer </li>
          <li>Dejavu - open source deception framework which can be used to deploys deploy multiple interactive decoys: https://github.com/bhdresh/Dejavu</li>
          <li>gravwell-community-edition: https://www.gravwell.io/blog/gravwell-community-edition</li>
          <li>logz.io: https://logz.io/</li>
          <li>SIEMonster: https://siemonster.com/</li>
          <li>Dsiem - Dsiem is a security event correlation engine for ELK stack, allowing the platform to be used as a       dedicated and full-featured SIEM system: https://github.com/defenxor/dsiem </li>
          <li>CyberSponse - community edtion: https://cybersponse.com/community-edition/</li>
          <li>Dflabs - community edition: https://www.dflabs.com/incman-soar-community-edition/</li>
          <li>Sigma - generic and open signature format that allows you to describe relevant log events in a straight forward manner: https://github.com/Neo23x0/sigma | https://github.com/socprime/SigmaUI </li>
          <li>MozDef - The Mozilla Enterprise Defense Platform (MozDef) seeks to automate the security incident handling process and facilitate the real-time activities of incident handlers: https://github.com/mozilla/MozDef </li>
            </span>
            </p3>
            </ul><br>


<p2><b><u>Web PT</u></b><p2>
<li>Automatic API Attack Tool - Imperva's customizable API attack tool takes an API specification as an input, and generates and runs attacks that are based on it as an output: https://github.com/imperva/automatic-api-attack-tool</li>


<p2><b><u>Online Tools</u></b><p2>
<li>Online packet Analyzer - http://packettotal.com/ </li>
<li>CyberChef: https://gchq.github.io/CyberChef/</li>
<li>Docker Image Analyzer: https://anchore.io/</li>
<li>URL Scanner / Sandbox: https://urlscan.io/</li>
<li>Steve Gibson Shields UP / UPNP Exposure Test: https://www.grc.com/x/ne.dll?rh1dkyd2 </li>
<li>Phish IA: https://app.phish.ai/#/scan_url </li>
<li>Mozilla Observatory: https://observatory.mozilla.org/ </li>
<li>Qualys SSL Labs Server Test: https://www.ssllabs.com/ssltest/ </li>
<li>Qualys SSL Labs Browser Test: https://www.ssllabs.com/ssltest/viewMyClient.html </li>
<li>Explain Shell Commands: https://explainshell.com/ </li>
<li>HTML/CSS/JS interactive Cheatsheet: http://htmlcheatsheet.com/</li>
<li>Misc HTML tools: https://hreftools.com/ </li>
<li>JSfiddle: https://jsfiddle.net/ </li>
<li>social IDE: https://codepen.io/</li>
<li>json path finder: https://jsonpath.com/ </li>
<li>repl.it - online Python compiler: https://repl.it/languages/Python%3F__s=ws9cqndijs3fipi6sacu</li>
<li>JS lint: https://jshint.com/</li>
<li>JSON schema data generator: https://json-schema-faker.js.org/ </li>
  <li>Search for open source repositories on github, gitlab, and bitbucket: https://www.bithublab.org/</li>
  <li>Python Regex tester: https://pythex.org/ </li>
  <li>dnstwister - domain name permutation engine: https://dnstwister.report/ </li>
  <li>mozilla SSL Configuration Generator: https://ssl-config.mozilla.org/ </li>

  <p2><b><u>API Stuff</u></b><p2>
  <li>Postman Cheatsheet: https://postman-quick-reference-guide.readthedocs.io/en/latest/index.html </li>
  <li>explore-with-postman: https://github.com/ambertests/explore-with-postman</li>
  <li>Great collection of examples: https://github.com/DannyDainton</li>
  <li>Test automation university: https://testautomationu.applitools.com/Automation </li>
  <li>Loops with Postman: https://thisendout.com/2017/02/22/loops-dynamic-variables-postman-pt2/</li>
  <li>All CheatSheets: http://overapi.com/ <li>
  <li>Hosted REST API: https://reqres.in/ </li>
  <li>httpbin - A simple HTTP Request & Response Service: http://httpbin.org/</li>
  

<p2><b>Password Lists</b></p2>
<ul>
<li>https://wiki.skullsecurity.org/index.php?title=Passwords</li>
<li>Seclists - https://github.com/danielmiessler/SecLists</li>
</ul>

<p2><b><u>Stress Test / Web Traffic Simulation</u></b><p2>
<li>https://loader.io/</li>
<li>https://a.blazemeter.com/app/sign-in</li>
<li>https://artillery.io/</li>
<li> NodeJS Test Cafe: https://devexpress.github.io/testcafe/ </li>
<li>Google puppeteer(headless chrome): https://github.com/GoogleChrome/puppeteer</li>
<li>GoldenEye - HTTP DoS Test Tool: https://github.com/jseidl/GoldenEye</li>
<li>Cisco TRex - open source, low cost, stateful and stateless traffic generator fuelled by DPDK: https://trex-tgn.cisco.com/</li>
<li>UBoat - Botnet simulator: https://github.com/Souhardya/UBoat </li>

<p2><b><u>XSS Resources</u></b></p2>
<ul>
<li>HTML5: http://html5sec.org/</li>
<li>OWASP: https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet</li>
<li>Reddit: https://www.reddit.com/r/xss/</li>
<li>Js payloads, great tutorials: http://www.xss-payloads.com/index.html</li>
<li>Powerfull web tool for creating event based payloads: http://brutelogic.com.br/webgun/ </li>
<li>Ultimate XSS protection Cheatsheet: https://xenotix.in/The%20Ultimate%20XSS%20Protection%20Cheat%20Sheet%20for%20Developers.pdf </li>
<li>HTML5 attack Vectors: https://dl.packetstormsecurity.net/papers/attack/HTML5AttackVectors_RafayBaloch_UPDATED.pdf </li>
<li>XSS Vulnerability Payload List: https://github.com/ismailtasdelen/xss-payload-list</li>
</ul>
