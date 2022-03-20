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
 <li>envizon - state of the art network visualization and vulnerability reporting tool: https://github.com/evait-security/envizon/tree/master/docker </li>
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
  <li><center> <a target="_blank" rel="no-image" href="https://camo.githubusercontent.com/ed1547b1b7f6060ad464d180a0c28975ba876830/68747470733a2f2f6861646f6c696e742e6769746875622e696f2f6861646f6c696e742f696d672f6361745f636f6e7461696e65722e706e67"><img border="0" src="https://bit.ly/2ODiXs5" width="50" height="50" style="vertical-align:middle" class="CircleBadge CircleBadge--small float-left mr-2"></a>Haskell Dockerfile Linter - A smarter Dockerfile linter that helps you build best practice Docker images: https://github.com/hadolint/hadolint</center> </li>
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
</br>

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

 
<h3><b>Cyber Ranges / Labs</b></h3>
<ul>
    <p3>
    <span>
   <li>Kubernetes Local Security Testing Lab - There's a number of playbooks which will bring up cluster's with a specific mis-configuration that can be exploited: https://github.com/raesene/kube_security_lab</li>
   <li>simulator - a distributed systems and infrastructure simulator for attacking and debugging Kubernetes: simulator creates a Kubernetes cluster for you in your AWS account; runs scenarios which misconfigure it and/or leave it vulnerable to compromise and trains you in mitigating against these vulnerabilities: https://github.com/kubernetes-simulator/simulator</li>
   <li>Splunk attack range: https://github.com/splunk/attack_range</li>
   <li>Red-Baron - a set of modules and custom/third-party providers for Terraform which tries to automate creating resilient, disposable, secure and agile infrastructure for Red Teams: https://github.com/Coalfire-Research/Red-Baron</li>
   <li>HazProne - a Cloud Pentesting Framework that emulates close to Real-World Scenarios by deploying Vulnerable-By-Demand aws resources enabling you to pentest Vulnerabilities within, and hence, gain a better understanding of what could go wrong and why. The framework helps gain practical, AWS Penetration testing knowledge/skills: https://github.com/stafordtituss/HazProne</li>
   <li>CI/CDon't - This project will deploy intentionally vulnerable software/infrastructure to your AWS account: https://hackingthe.cloud/aws/capture_the_flag/cicdont/ </li>
    </span>
  </p3>
  </ul>

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
  <li>Chain Reactor - is an open source framework for composing executables that can simulate adversary behaviors and techniques on Linux endpoints: https://github.com/redcanaryco/chain-reactor </li>
  <li>Redcloud - a powerful and user-friendly toolbox for deploying a fully featured Red Team Infrastructure using Docker.https://github.com/khast3x/Redcloud </li>
      <li>Red Teaming/Adversary Simulation Toolkit - a collection of open source and commercial tools that aid in red team operationshttps://github.com/infosecn1nja/Red-Teaming-Toolkit </li>
      <li>racketeer - Ransomware emulation toolkit: https://github.com/dsnezhkov/racketeer</li>
      <li>- adversary simulation tool written in C# that executes adversary techniques within Windows Active Directory environments. The resulting telemetry can be leveraged to measure and improve the efficacy of a detection engineering program. PurpleSharp leverages the MITRE ATT&CK Framework and executes different techniques across the attack life cycle: execution, persistence, privilege escalation, credential access, lateral movement, etc. It currently supports 47 unique ATT&CK techniques: https://github.com/mvelazc0/PurpleSharp</li>
      <li>pingcastle -  a tool designed to assess quickly the Active Directory security level with a methodology based on risk assessment and a maturity framework: https://github.com/vletoux/pingcastle</li>
      <li>Some red team automation (RTA) python scripts that run on Windows, Mac OS, and *nix. RTA scripts emulate known attacker behaviors and are an easy way too verify that your rules are active and working as expected - https://github.com/elastic/detection-rules/tree/3e511965b49eae69d103b9210765bceee9cb6396/rta</li>
      <li>Teqnix - Penetration Testing Platform. Along with all the cool automation features, some of the benefits of TEQNIX is having access to a set of tools that do not 
					require the user to install or to maintain them. Furthermore, the library of tools is an asset to your testing methodologies ready to be launched.https://teqnix.io/</li>

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
          <li>MalwareBazaar - is a project from abuse.ch with the goal of sharing malware samples with the infosec community, AV vendors and threat intelligence providers: https://bazaar.abuse.ch/ </li>
          <li>RapidPayload - Metasploit Payload Generator: https://github.com/AngelSecurityTeam/RapidPayload</li>
          <li><center><a target="_blank" rel="no-image" href="https://github.com/EgeBalci/sgn/blob/master/README.md"><img border="0" src="https://github.com/EgeBalci/sgn/raw/master/img/banner.png" width="85" height="20" style="vertical-align:middle"></a>SGN - a polymorphic binary encoder for offensive security purposes such as generating statically undetecable binary payloads: https://github.com/EgeBalci/sgn/blob/master/README.md</center></li>
          <li>Arbitrium-RAT - a cross-platform is a remote access trojan (RAT), Fully UnDetectable (FUD), It allows you to control Android, Windows and Linux and doesn't require any firewall exceptions or port forwarding: https://github.com/BenChaliah/Arbitrium-RAT</li>
          <li>ScareCrow - a payload creation framework for generating loaders for the use of side loading (not injection) into a legitimate Windows process (bypassing Application Whitelisting controls): https://github.com/optiv/ScareCrow</li>
          <li>SharpEDRChecker - catches hidden EDRs as well via its metadata checks, more info in a blog post coming soon: https://github.com/PwnDexter/SharpEDRChecker</li>
          <li>ratel -  penetration test tool that allows you to take control of a windows machine: https://github.com/FrenchCisco/RATel </li>
          <li>OffensivePipeline - allows to download, compile (without Visual Studio) and obfuscate C# tools for Red Team exercises: https://github.com/Aetsu/OffensivePipeline </li>
          <li>Limelighter - a tool which creates a spoof code signing certificates and sign binaries and DLL files to help evade EDR products and avoid MSS and sock scruitneyhttps://github.com/Tylous/Limelighter</li>
          <li>Chimera - a (shiny and very hack-ish) PowerShell obfuscation script designed to bypass AMSI and antivirus solutions: https://github.com/tokyoneon/Chimera</li>
          <li>Dent - A framework generates code to exploit vulnerabilties in Microsoft Defender Advanced Threat Protection's Attack Surface Reduction (ASR) rules to execute shellcode without being detected or prevented: https://github.com/optiv/Dent</li>
          <li>onelinepy - Python Obfuscator for FUD Python Code: https://github.com/spicesouls/onelinepy</li>
          <li>MeterPwrShell - automated Tool That Generate A Powershell Oneliner That Can Create Meterpreter Shell On Metasploit,Bypass AMSI,Bypass Firewall,Bypass UAC,And Bypass Windows Defender: https://github.com/GetRektBoy724/MeterPwrShell</li>
          <li>SigFlip -  tool for patching authenticode signed PE files (exe, dll, sys ..etc) in a way that doesn't affect or break the existing authenticode signature, in other words you can change PE file checksum/hash by embedding data (i.e shellcode) without breaking the file signature, integrity checks or PE file functionality: https://github.com/med0x2e/SigFlip</li>
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
          <li>ninja -  C2 server created by Purple Team to do stealthy computer and Active directoty enumeration without being detected by SIEM and AVs: https://github.com/ahmedkhlief/Ninja</li>
          <li>faction framework - a C2 framework for security professionals, providing an easy way to extend and interact with agents. It focuses on providing an easy, stable, and approachable platform for C2 communications through well documented REST and Socket.IO APIs: https://www.factionc2.com/</li>
          <li>chisel - a fast TCP/UDP tunnel, transported over HTTP, secured via SSH: https://github.com/jpillora/chisel</li>
          <li>Udp2raw-tunnel - A Tunnel which turns UDP Traffic into Encrypted FakeTCP/UDP/ICMP Traffic by using Raw Socket, helps you Bypass UDP FireWalls(or Unstable UDP Environment): https://github.com/wangyu-/udp2raw-tunnel</li>
          <li>mubeng - an incredibly fast proxy checker & IP rotator with ease: https://github.com/kitabisa/mubeng</li>
          <li>Interactsh - an Open-Source Solution for Out of band Data Extraction, A tool designed to detect bugs that cause external interactions, For example - Blind SQLi, Blind CMDi, SSRF, etc: https://github.com/projectdiscovery/interactsh</li>
          <li>reverse-ssh - a statically-linked ssh server with a reverse connection feature for simple yet powerful remote accesshttps://github.com/Fahrj/reverse-ssh</li>
          <li>ligolo-ng - a simple, lightweight and fast tool that allows pentesters to establish tunnels from a reverse TCP/TLS connection without the need of SOCKS: https://github.com/tnpitsecurity/ligolo-ng</li>
          <li>Azure Outlook C2 - Azure Outlook Command & Control that uses Microsoft Graph API for C2 communications & data exfiltration: https://github.com/boku7/azureOutlookC2</li>
          <li>interactsh - Open-Source Solution for Out of band Data Extraction, A tool designed to detect bugs that cause external interactions, For example - Blind SQLi, Blind CMDi, SSRF, etc: https://github.com/projectdiscovery/interactsh</li>
          <li>rconn - a multiplatform program for creating reverse connections. It lets you consume services that are behind NAT and/or firewall without adding firewall rules or port-forwarding: https://github.com/jafarlihi/rconn</li>
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
      <li>CQTools - This toolkit allows to deliver complete attacks within the infrastructure, starting with sniffing and spoofing activities, going through information extraction, password extraction, custom shell generation, custom payload generation, hiding code from antivirus solutions, various keyloggers and leverage this information to deliver attacks: https://4f2bcn3u2m2u2z7ghc17a5jm-wpengine.netdna-ssl.com/wp-content/uploads/2019/03/cqtools-the-new-ultimate-hacking-toolkit-black-hat-asia-2019-2.7z | password: CQUREAcademy#123! | This whitepaper by Grzegorz Tworek describes CQRDCache tool usage": https://i.blackhat.com/asia-19/Thu-March-28/bh-asia-Januszkiewicz-CQTools-New-Ultimate-Hacking-Toolkit-wp.pdf </li> 
      <li>PEASS - Privilege Escalation Awesome Scripts SUITE: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite</li>
      <li>Flux-Keylogger -  javascript keylogger with web panel: https://github.com/LimerBoy/Flux-Keylogger</li>
      <li>Adamantium-Thief - Get chromium browsers: passwords, credit cards, history, cookies, bookmarks: https://github.com/LimerBoy/Adamantium-Thief</li>
      <li>chromepass - a python-based console application that generates a windows executable that Decrypt Chrome saved paswords, Send a file with the login/password combinations remotely: https://github.com/darkarp/chromepass/blob/master/README.md</li>
      <li>invoker - The goal is to use this tool when access to some Windows OS features through GUI is restricted: https://github.com/ivan-sincek/invoker</li>
      <li>Talon - a tool designed to perform automated password guessing attacks while remaining undetected. Great for user enumartion in domain environment(LDAP/Kerberos): https://github.com/optiv/talon | Great blog post regarding the attack: https://www.optiv.com/explore-optiv-insights/blog/digging-your-talons-new-take-password-guessing </li>
      <li>ADE - ActiveDirectoryEnum: https://github.com/CasperGN/ActiveDirectoryEnumeration </li>
      <li>PYTMIPE - PYthon library for Token Manipulation and Impersonation for Privilege Escalation: https://github.com/quentinhardy/pytmipe</li>
      <li>Invoke-PSImage - Encodes a PowerShell script in the pixels of a PNG file and generates a oneliner to execute: https://github.com/peewpw/Invoke-PSImage</li>
      <li>wynis - Just a powershell scripts for auditing security with CIS BEST Practices Windows 10 and Window Server 2016: https://github.com/Sneakysecdoggo/Wynis</li>
      <li>emp3r0r - linux post-exploitation framework written in go: https://github.com/jm33-m0/emp3r0r</li>
      <li><a target="_blank" rel="no-image" href="https://github.com/vulmon/Vulmap"><img border="0" src="https://raw.githubusercontent.com/vulmon/Vulmap/master/Vulmap-Windows/vulmap-logo.png" width="65" height="35" style="vertical-align:middle"></a>Vulmap - online local vulnerability scanner project. It consists of online local vulnerability scanning programs for Windows and Linux operating systems. These scripts can be used for defensive and offensive purposes: https://github.com/vulmon/Vulmap </li>
      <li>traitor - automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy: https://github.com/liamg/traitor</li>
      <li>pwncat - a post-exploitation platform for Linux targets. It started out as a wrapper around basic bind and reverse shells and has grown from there. It streamlines common red team operations while staging code from your attacker machine, not the target: https://github.com/calebstewart/pwncat </li>
      <li>reverse-shell-generator - Hosted Reverse Shell generator with a ton of functionality: https://github.com/0dayCTF/reverse-shell-generator </li>
      <li>Go-RouterSocks - this tool will expose one socks port and route the traffic through the configured path: https://github.com/nodauf/Go-RouterSocks</li>
      <li>GodSpeed - a robust and intuitive manager for reverse shells: https://github.com/redcode-labs/GodSpeed</li>
      <li>SharpHound - C# Rewrite of the BloodHound Ingestor: https://github.com/BloodHoundAD/SharpHound3</li>
      <li>Max Bloodhound - Maximizing BloodHound with a simple suite of tools: https://github.com/knavesec/Max</li>
      <li>SNOWCRASH - polyglot payload generator. Creates a script that can be launched on both Linux and Windows machines: https://github.com/redcode-labs/SNOWCRASH</li>
      <li>PoisonApple - command-line tool to perform various persistence mechanism techniques on macOS: https://github.com/CyborgSecurity/PoisonApple</li>
      <li>DripLoader - Evasive shellcode loader for bypassing event-based injection detection, without necessarily suppressing event collection: https://github.com/xinbailu/DripLoader</li>
      <li>r77 Rootkit - a ring 3 Rootkit that hides entities from all processes: https://github.com/bytecode77/r77-rootkit</li>
      <li>SharpHook - inspired by the SharpRDPThief project, It uses various API hooks in order to give us the desired credentials.: https://github.com/IlanKalendarov/SharpHook</li>
      <li>PowerShdll - Run PowerShell with dlls only. Does not require access to powershell.exe as it uses powershell automation dlls.
      PowerShdll can be run with: rundll32.exe, installutil.exe, regsvcs.exe, regasm.exe and regsvr32.exe: https://github.com/p3nt4/PowerShdll/tree/master/dll</li>
      <li>PSAmsi - a tool for auditing and defeating AMSI signatures: https://github.com/cobbr/PSAmsi</li>
      <li>OffensivePipeline -  allows to download, compile (without Visual Studio) and obfuscate C# tools for Red Team exercises: https://github.com/Aetsu/OffensivePipeline</li>
      </span> 
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
          <li>zphisher - upgrdaed version(fork) of Shellphish: https://github.com/htr-tech/zphisher</li>
          <li>nexphisher - Advanced phishing tool: https://github.com/htr-tech/nexphisher</li>
          <li>maskphish - a simple script to hide phishing URL under a normal looking URL(google.com or facebook.com): https://github.com/jaykali/maskphish</li>
          <li>Gophish - phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training: https://github.com/gophish/gophish
          <ul>
          <li>How to set up gophish to evade security controls: https://www.sprocketsecurity.com/blog/never-had-a-bad-day-phishing-how-to-set-up-gophish-to-evade-security-controls</li>
          <li>The Ultimate Guide to Phishing - Learn how to Phish using EvilGinx2 and GoPhish: https://sidb.in/2021/08/03/Phishing-0-to-100.html</li>
          </ul>
          </li>
          <li>SniperPhish -  a phishing toolkit for pentester or security professionals to enhance user awareness by simulating real-world phishing attacks. SniperPhish helps to combine both phishing emails and phishing websites you created to centrally track user actions: https://github.com/GemGeorge/SniperPhish</li>
          <li>phishmonger - Phishing platform designed for pentesters. This tool allows us to craft phishing emails in Outlook, clone them quickly, automatically template them for mass distribution, test email templates, schedule phishing campaigns, and track phishing results. Phishmonger is not just GoPhish in Node! You do not have to set up a separate mail server. Phishmonger itself is a mail server: https://github.com/fkasler/phishmonger</li>
          <li>awsssome_phish - phish aws sso code with dynamic url creation with lambda function: https://github.com/sebastian-mora/awsssome_phish</li>
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
      <li>Starkiller - Frontend for Powershell Empire. It is an Electron application written in VueJS: https://github.com/BC-SECURITY/Starkiller </li>
      <li>One-Lin3r - consists of various one-liners that aids in penetration testing operations: https://github.com/D4Vinci/One-Lin3r</li>
      <li>mad-metasploit - Metasploit custom modules, plugins, resource script: https://github.com/hahwul/mad-metasploit </li>
      <li>EasySploit - Metasploit automation: https://github.com/KALILINUXTRICKSYT/easysploit </li>
      <li>pwndrop - self-deployable file hosting service for sending out red teaming payloads or securely sharing your private files over HTTP and WebDAV: https://github.com/kgretzky/pwndrop</li>
      <li><center><a target="_blank" rel="no-image" href="https://github.com/cobbr/Covenant"><img border="0" src="https://raw.githubusercontent.com/wiki/cobbr/Covenant/covenant.png" width="90" height="20" style="vertical-align:middle"></a> - a .NET command and control framework that aims to highlight the attack surface of .NET, make the use of offensive .NET tradecraft easier, and serve as a collaborative command and control platform for red teamers: https://github.com/cobbr/Covenant</center></li>
      <li>SnitchDNS - s a database driven DNS Server with a Web UI, written in Python and Twisted, that makes DNS administration easier with all configuration changed applied instantly without restarting any system services: https://github.com/ctxis/SnitchDNS</li>
      <li>prelude Operator - the first intelligent and autonomous platform built to attack, defend and train your critical assets through continuous red teaming: https://github.com/preludeorg | https://www.prelude.org/platform/operator | https://www.youtube.com/channel/UCZyx-PDZ_k7Vuzyqr4-qK9A </li>
      <li>ARTi-C2 - is a modern execution framework built to empower security teams to scale attack scenario execution from single and multi-breach point targets with the intent to produce actionable attack intelligence that improves the effectiveness security products and incident response: https://github.com/blackbotinc/Atomic-Red-Team-Intelligence-C2</li>
      <li>PowerSharpPack - many usefull offensive CSharp Projects wraped into Powershell for easy usage: https://github.com/S3cur3Th1sSh1t/PowerSharpPack</li>
      <li>zuthaka - a collaborative free open-source Command & Control integration framework that allows developers to concentrate on the core function and goal of their C2: https://github.com/pucarasec/zuthaka</li>
      <li>bantam - an advanced PHP backdoor management tool, with a lightweight server footprint, multi-threaded communication, and an advanced payload generation and obfuscation tool: https://github.com/gellin/bantam</li>
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
    <li>Slingshot C2 Matrix Edition - made in collaboration with SANS, Ryan O'Grady, and C2 Matrix contributors. The goal is to lower the learning curve of installing each C2 framework and getting you straight to testing which C2s work against your organization: https://howto.thec2matrix.com/slingshot-c2-matrix-edition</li>
    <li>uncoder.io - online translator for SIEM saved searches, filters, queries, API requests, correlation and Sigma rules to help SOC Analysts, Threat Hunters and SIEM Engineers: https://uncoder.io/</li>
    <li>F-secure - Attack Detection Fundamentals: https://labs.f-secure.com/blog/attack-detection-fundamentals-initial-access-lab-1/</li>
    <li>PwnDoc - a pentest reporting application making it simple and easy to write your findings and generate a customizable Docx report: https://github.com/pwndoc/pwndoc </li>
    <li>ThreatPursuit-VM - MANDIANT THREAT INTELLIGENCE VM: https://github.com/fireeye/ThreatPursuit-VM</li>
    <li>KQL Internals: https://identityandsecuritydotcom.files.wordpress.com/2020/08/kql_internals_hk.pdf </li>
    <li>jarm - an active Transport Layer Security (TLS) server fingerprinting tool(by CRM): https://github.com/salesforce/jarm</li>
    <li>BruteShark - a Network Forensic Analysis Tool (NFAT) that performs deep processing and inspection of network traffic (mainly PCAP files): https://github.com/odedshimon/BruteShark </li>
    <li>Name-that-hash - will name that hash type: https://github.com/HashPals/Name-That-Hash</li>
    <li>Windows & Active Directory Exploitation Cheat Sheet and Command Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference/</li>
    <li>nzyme - a free and open WiFi defense system that detects and physically locates threats using an easy to build and deploy sensor system: https://www.nzyme.org/</li>
    <li>Certified Pre-Owned - Abusing Active Directory Certificate Services: https://posts.specterops.io/certified-pre-owned-d95910965cd2</li>
    <li>pimpmykali - a shell script that fixes bunch a bugs on a Kali Linux virtual machines https://github.com/Dewalt-arch/pimpmykali</li>

    </span>
  </p3>
  </ul>
       <h3><b>Blue Teams - Honeypots / IDS / Traps/ CTR</b></h3>
    <ul>
      <p3>
        <span>
          <li>honeybits - spread breadcrumbs & honeytokens: https://github.com/0x4D31/honeybits</li>
          <li>DTAG(T-Pot creators) https://github.com/dtag-dev-sec </li>
          <li> rockNSM(IDS) installation notes from SANS: https://isc.sans.edu/diary/rss/22832 </li>
          <li><a target="_blank" rel="no-image" href="https://securityonionsolutions.com/software/"><img border="0" src="https://pbs.twimg.com/profile_images/1285648758525526017/gQFtcr9m.jpg" width="60" height="50" style="vertical-align:middle"></a><center>Security Onion 2 - free and open source Linux distribution for threat hunting, enterprise security monitoring, and log management. It includes TheHive, Playbook and Sigma, Fleet and osquery, CyberChef, Elasticsearch, Logstash, Kibana, Suricata, Zeek, Wazuh, and many other security tools: https://securityonionsolutions.com/software/ | https://docs.securityonion.net/en/2.3/about.html</center></li>
            <li>unfetter: https://github.com/unfetter-analytic/unfetter </li>
             <li>portspoof: https://github.com/drk1wi/portspoof </li>
          <li>GeoLogonalyzer - a utility to perform location and metadata lookups on source IP addresses of remote access logs: https://github.com/fireeye/GeoLogonalyzer </li>
          <li>Dejavu - open source deception framework which can be used to deploys deploy multiple interactive decoys: https://github.com/bhdresh/Dejavu</li>
          <li><a target="_blank" rel="no-image" href="https://github.com/fireeye/capa"><img border="0" src="https://github.com/fireeye/capa/raw/master/.github/logo.png" width="120" height="50" style="vertical-align:middle"></a> - detects capabilities in executable files. You run it against a PE file or shellcode and it tells you what it thinks the program can do </li>
          <li>gravwell-community-edition: https://www.gravwell.io/blog/gravwell-community-edition</li>
          <li>logz.io: https://logz.io/</li>
          <li>SIEMonster: https://siemonster.com/</li>
          <li>Dsiem - Dsiem is a security event correlation engine for ELK stack, allowing the platform to be used as a       dedicated and full-featured SIEM system: https://github.com/defenxor/dsiem </li>
          <li>siembol - provides a scalable, advanced security analytics framework based on open-source big data technologies. Siembol normalizes, enriches, and alerts on data from various sources, which allows security teams to respond to attacks before they become incidents: https://github.com/G-Research/siembol</li>
          <li>CyberSponse - community edtion: https://cybersponse.com/community-edition/</li>
          <li>Dflabs - community edition: https://www.dflabs.com/incman-soar-community-edition/</li>
          <li><a target="_blank" rel="no-image" href="https://thehive-project.org/"><img border="0" src="https://thehive-project.org/assets/img/logos/thehive.svg" width="80" height="35" style="vertical-align:middle"></a> - A scalable, open source and free Security Incident Response Platform, tightly integrated with MISP: https://thehive-project.org/ </li>
          <li>Sigma - generic and open signature format that allows you to describe relevant log events in a straight forward manner: https://github.com/Neo23x0/sigma | https://github.com/socprime/SigmaUI </li>
          <li>MozDef - The Mozilla Enterprise Defense Platform (MozDef) seeks to automate the security incident handling process and facilitate the real-time activities of incident handlers: https://github.com/mozilla/MozDef </li>
          <li><a target="_blank" rel="no-image" href="https://www.opencti.io/en/"><img border="0" src="https://www.opencti.io/wp-content/uploads/2019/02/logo_text.png" width="120" height="35" style="vertical-align:middle"></a> - Unified platform for all levels of Cyber Threat Intelligence: https://www.opencti.io/en/</li>
          <li><a target="_blank" rel="no-image" href="https://wazuh.com/"><img border="0" src="https://wazuh.com/wp-content/themes/wazuh/assets/images/wazuh_logo.svg" width="80" height="35" style="vertical-align:middle"></a> - enterprise-ready security monitoring solution for threat detection, integrity monitoring, incident response and compliance: https://wazuh.com/</li>
          <li>spidertrap - Trap web crawlers and spiders in an infinite set of dynamically generated webpage: https://github.com/adhdproject/adhdproject.github.io/blob/master/Tools/Spidertrap.md </li>
          <li>ElastAlert - a simple framework for alerting on anomalies, spikes, or other patterns of interest from data in Elasticsearch: https://github.com/Yelp/elastalert</li>
          <li>glastof - is a Python web application honeypot founded by Lukas Rist:https://github.com/mushorg/glastopf </li>
          <li>compot - is a low interactive server side Industrial Control Systems honeypot designed to be easy to deploy, modify and extend: http://conpot.org/ </li>
          <li>jimi - an automation first no-code platform designed and developed originally for Security Orchestration and Response: https://github.com/z1pti3/jimi</li>
          <li>Malcolm - an easily deployable network analysis tool suite for full packet capture artifacts (PCAP files) and Zeek logs: https://github.com/idaholab/Malcolm/blob/master/README.md</li>
          <li><center><a target="_blank" rel="no-image" href="https://honeydb.io/"><img border="0" src="https://honeydb.io/static/img/honeydb.png" width="40" height="40" style="vertical-align:middle"></a>HoneyDB - provides real time data of honeypot activity. This data comes from honeypot sensors deployed globally on the Internet: https://honeydb.io/</center></li>
          <li><a target="_blank" rel="no-image" href="https://github.com/saferwall/saferwall"><img border="0" src="https://camo.githubusercontent.com/88d5bf65402c828dfa402bf9fd700441c2975efa/68747470733a2f2f692e696d6775722e636f6d2f7a6a434f4b506f2e706e67" width="65" height="50" style="vertical-align:middle"></a> -  malware analysis platform: https://github.com/saferwall/saferwall </li>
          <li><a target="_blank" rel="no-image" href="https://github.com/secureCodeBox/secureCodeBox"><img border="0" src="https://github.com/secureCodeBox/secureCodeBox/raw/master/docs/resources/logo.png" width="80" height="25" style="vertical-align:middle"></a> - a docker based, modularized toolchain for continuous security scans of your software project: https://github.com/secureCodeBox/secureCodeBox</li>
          <li>Detection Lab - this lab has been designed with defenders in mind. Its primary purpose is to allow the user to quickly build a Windows domain that comes pre-loaded with security tooling and some best practices when it comes to system logging configurations: https://github.com/clong/DetectionLab</li>
          <li>vulnerable-AD - create a vulnerable active directory that's allowing you to test most of active directory attacks in local lab: https://github.com/WazeHell/vulnerable-AD</li>
          <li>ADLab - a tool created in PowerShell to quickly setup an Active directory lab for testing purposes. This tool can help setup a Domain controller and Workstation in a lab environment quickly and effectively: https://browninfosecguy.com/Active-Directory-Lab-Setup-Tool | https://github.com/browninfosecguy/ADLab</li>
          <li>BadBlood -  fills a Microsoft Active Directory Domain with a structure and thousands of objects: https://github.com/davidprowe/BadBlood</li>
          <li>PurpleCloud - Pentest Cyber Range for a small Active Directory Domain. Automated templates for building your own Pentest/Red Team/Cyber Range in the Azure cloud: https://github.com/iknowjason/PurpleCloud </li>
          <li>Azure purple team lab by BLackHills InfoSec:  https://www.blackhillsinfosec.com/how-to-applied-purple-teaming-lab-build-on-azure-with-terraform/ | https://github.com/DefensiveOrigins/APT-Lab-Terraform </li>
          <li>ATTPwn - a computer security tool designed to emulate adversaries. The tool aims to bring emulation of a real threat into closer contact with implementations based on the techniques and tactics from the MITRE ATT&CK framework: https://github.com/ElevenPaths/ATTPwn</li>
          <li>Redcloud -  a powerful and user-friendly toolbox for deploying a fully featured Red Team Infrastructure using Docker: https://github.com/khast3x/Redcloud </li>
          <li>BlueCloud - Cyber Range deployment of HELK and Velociraptor! Automated terraform deployment of one system running HELK + Velociraptor server with one registered Windows endpoint in Azure or AWS: https://github.com/iknowjason/BlueCloud</li>
          <li>NERVE - Network Exploitation, Reconnaissance & Vulnerability Engine: https://github.com/PaytmLabs/nerve</li>
          <li>CHAPS - is a PowerShell script for checking system security settings where additional software and assessment tools, such as Microsoft Policy Analyzer, cannot be installed: https://github.com/cutaway-security/chaps</li>
          <li>Brim - open source desktop application for security and network specialists. Brim makes it easy to search and analyze data from packet captures like those created by Wireshark and structured logs, especially from the Zeek network analysis framework: https://github.com/brimsec/brim </li>
          <li><a target="_blank" rel="no-image" href="http://openuba.org/"><img border="0" src="http://openuba.org/img/logo.png" width="85" height="15" style="vertical-align:middle"></a> - A FLEXIBLE OPEN SOURCE UEBA PLATFORM USED FOR SECURITY ANALYTICS: http://openuba.org/</li>
          <li>Intel Owl - OSINT solution to get threat intelligence data about a specific file, an IP or a domain from a single API at scale: https://github.com/intelowlproject/IntelOwl</li>
          <li>Intrigue Core - open attack surface enumeration engine. It integrates and orchestrates a wide variety of  security data sources, distilling them into a normalized object model: https://core.intrigue.io/</li>
          <li>Awesome CobaltStrike Defence: https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence </li>
          <li>Crossfeed - a tool that continuously enumerates and monitors an organization's public-facing attack surface in order to discover assets and flag potential security flaws: https://github.com/cisagov/crossfeed</li>
          <li>Awesome Incident Response - https://github.com/meirwah/awesome-incident-response</li>

            </span>
            </p3>
            </ul><br>


<h3><b>Web Security</h3></b>
<ul>
<li>Automatic API Attack Tool - Imperva's customizable API attack tool takes an API specification as an input, and generates and runs attacks that are based on it as an output: https://github.com/imperva/automatic-api-attack-tool</li>
<li>Taipan - an automated web application vulnerability scanner that allows to identify web vulnerabilities in an automatic fashion: https://github.com/enkomio/Taipan/blob/master/README.md </li>
<li>fuzz-lightyear -  pytest-inspired, DAST framework, capable of identifying vulnerabilities in a distributed, micro-service ecosystem through stateful Swagger fuzzing: https://github.com/Yelp/fuzz-lightyear/blob/master/README.md</li>
<li>GoSpider - gast web spider written in Go: https://github.com/jaeles-project/gospider</li>
<li>XSS-Freak - XSS scanner fully written in python3. It crawls the website for all possible links and directories to expand its attack scope. Then it searches them for input tags and then launches a bunch of XSS payloads: https://github.com/hacker900123/XSS-Freak</li>
<li><center><a target="_blank" rel="no-image" href="https://github.com/anouarbensaad/vulnx"><img border="0" src="https://i.ibb.co/ZxxFqxQ/vxv2.png" width="80" height="50" style="vertical-align:middle"></a>vulnx - Intelligent Bot Auto Shell Injector that detects vulnerabilities in multiple types of Cms: https://github.com/anouarbensaad/vulnx</center></li>
<li><center><a target="_blank" rel="no-image" href="https://github.com/flipkart-incubator/Astra"  class="CircleBadge CircleBadge--small float-left mr-2"><img border="0" src="https://bit.ly/371kPmF" width="120" height="50" style="vertical-align:middle" class="CircleBadge-icon"></a>Astra - REST API penetration testing tool: https://github.com/flipkart-incubator/Astra</center></li>
<li><a target="_blank" rel="no-image" href="https://github.com/thewhiteh4t/finalrecon"><img border="0" src="https://bit.ly/2zQrKDn" width="80" height="50" style="vertical-align:middle"></a><center>finalrecon - fast and simple python script for web reconnaissance: https://github.com/thewhiteh4t/finalrecon</center></li>
  <li>Payloads - A collection of web attack payloads: https://github.com/foospidy/payloads </li>
  <li>AuthMatrix - an extension to Burp Suite that provides a simple way to test authorization in web applications and web services: https://github.com/SecurityInnovation/AuthMatrix</li>
  <li><a target="_blank" rel="no-image" href="https://github.com/eth0izzle/shhgit"><img border="0" src="https://github.com/eth0izzle/shhgit/raw/master/images/shhgit.png" width="50" height="50" style="vertical-align:middle"></a> -  shhgit finds secrets and sensitive files across GitHub (including Gists), GitLab and BitBucket committed in near real time: https://github.com/eth0izzle/shhgit </li>
  <li><a target="_blank" rel="no-image" href="https://www.sken.ai/"><img border="0" src="https://www.sken.ai/assets/img/logo.svg" width="100" height="50" style="vertical-align:middle"></a> - One tool to do all scans. Sken packages and manages open source scanners across all scan types, adds a SaaS orchestration layer and automates them in CI/CD: https://www.sken.ai/ </li>
  <li><a target="_blank" rel="no-image" href="https://github.com/LasCC/Hack-Tools"><img border="0" src="https://bit.ly/3hCDZUB" width="80" height="35" style="vertical-align:middle"></a>Hack-Tools - the all-in-one Red Team browser extension for Web Pentesters: https://github.com/LasCC/Hack-Tools</li>
  <li><a target="_blank" rel="no-image" href="https://github.com/epi052/feroxbuster"><img border="0" src="https://github.com/epi052/feroxbuster/raw/master/img/logo/default-cropped.png" width="95" height="45" style="vertical-align:middle"></a> - A simple, fast, recursive content discovery tool written in Rust</li>
  <li><a target="_blank" rel="no-image" href="https://github.com/jaeles-project/jaeles"><img border="0" src="https://github.com/jaeles-project/jaeles-plugins/raw/master/assets/jaeles.png?raw=true" width="60" height="50" style="vertical-align:middle"></a><center>Jaeles - a powerful, flexible and easily extensible framework written in Go for building your own Web Application Scanner: https://github.com/jaeles-project/jaeles</center></li>
  <li>tamper.dev - an extension that allows you to edit HTTP/HTTPS requests and responses as they happen without the need of a proxy: https://tamper.dev/ </li>
  <li>proxify - Swiss Army Knife Proxy for rapid deployments. Supports multiple operations such as request/response dump, filtering and manipulation via DSL language, upstream HTTP/Socks5 proxy: https://github.com/projectdiscovery/proxify</li>
  <li>XSSTRON - Powerful Chromium Browser to find XSS Vulnerabilites automatically while browsing web: https://github.com/RenwaX23/XSSTRON</li>
  <li>AutoRepeater - Automated HTTP Request Repeating With Burp Suite: https://github.com/nccgroup/AutoRepeater</li>
<li>xsshunter - allows you to find all kinds of cross-site scripting vulnerabilities, including the often-missed blind XSS. The service works by hosting specialized XSS probes which, upon firing, scan the page and send information about the vulnerable page to the XSS Hunter service: https://xsshunter.com/</li>
  <li>vajra - utomated web hacking framework to automate boring recon tasks and same scans for multiple target during web applications penetration testing. Vajra has highly customizable target scope based scan feature: https://github.com/r3curs1v3-pr0xy/vajra</li>
  <li>MindAPI - a mindmap which combines years of experience in testing API security: https://github.com/dsopas/MindAPI</li>
  <li>gotestwaf - Go project to test different web application firewalls (WAF) for detection logic and bypasses: https://github.com/wallarm/gotestwaf</li>
  <li>kiterunner - API and content discovery at lightning fast speeds, bruteforcing routes/endpoints in modern applications: https://github.com/assetnote/kiterunner</li>
  <li>Epiphany - a pre-engagement \ self-assessment tool to identify weak spots of a web property from a DDoS attacker perspective: https://github.com/Cyberlands-io/epiphany</li>
  <li>jwtXploiter - a tool to test security of JSON Web Tokens. Test a JWT against all known CVEs: https://github.com/DontPanicO/jwtXploiter</li>
  <li>rengine - An automated reconnaissance framework for web applications with focus on highly configurable streamlined recon process via Engines, recon data correlation and organization, continuous monitoring, backed by database and simple yet intuitive User Interfac: https://github.com/yogeshojha/rengine</li>
  <li>graphw00f - inspired by wafw00f is the GraphQL fingerprinting tool for GQL endpoints, it sends a mix of benign and malformed queries to determine the GraphQL engine running behind the scenes. graphw00f will provide insights into what security defences each technology provides out of the box, and whether they are on or off by default: https://github.com/dolevf/graphw00f</li>
  <li>changeme - ocuses on detecting default and backdoor credentials and not necessarily common credentials. It's default mode is to scan HTTP default credentials, but has support for other credentials: https://github.com/ztgrace/changeme</li>
</ul></br>
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
<li><a target="_blank" rel="no-image" href="https://portswigger.net/web-security/cross-site-scripting/cheat-sheet"><img border="0" src="https://socbox.com/wp-content/uploads/2019/06/portswigger.png" width="65" height="20" style="vertical-align:middle"></a><center>portswigger XSS cheat-sgeet: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet</center></li>
</ul></br>

<h3><b>Cloud Security</h3></b>
<ul>
<li>serverless-prey - a collection of serverless functions (FaaS), that, once launched to a cloud environment and invoked, establish a TCP reverse shell, enabling the user to introspect the underlying container: https://github.com/pumasecurity/serverless-prey </li>
<li>Deepfence Runtime Threat Mapper - is a subset of the Deepfence cloud native workload protection platform, released as a community edition: https://github.com/deepfence/ThreatMapper/blob/master/README.md</li>
<li>Dow Jones Hammer - a multi-account cloud security tool for AWS. It identifies misconfigurations and insecure data exposures within most popular AWS resources, across all regions and accounts: https://github.com/dowjones/hammer/blob/master/README.md</li>
<li><a target="_blank" rel="no-image" href="https://github.com/cyberark/SkyArk"><img border="0" src="https://github.com/Hechtov/Photos/raw/master/SkyArk/SkyArkLogo2.png" width="120" height="50" style="vertical-align:middle"></a> -  a cloud security project with two main scanning modules- AzureStealth | AWStealth: https://github.com/cyberark/SkyArk </li>
<li>serverless-prey - a collection of serverless functions (FaaS), that, once launched to a cloud environment and invoked, establish a TCP reverse shell, enabling the user to introspect the underlying container: https://github.com/pumasecurity/serverless-prey</li>
<li>Prowler - AWS Security Toola command line tool for AWS Security Best Practices Assessment, Auditing, Hardening and Forensics Readiness Tool: https://github.com/toniblyx/prowler</li>
<li>cloudsploit (Aqua) - an open-source project designed to allow detection of security risks in cloud infrastructure accounts: https://github.com/aquasecurity/cloudsploit </li>
<li>deepfence SecretScanner - helps users scan their container images or local directories on hosts and outputs JSON file with details of all the secrets found: https://github.com/deepfence/SecretScanner </li>
<li>OpenCSPM - an open-source platform for gaining deeper insight into your cloud configuration and metadata to help understand and reduce risk over time: https://github.com/OpenCSPM/opencspm </li>
<li>endgame - An AWS Pentesting tool that lets you use one-liner commands to backdoor an AWS account's resources with a rogue AWS account - or share the resources with the entire Internet: https://endgame.readthedocs.io/en/latest/ </li>
<li>rpCheckup - an AWS resource policy security checkup tool that identifies public, external account access, intra-org account access, and private resources. It makes it easy to reason about resource visibility across all the accounts in your org: https://github.com/goldfiglabs/rpCheckup </li>
<li>prawler - is a command line tool for AWS Security Best Practices Assessment, Auditing, Hardening and Forensics Readiness Tool: https://github.com/toniblyx/prowler </li>
<li>cloudmapper - helps you analyze your Amazon Web Services (AWS) environments. The original purpose was to generate network diagrams and display them in your browser. It now contains much more functionality, including auditing for security issues: https://github.com/duo-labs/cloudmapper</li>
<li>netz - discover an internet-wide misconfiguration of network components like web-servers/databases/cache-services and more: https://github.com/SpectralOps/netz</li>
<li>red-shadow - scan your AWS IAM Configuration for shadow admins in AWS IAM based on misconfigured deny policies not affecting users in groups discovered by Lightspin's Security Research Team: https://github.com/lightspin-tech/red-shadow</li>
<li>Principal Mapper  -  script and library for identifying risks in the configuration of AWS Identity and Access Management (IAM) for an AWS account or an AWS organization: https://github.com/nccgroup/PMapper | https://research.nccgroup.com/2021/03/29/tool-release-principal-mapper-v1-1-0-update/</li>
<li>Patrolaroid - an instant camera for capturing cloud workload risks. It’s a prod-friendly scanner that makes finding security issues in AWS instances and buckets less annoying and disruptive for software engineers and cloud admins: https://github.com/rpetrich/patrolaroid </li>
</ul>
</br>

<h3><b>office365 / AAD Security</h3></b>
<ul>
<li><a target="_blank" rel="no-image" href="https://github.com/dirkjanm/ROADtools"><img border="0" src="https://github.com/dirkjanm/ROADtools/raw/master/roadrecon/frontend/src/assets/rt_transparent.svg" width="120" height="50" style="vertical-align:middle"></a> -  a framework to interact with Azure AD. It currently consists of a library (roadlib) and the ROADrecon Azure AD exploration tool: https://github.com/dirkjanm/ROADtools </li>
<li>o365recon - script to retrieve information via O365 with a valid cred: https://github.com/nyxgeek/o365recon</li>
<li>MailSniper -  a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords, insider intel, network architecture information, etc.). It can be used as a non-administrative user to search their own email, or by an Exchange administrator to search the mailboxes of every user in a domain: https://github.com/dafthack/MailSniper</li>
<li>o365creeper - is a simple Python script used to validate email accounts that belong to Office 365 tenants: https://github.com/LMGsec/o365creeper</li>
<li>Sparrow.ps1 - created by CISA's Cloud Forensics team to help detect possible compromised accounts and applications in the Azure/m365 environment: https://github.com/cisagov/Sparrow</li>
<li>CrowdStrike Reporting Tool for Azure (CRT): https://github.com/CrowdStrike/CRT</li>
<li>MSOLSpray - A password spraying tool for Microsoft Online accounts (Azure/O365): https://github.com/dafthack/MSOLSpray </li>
<li>AADInternals - PowerShell module contains tools for administering and hacking Azure AD and Office 365: https://o365blog.com/aadinternals/ | https://github.com/Gerenios/AADInternals </li>
<li>Stormspotter -  creates an “attack graph” of the resources in an Azure subscription. It enables red teams and pentesters to visualize the attack surface and pivot opportunities within a tenant, and supercharges your defenders to quickly orient and prioritize incident response work: https://github.com/Azure/Stormspotter</li>
<li>m365_groups_enum - Enumerate Microsoft 365 Groups in a tenant with their metadata: https://github.com/cnotin/m365_groups_enum</li>
<li>Microsoft Azure & O365 CLI Tool Cheatsheet: https://github.com/dafthack/CloudPentestCheatsheets/blob/master/cheatsheets/Azure.md</li>
<li>BruteLoops - a dead simple library providing the foundational logic for efficient password brute force attacks against authentication interfaceshttps://github.com/arch4ngel/BruteLoops</li>
<li>MicroBurst - a PowerShell Toolkit for Attacking Azure that includes functions and scripts that support Azure Services discovery, weak configuration auditing, and post exploitation actions such as credential dumping. It is intended to be used during penetration tests where Azure is in use: https://github.com/NetSPI/MicroBurst</li>
<li>PowerZure - a PowerShell project created to assess and exploit resources within Microsoft’s cloud platform: https://github.com/hausec/PowerZure</li>
<li>Azure-Red-Team - collection of AAD recon and attack resorces: https://github.com/rootsecdev/Azure-Red-Team</li>
<li>AzureAD_Autologon_Brute - Brute force attack tool for Azure AD Autologon: https://github.com/nyxgeek/AzureAD_Autologon_Brute</li>
<li>MicroBurst -  includes functions and scripts that support Azure Services discovery, weak configuration auditing, and post exploitation actions such as credential dumping: https://github.com/NetSPI/MicroBurst</li>
<li>Go365 - a tool designed to perform user enumeration* and password guessing attacks on organizations that use Office365 (now/soon Microsoft365). Go365 uses a unique SOAP API endpoint on login.microsoftonline.com that most other tools do not use: https://github.com/optiv/Go365</li>
</ul>
</br>

<p2><b><u>Online Tools</u></b><p2>
<ul>
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
<li>JSfiddle: https://jsfiddle.net/ </li>
<li>Code validator (Yaml, JSON, JS, etc): https://codebeautify.org/yaml-validator </li>
<li>social IDE: https://codepen.io/</li>
<li>json path finder: https://jsonpath.com/ </li>
<li>json query language: https://jmespath.org/ </li>
<li>repl.it - online Python compiler: https://repl.it/languages/Python%3F__s=ws9cqndijs3fipi6sacu</li>
<li>dillinger - live markdown editor https://dillinger.io/ </li>
<li>glitch -  the friendly community where everyone codes together: https://glitch.com/</li>
<li>JS lint: https://jshint.com/</li>
<li>JSON schema data generator: https://json-schema-faker.js.org/ </li>
  <li>Search for open source repositories on github, gitlab, and bitbucket: https://www.bithublab.org/</li>
  <li>Python Regex tester: https://pythex.org/ </li>
  <li>dnstwister - domain name permutation engine: https://dnstwister.report/ </li>
  <li>mozilla SSL Configuration Generator: https://ssl-config.mozilla.org/ </li>
  </ul>
</br>
  <p2><b><u>API Stuff</u></b><p2>
  <ul>
  <li>Postman Cheatsheet: https://postman-quick-reference-guide.readthedocs.io/en/latest/index.html </li>
  <li>explore-with-postman: https://github.com/ambertests/explore-with-postman</li>
  <li>Great collection of examples: https://github.com/DannyDainton</li>
  <li>Test automation university: https://testautomationu.applitools.com/Automation </li>
  <li>Loops with Postman: https://thisendout.com/2017/02/22/loops-dynamic-variables-postman-pt2/</li>
  <li>All CheatSheets: http://overapi.com/ </li>
  <li>Hosted REST API: https://reqres.in/ </li>
  <li>httpbin - A simple HTTP Request & Response Service: http://httpbin.org/</li>
  <li>Fake REST API with JSON and POSTMAN: https://dev.to/tadea/fake-rest-api-with-json-and-postman-5gi8</li>
  <li>Petstore - a sample server Petstore server: https://petstore.swagger.io/</li>
  <li>Parabank REST API: http://parabank.parasoft.com/parabank/api-docs/index.html</li>
  <li>Use curl to interact with an API: https://www.redhat.com/sysadmin/use-curl-api</li>
  </ul>
  
</br>
<p2><b>Password Lists</b></p2>
<ul>
<li>https://wiki.skullsecurity.org/index.php?title=Passwords</li>
<li>Seclists - https://github.com/danielmiessler/SecLists</li>
</ul>

<p2><b><u>Stress Test / Web Traffic Simulation / Test Automation</u></b><p2>
<li>https://loader.io/</li>
<li>https://a.blazemeter.com/app/sign-in</li>
<li>https://artillery.io/</li>
<li> NodeJS Test Cafe: https://devexpress.github.io/testcafe/ </li>
<li>Google puppeteer(headless chrome): https://github.com/GoogleChrome/puppeteer</li>
<li>GoldenEye - HTTP DoS Test Tool: https://github.com/jseidl/GoldenEye</li>
<li>Cisco TRex - open source, low cost, stateful and stateless traffic generator fuelled by DPDK: https://trex-tgn.cisco.com/</li>
<li>UBoat - Botnet simulator: https://github.com/Souhardya/UBoat </li>
<li>TestProject - free end-to-end test automation platform for web, mobile, and API testing that’s supported by the #1 test automation community: https://testproject.io/ </li>
<li>Karate - open-source tool to combine API test-automation, mocks, performance-testing and even UI automation into a single, unified framework: https://github.com/intuit/karate/blob/master/README.md</li>
<li>Saddam - DDos amplification attack tool: https://github.com/OffensivePython/Saddam</li>
<li>Tsunami - a more professional and efficient version of the network stress tester / denial of service tools known as LOIC: https://sourceforge.net/projects/tsunami-dos/</li>
<li>dsnperf -free tool to gather accurate latency and throughput metrics for Domain Name Service (DNS): https://github.com/DNS-OARC/dnsperf</li>
<li>rpounder - apache bench for DNS resolvers: https://github.com/mowings/rpounder</li>
<li>dnsstresss - Simple Go program to stress test a DNS server: https://github.com/MickaelBergem/dnsstresss</li>
<li>dnsprobe - a tool built on top of retryabledns that allows you to perform multiple dns queries of your choice with a list of user supplied resolvers: https://github.com/projectdiscovery/dnsprobe</li>
<li><a target="_blank" rel="no-image" href="https://github.com/loadimpact/k6"><img border="0" src="https://bit.ly/3704xuo" width="80" height="50" style="vertical-align:middle"></a><center>k6 - a modern load testing tool, building on Load Impact's years of experience in the load and performance testing industry: https://github.com/loadimpact/k6</center></li>
<li><a target="_blank" rel="no-image" href="https://github.com/microsoft/playwright"><g-emoji class="g-emoji" alias="performing_arts" fallback-src="https://github.githubassets.com/images/icons/emoji/unicode/1f3ad.png">🎭</g-emoji></a><center>Playwright - a Node library to automate Chromium, Firefox and WebKit with a single API. Playwright is built to enable cross-browser web automation that is ever-green, capable, reliable and fast: https://github.com/microsoft/playwright</center></li>
<li>httpie - a user-friendly command-line HTTP client for the API era: https://httpie.org/</li>
<li>httptoolkit - gives you instant insight and access into every request & response, with zero hassle. Test clients, debug APIs and catch bugs, all at lightning speed: https://httptoolkit.tech/ </li>
<li>hurl - a command line tool that runs HTTP requests defined in a simple plain text format. It can perform requests, capture values and evaluate queries on headers and body response. Hurl is very versatile: it can be used for both fetching data and testing HTTP sessions: https://hurl.dev/</li>
<li>PacketSender - utility to allow sending and receiving TCP, UDP, and SSL (encrypted TCP) packets: https://github.com/dannagle/PacketSender</li>
<li>Ddosify - High-performance load testing tool: https://github.com/ddosify/ddosify</li>
