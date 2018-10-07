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
  <br>
<p1 class="lead"><b>Misc Docker</b></p1>
<li>https://hub.docker.com/r/blacktop/cuckoo/    https://github.com/blacktop/docker-cuckoo </li>
<li>Script to check docker security(CIS) - https://hub.docker.com/r/diogomonica/docker-bench-security/ </li>
  <li>clair - static analysis of vulnerabilities in application containers: https://github.com/coreos/clair</li>
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


<p2><b>Misc Usefull Stuff</b></p2>
<ul>
<li>Bypass application whitelisting: http://www.blackhillsinfosec.com/?p=5633</li>
<li>Malcious outlook rules: https://silentbreaksecurity.com/malicious-outlook-rules/ </li>
<li>Great cheatsheets https://highon.coffee/blog/cheat-sheet/ </li>
<li>Headless Browseres https://github.com/dhamaniasad/HeadlessBrowsers </li>
  <li> Linode Linux useful IP commands: https://www.linode.com/docs/networking/linux-static-ip-configuration </li>
  <li>netdata - system for distributed real-time performance and health monitoring: https://github.com/firehol/netdata </li>
  <li>yamot - Yet Another Monitoring Tool: https://github.com/knrdl/yamot</li>
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
    <li>blackeye - Phishing Tool, with 32 templates: https://github.com/thelinuxchoice/blackeye</li>
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
            <li>Sensepost Data exfiltration Toolkit(DET): https://github.com/sensepost/DET </li>
  <li>Pyexfil: https://github.com/ytisf/PyExfil </li>
            <li>DoxuCannon: https://github.com/audibleblink/doxycannon </li>
          <li>Grok-backdoor: https://github.com/deepzec/Grok-backdoor </li>
          <li>foxtrot C2 - C&C to deliver content and shuttle command execution instructions: https://github.com/dsnezhkov/foxtrot</li>
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
      </span>
  </p3>
  </ul>
  <h3><b>AIO Tools / Frameworks</b></h3>
  <ul>
    <p3>
    <span>
      <li>PowerSploit - A PowerShell Post-Exploitation Framework: https://github.com/PowerShellMafia/PowerSploit </li>
      <li>Empire: https://www.powershellempire.com/ </li>
      <li>Empire GUI: https://github.com/EmpireProject/Empire-GUI </li>
      <li>One-Lin3r - consists of various one-liners that aids in penetration testing operations: https://github.com/D4Vinci/One-Lin3r</li>
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
            </span>
            </p3>
            </ul><br>
          
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
  <li>Search for open source repositories on github, gitlab, and bitbucket: https://www.bithublab.org/<li/>
  <li>dnstwister - domain name permutation engine: https://dnstwister.report/ </li>

<p2><b>Password Lists</b></p2>
<ul>
<li>https://wiki.skullsecurity.org/index.php?title=Passwords</li>
</ul>

<p2><b><u>Stress Test / Web Traffic Simulation</u></b><p2>
<li>https://loader.io/</li>
<li>https://a.blazemeter.com/app/sign-in</li>
<li>https://artillery.io/</li>
<li> NodeJS Test Cafe: https://devexpress.github.io/testcafe/ </li>
<li>Google puppeteer(headless chrome): https://github.com/GoogleChrome/puppeteer</li>

<p2><b>XSS Resources</b></p2>
<ul>
<li>HTML5 - http://html5sec.org/</li>
<li>OWASP - https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet</li>
<li>Reddit - https://www.reddit.com/r/xss/</li>
<li>Js payloads, great tutorials - http://www.xss-payloads.com/index.html</li>
<li>Powerfull web tool for creating event based payloads - http://brutelogic.com.br/webgun/ </li>
<li>Ultimate XSS protection Cheatsheet - https://xenotix.in/The%20Ultimate%20XSS%20Protection%20Cheat%20Sheet%20for%20Developers.pdf </li>
<li>HTML5 attack Vectors - https://dl.packetstormsecurity.net/papers/attack/HTML5AttackVectors_RafayBaloch_UPDATED.pdf </li>
</ul>

| Test command | Somehting here |
| --- | --- |
| 'bla bla bla command' | something here |
| 'short command' | short integer 'True' |
