# Nimo-Awesome_repo

***

## Table of Contents

1. [Nimo awesomerepo](#nimo-awesomerepo)
2. [Misc Docker](#misc-docker)
3. [Misc Useful Stuff](#misc-useful-stuff)
4. [Threat Hunting & Simulation](#Threat-Hunting-&-Simulation)
   - [Adversary/Threat Simulation](#adversary-threat-simulation)
   - [Cyber Ranges / Labs](#cyber-ranges-labs)
5. [Payloads / RATS](#payloads-rats)
6. [Stealthy Communication / Covert Channel](#stealthy-communication-covert-channel)
7. [Post Exploitation](#post-exploitation)
8. [Social Engineering](#social-engineering)
9. [AIO Tools / Frameworks](#aio-tools-frameworks)
10. [Hunting Guides / Forensics / MISC](#hunting-guides-forensics-misc)
11. [Blue Teams - Honeypots / IDS / Traps/ CTR](#blue-teams-honeypots-ids-traps-ctr)
12. [Web Security](#web-security)
13. [XSS Resources](#xss-resources)
14. [Cloud Security](#cloud-security)
15. [Office365 / AAD Security](#office365-aad-security)
16. [Online Tools](#online-tools)
17. [API Stuff](#api-stuff)
18. [Password Lists](#password-lists)
19. [Stress Test / Web Traffic Simulation / Test Automation](#stress-test-web-traffic-simulation-test-automation)

<h2><b><u>Usefull Docker Images</u></b></h2>
<ul><p1><b>Vulnerable Apps</b></p1>
<li>https://github.com/citizen-stig/dockermutillidae</li>
<li>https://hub.docker.com/r/opendns/security-ninjas/</li>
<li>https://github.com/remotephone/dvwa-lamp</li>
<li>https://hub.docker.com/r/ismisepaul/securityshepherd/</li>
<li>https://hub.docker.com/r/danmx/docker-owasp-webgoat/</li>
<li>https://github.com/bkimminich/juice-shop</li>
  <li>https://github.com/payatu/Tiredful-API</li>
  <li>vulnerable-api - example Python API that is vulnerable to several different web API attacks: https://github.com/rahulunair/vulnerable-api</li>
  <li>websheep - an app based on a willingly vulnerable ReSTful APIs: https://github.com/marmicode/websheep</li>
  <li>TIWAP - Totally Insecure Web Application Project: https://github.com/tombstoneghost/TIWAP</li>
  <li>jackhammer - One Security vulnerability assessment/management tool: https://github.com/olacabs/jackhammer/blob/master/docker-build.sh</li>
 <li>owtf - Offensive Web Testing Framework: https://github.com/owtf/owtf/tree/develop/docker</li>
 <li>docker-blackeye - container for running the phishing attack using Blackeye: https://github.com/vishnudxb/docker-blackeye </li>
 <li>h8mail - Powerful and user-friendly password finder: https://github.com/khast3x/h8mail/blob/master/Dockerfile</li>
 <li>Instatbox -  a project that spins up temporary Linux systems with instant webshell access from any browser: https://github.com/instantbox/instantbox/blob/master/Dockerfile</li>
 <li>envizon - state of the art network visualization and vulnerability reporting tool: https://github.com/evait-security/envizon/tree/master/docker </li>
 <li>vapi - is Vulnerable Adversely Programmed Interface which is Self-Hostable API that mimics OWASP API Top 10 scenarios in the means of Exercises: https://github.com/roottusk/vapi</li>
 <li>capital - the Checkmarx research team created c{api}tal to provide users with an active playground in which they hone their API Security skills: https://github.com/Checkmarx/capital</li>
 <li>bankground - banking playground project to learn REST/OpenAPI and GraphQL APIs: https://gitlab.com/karelhusa/bankground | https://bankground.apimate.eu/</li>
 <li>axiom - a dynamic infrastructure framework to efficiently work with multi-cloud environments, build and deploy repeatable infrastructure focussed on offensive and defensive security: https://github.com/pry0cc/axiom</li>
 <li>Exegol - a community-driven hacking environment, powerful and yet simple enough to be used by anyone in day to day engagements. Exegol is the best solution to deploy powerful hacking environments securely, easily, professionally: https://github.com/ThePorgs/Exegol</li>
  <br>

<h2><u><p1 class="lead"><b>Misc Docker</b></p1></u></h2>
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
  <li>Haskell Dockerfile Linter - A smarter Dockerfile linter that helps you build best practice Docker images: https://github.com/hadolint/hadolint</li>
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
<li>fake-service - can handle both HTTP and gRPC traffic, for testing upstream service communications and testing service mesh and other scenarios: https://github.com/nicholasjackson/fake-service</li>
 <li>Docker-OSX - runn Mac OS X in Docker with near-native performance! X11 Forwarding! iMessage security research! iPhone USB working! macOS in a Docker container: https://github.com/sickcodes/Docker-OSX | https://gombosg.com/2022/01/running-macos-inside-linux/</li>
 <li>Nightingale - Docker image for Pentesters: https://github.com/RAJANAGORI/Nightingale</li>
</br>

<h2><u><p2><b>Misc Usefull Stuff</b></p2></u></h2>
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

<h2><u><strong>Threat Hunting && Simulation</strong></u></h2>

  <h3><u><b>Adversary/Threat Simulation</b></u></h3>
  <ul>
    <p3>
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
  <li>Blue Team Training Kit: https://www.bt3.no/ </li>
  <li>UBoat - POC HTTP Botnet designed to replicate a full weaponised commercial botnet: https://github.com/Souhardya/UBoat</li>
  <li>FireProx - FireProx leverages the AWS API Gateway to create pass-through proxies that rotate the source IP address with every request: https://github.com/ustayready/fireprox</li>
  <li>Chain Reactor - is an open source framework for composing executables that can simulate adversary behaviors and techniques on Linux endpoints: https://github.com/redcanaryco/chain-reactor </li>
  <li>Redcloud - a powerful and user-friendly toolbox for deploying a fully featured Red Team Infrastructure using Docker.https://github.com/khast3x/Redcloud </li>
      <li>Red Teaming/Adversary Simulation Toolkit - a collection of open source and commercial tools that aid in red team operationshttps://github.com/infosecn1nja/Red-Teaming-Toolkit </li>
      <li>racketeer - Ransomware emulation toolkit: https://github.com/dsnezhkov/racketeer</li>
      <li>PurpleSharp - adversary simulation tool written in C# that executes adversary techniques within Windows Active Directory environments. The resulting telemetry can be leveraged to measure and improve the efficacy of a detection engineering program. PurpleSharp leverages the MITRE ATT&CK Framework and executes different techniques across the attack life cycle: execution, persistence, privilege escalation, credential access, lateral movement, etc. It currently supports 47 unique ATT&CK techniques: https://github.com/mvelazc0/PurpleSharp</li>
      <li>pingcastle -  a tool designed to assess quickly the Active Directory security level with a methodology based on risk assessment and a maturity framework: https://github.com/vletoux/pingcastle</li>
      <li>Some red team automation (RTA) python scripts that run on Windows, Mac OS, and *nix. RTA scripts emulate known attacker behaviors and are an easy way too verify that your rules are active and working as expected - https://github.com/elastic/detection-rules/tree/3e511965b49eae69d103b9210765bceee9cb6396/rta</li>
      <li>Teqnix - Penetration Testing Platform. Along with all the cool automation features, some of the benefits of TEQNIX is having access to a set of tools that do not 
					require the user to install or to maintain them. Furthermore, the library of tools is an asset to your testing methodologies ready to be launched.https://teqnix.io/</li>
          <li>Exegol - a fully configured docker with many useful additional tools, resources (scripts and binaries for privesc, credential theft etc.): https://github.com/ShutdownRepo/Exegol</li>
          <li>redherd-framework - a collaborative and serverless framework for orchestrating a geographically distributed group of assets capable of simulating complex offensive cyberspace operations: https://github.com/redherd-project/redherd-framework</li>
          <li>PMAT-labs - this repository contains live malware samples for use in the Practical Malware Analysis & Triage course (PMAT). These samples are either written to emulate common malware characteristics or are live, real world, "caught in the wild" samples: https://github.com/HuskyHacks/PMAT-labs</li>
          <li>stratus-red-team - is "Atomic Red Team™" for the cloud, allowing to emulate offensive attack techniques in a granular and self-contained manner: https://github.com/Datadog/stratus-red-team/</li>
          <li>firedrill - an open-source library from FourCore Labs to build malware simulations easily: https://github.com/FourCoreLabs/firedrill</li>
          <li>Vulhub - an open-source collection of pre-built vulnerable docker environments: https://github.com/vulhub/vulhub</li>
          <li>AWS CloudSaga - Simulate security events in AWS: https://github.com/awslabs/aws-cloudsaga</li>
          <li>flightsim - a lightweight utility used to generate malicious network traffic and help security teams to evaluate security controls and network visibility. The tool performs tests to simulate DNS tunneling, DGA traffic, requests to known active C2 destinations, and other suspicious traffic patterns: https://github.com/alphasoc/flightsim</li>
          <li>Red-Teaming-Toolkit - this repository contains cutting-edge open-source security tools (OST) that will help you during adversary simulation and as information intended for threat hunter can make detection and prevention control easier.: https://github.com/infosecn1nja/Red-Teaming-Toolkit</li>
          <li>SysmonSimulator - an Open source Windows event simulation utility created in C language, that can be used to simulate most of the attacks using WINAPIs: https://github.com/ScarredMonk/SysmonSimulator</li>
          <li>goreplay - an open-source network monitoring tool which can record your live traffic and use it for shadowing, load testing, monitoring and detailed analysis: https://github.com/buger/goreplay</li>
          <li>Top 10 Awesome Open-Source Adversary Simulation Tools: https://fourcore.io/blogs/top-10-open-source-adversary-emulation-tools</li>
          <li>artifact malware-samples - malicious artifacts which can be used to test code SCA and SAST scanners: https://github.com/DataDog/security-labs-pocs/tree/main/malware-samples</li>
            <li>ATTPwn - a computer security tool designed to emulate adversaries. The tool aims to bring emulation of a real threat into closer contact with implementations based on the techniques and tactics from the MITRE ATT&CK framework: https://github.com/ElevenPaths/ATTPwn</li>
            <li>derf (Detection Replay Framework) - is an "Attacks As A Service" framework, allowing the emulation of offensive techniques and generation of repeatable detection samples from a UI - without the need for End Users to install software, use the CLI or possess credentials in the target environment: https://github.com/vectra-ai-research/derf</li>

  </p3>
  </ul>
    <h3><b>Cyber Ranges / Labs</b></h3>
  <ul>
    <p3>
    <span>
    <li>aws-pentesting-lab - PenTesting laboratory deployed as IaC with Terraform on AWS. It deploys a Kali Linux instance accessible via ssh & wireguard VPN. Vulnerable instances in a private subnet: https://github.com/juanjoSanz/aws-pentesting-lab</li>
        <li>Detection Lab - this lab has been designed with defenders in mind. Its primary purpose is to allow the user to quickly build a Windows domain that comes pre-loaded with security tooling and some best practices when it comes to system logging configurations: https://github.com/clong/DetectionLab</li>
    <li>vulnerable-AD - create a vulnerable active directory that's allowing you to test most of active directory attacks in local lab: https://github.com/WazeHell/vulnerable-AD</li>
    <li>ADLab - a tool created in PowerShell to quickly setup an Active directory lab for testing purposes. This tool can help setup a Domain controller and Workstation in a lab environment quickly and effectively: https://browninfosecguy.com/Active-Directory-Lab-Setup-Tool | https://github.com/browninfosecguy/ADLab</li>
    <li>BadBlood -  fills a Microsoft Active Directory Domain with a structure and thousands of objects: https://github.com/davidprowe/BadBlood</li>
    <li>PurpleCloud - Pentest Cyber Range for a small Active Directory Domain. Automated templates for building your own Pentest/Red Team/Cyber Range in the Azure cloud: https://github.com/iknowjason/PurpleCloud </li>
    <li>Azure purple team lab by BLackHills InfoSec:  https://www.blackhillsinfosec.com/how-to-applied-purple-teaming-lab-build-on-azure-with-terraform/ | https://github.com/DefensiveOrigins/APT-Lab-Terraform </li>
    <li>Redcloud -  a powerful and user-friendly toolbox for deploying a fully featured Red Team Infrastructure using Docker: https://github.com/khast3x/Redcloud </li>
    <li>BlueCloud - Cyber Range deployment of HELK and Velociraptor! Automated terraform deployment of one system running HELK + Velociraptor server with one registered Windows endpoint in Azure or AWS: https://github.com/iknowjason/BlueCloud</li>
    <li>Sadcloud - a tool for spinning up insecure AWS infrastructure with Terraform: https://github.com/nccgroup/sadcloud</li>
   <li>Terraform to demonstrate exposed resources in AWS: https://github.com/kmcquade/terraform-aws-resource-exposure</li>
   <li>IAM Vulnerable - An AWS IAM Privilege Escalation Playground: https://labs.bishopfox.com/tech-blog/iam-vulnerable-an-aws-iam-privilege-escalation-playground | https://labs.bishopfox.com/tech-blog/iam-vulnerable-assessing-the-aws-assessment-tools#Q1</li>
   <li>Kubernetes Local Security Testing Lab - There's a number of playbooks which will bring up cluster's with a specific mis-configuration that can be exploited: https://github.com/raesene/kube_security_lab</li>
   <li>simulator - a distributed systems and infrastructure simulator for attacking and debugging Kubernetes: simulator creates a Kubernetes cluster for you in your AWS account; runs scenarios which misconfigure it and/or leave it vulnerable to compromise and trains you in mitigating against these vulnerabilities: https://github.com/kubernetes-simulator/simulator</li>
   <li>Splunk attack range: https://github.com/splunk/attack_range</li>
   <li>Red-Baron - a set of modules and custom/third-party providers for Terraform which tries to automate creating resilient, disposable, secure and agile infrastructure for Red Teams: https://github.com/Coalfire-Research/Red-Baron</li>
   <li>HazProne - a Cloud Pentesting Framework that emulates close to Real-World Scenarios by deploying Vulnerable-By-Demand aws resources enabling you to pentest Vulnerabilities within, and hence, gain a better understanding of what could go wrong and why. The framework helps gain practical, AWS Penetration testing knowledge/skills: https://github.com/stafordtituss/HazProne</li>
   <li>cicd-goat - deliberately vulnerable CI/CD environment. Hack CI/CD pipelines, catch the flags: https://github.com/cider-security-research/cicd-goat</li>
   <li>CI/CDon't - This project will deploy intentionally vulnerable software/infrastructure to your AWS account: https://hackingthe.cloud/aws/capture_the_flag/cicdont/</li>
   <li>Azure Red Team Attack and Detect Workshop - a vulnerable-by-design Azure lab, containing 2 x attack paths with common misconfigurations: https://github.com/mandiant/Azure_Workshop</li>
      <li>AWSGoat - A Damn Vulnerable AWS Infrastructure. AWSGoat is a vulnerable by design infrastructure on AWS featuring the latest released OWASP Top 10 web application security risks (2021) and other misconfiguration: https://github.com/ine-labs/AWSGoat</li>
   <li>AzureGoat - a vulnerable by design infrastructure on Azure featuring the latest released OWASP Top 10 web application security risks (2021) and other misconfiguration: https://github.com/ine-labs/AzureGoat</li>
    <li>Datadog Security Labs Research - this repository aims at providing proof of concept exploits and technical demos to help the community respond to threats: https://github.com/DataDog/security-labs-pocs</li>
   <li>GitGoat - enables DevOps and Engineering teams to test security products intending to integrate with GitHub. GitGoat is a learning and training project that demonstrates common configuration errors that can potentially allow adversaries to introduce code to production: https://github.com/arnica-ext/GitGoat</li>
   <li>cloudgoat - s Rhino Security Labs' "Vulnerable by Design" AWS deployment tool: https://github.com/RhinoSecurityLabs/cloudgoat</li>
   <li>CyberRange - this project provides a bootstrap framework for a complete offensive, defensive, reverse engineering, & security intelligence tooling in a private research lab using the AWS Cloud: https://github.com/secdevops-cuse/CyberRange</li>
  <li>Red-Baron - a set of modules and custom/third-party providers for Terraform which tries to automate creating resilient, disposable, secure and agile infrastructure for Red Teams: https://github.com/Coalfire-Research/Red-Baron</li>
  <li>cloudsec-tidbits - a blogpost series showcasing interesting bugs found by Doyensec during cloud security testing activities: https://github.com/doyensec/cloudsec-tidbits</li>
  <li>kali-purple - the ultimate SOC in a box. Practice Ops, red, blue and purple teaming: https://gitlab.com/kalilinux/kali-purple/documentation</li>
   <li>GCPGoat - A Damn Vulnerable GCP Infrastructure: https://github.com/ine-labs/GCPGoat</li>
   <li>Supply Chain Goat - provides a training ground to practice implementing countermeasures specific to the software supply chain: https://github.com/step-security/supply-chain-goat</li>
   <li>oidc-ssrf - evil OIDC server: the OpenID Configuration URL returns a 307 to cause SSRF: https://github.com/doyensec/oidc-ssrf</li>
     <li>Damn Vulnerable Functions as a Service: https://github.com/we45/DVFaaS-Damn-Vulnerable-Functions-as-a-Service</li>
  <li>Awesome Cloud Security Labs - a list of free cloud native security learning labs. Includes CTF, self-hosted workshops, guided vulnerability labs, and research labs: https://github.com/iknowjason/Awesome-CloudSec-Labs</li>
  <li>cloudfoxable - an intentionally vulnerable AWS environment created specifically to showcase CloudFox’s capabilities and help you find latent attack paths more effectively: https://github.com/BishopFox/cloudfoxable</li>
  <li>[BadZure](https://github.com/mvelazc0/BadZure) - a PowerShell script that leverages the Microsoft Graph SDK to orchestrate the setup of Azure Active Directory tenants, populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths.</li>
  <li>cnappgoat - a multi-cloud, vulnerable-by-design environment deployment tool – specifically engineered to facilitate practice arenas for defenders and pentesters. Its main function is to deploy intentionally vulnerable environments across multiple cloud service providers, to help you sharpen your skills in exploiting, detecting, and preventing such vulnerabilities: https://github.com/ermetic-research/cnappgoat</i>
  <li>XMGoat - a composed of XM Cyber terraform templates that help you learn about common Azure security issues: https://github.com/XMCyber/XMGoat</li>
  <li>github-actions-goat - an educational project that simulates common security attacks and vulnerabilities in a GitHub Actions CI/CD environment and shows how to defend against such attacks: https://github.com/step-security/github-actions-goat</li>
  <li>DVFaaS(Damn Vulnerable Functions as a Service) - deploy and run a bunch of 'orribly insecure functions on AWS Lambda: https://github.com/we45/DVFaaS-Damn-Vulnerable-Functions-as-a-Service</li>
  <li>SinCity - a GPT-powered, MITRE ATT&CK-based tool which automates the provisioning and management of an IT environment in a conversational way: https://github.com/tenable/SinCity</li>
  <li>WolfPack - combines the capabilities of Terraform and Packer to streamline the deployment of red team redirectors on a large scale: https://github.com/RoseSecurity-Research/WolfPack</li>
  <li>GOAD - a pentest active directory LAB project. The purpose of this lab is to give pentesters a vulnerable Active directory environment ready to use to practice usual attack techniques: https://github.com/Orange-Cyberdefense/GOAD</li>
  <li>cdk-goat - a demonstration of a "vulnerable-by-design" AWS Cloud Development Kit (CDK) infrastructure: https://github.com/avishayil/cdk-goat</li>
  <li>[vulnerable-apps - Over 100 forks of deliberately vulnerable web applications and APIs: ](https://github.com/vulnerable-apps)</li>
  <li><[AutomatedEmulation - a simple terraform template creating a customizable and automated Breach and Attack Simulation lab(caldera, perlude, VECTR)](https://github.com/iknowjason/AutomatedEmulation)/li>
  <li>AutomatedLab - enables you to setup test and lab environments on Hyper-v or Azure with multiple products or just a single VM in a very short time: https://github.com/AutomatedLab/AutomatedLab</li>
  <li>EH-Patch-Todo-App - Goof - Snyk's vulnerable demo app: https://github.com/snyk-workshops/EH-Patch-Todo-App</li>
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
          <li>Arbitrium-RAT - a cross-platform is a remote access trojan (RAT), Fully UnDetectable (FUD), It allows you to control Android, Windows and Linux and doesn't require any firewall exceptions or port forwarding: https://github.com/im-hanzou/Arbitrium-RAT</li>
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
          <li>awesome-linux-rootkits: https://github.com/milabs/awesome-linux-rootkits</li>
          <li>Koppeling - a demonstration of advanced DLL hijack techniques. It was released in conjunction with the "Adaptive DLL Hijacking" blog post: https://github.com/monoxgas/Koppeling</li>
          <li>SillyRAT - A Cross Platform multifunctional (Windows/Linux/Mac) RAT: https://github.com/hash3liZer/SillyRAT</li>
          <li>mortar - red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive: https://github.com/0xsp-SRD/mortar</li>
            <li>go-shellcode - a repository of Windows Shellcode runners and supporting utilities. The applications load and execute Shellcode using various API calls or techniques: https://github.com/Ne0nd0g/go-shellcode</li>
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
          <li>Sliver and Cursed Chrome for Post Exploitation - a blog post that guides you through using Cursed Chrome within Sliver to more effectively perform adversary emulation tests: https://dev.to/living_syn/sliver-and-cursed-chrome-for-post-exploitation-4gnk</li>
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
          <li>HTTPUploadExfil - a (very) simple HTTP server written in Go that's useful for getting files (and other information) off a machine using HTTP: https://github.com/IngoKl/HTTPUploadExfil</li>
          <li>GC2-sheet - GC2 (Google Command and Control) is a Command and Control application that allows an attacker to execute commands on the target machine using Google Sheet and exfiltrates data using Google Drive: https://github.com/looCiprian/GC2-sheet</li>
          <li>tor-rootkit - a Python 3 standalone Windows 10 / Linux Rootkit. The networking communication get's established over the tor network: https://github.com/emcruise/tor-rootkit</li>
          <li>DNSStager - an open-source project based on Python used to hide and transfer your payload using DNS: https://github.com/mhaskar/DNSStager</li>
          <li>rathole - a secure, stable and high-performance reverse proxy for NAT traversal, written in Rust: https://github.com/rapiz1/rathole</li>
          <li>TREVORproxy - a SOCKS proxy written in Python that randomizes your source IP address. Round-robin your evil packets through SSH tunnels or give them billions of unique source addresses: https://github.com/blacklanternsecurity/TREVORproxy</li>
          <li>dnscrypt-proxy - A flexible DNS proxy, with support for modern encrypted DNS protocols such as DNSCrypt v2, DNS-over-HTTPS, Anonymized DNSCrypt and ODoH (Oblivious DoH): https://github.com/DNSCrypt/dnscrypt-proxy</li>
          <li>GoWard - a robust and rapidly-deployable Red Team proxy with strong OPSEC considerations.: https://github.com/chdav/GoWard</li>
          <li>awesome-tunneling - The purpose of this list is to track and compare tunneling solutions. This is primarily targeted toward self-hosters and developers who want to do things like exposing a local webserver via a public domain name, with automatic HTTPS, even if behind a NAT or other restricted network: https://github.com/anderspitman/awesome-tunneling</li>
          <li>bore - a modern, simple TCP tunnel in Rust that exposes local ports to a remote server, bypassing standard NAT connection firewalls: https://github.com/ekzhang/bore</li>
                    <li>rconn - a multiplatform program for creating reverse connections. It lets you consume services that are behind NAT and/or firewall without adding firewall rules or port-forwarding: https://github.com/jafarlihi/rconn</li>
          <li>GoSH - Golang reverse/bind shell generator. This tool generates a Go binary that launches a shell of the desired type on the targeted host: https://github.com/redcode-labs/GoSH</li>
          <li>tornado - anonymously reverse shell over onion network using hidden services without portfortwarding: https://github.com/samet-g/tornado</li>
          <li>Pitraix - modern Cross-Platform HTTP-Based P2P Botnet over TOR that cannot be traced: https://github.com/ThrillQuks/Pitraix</li>
          <li>revshells - online reverse shell generator: https://www.revshells.com/</li>
          <li>NimPlant - a light first-stage C2 implant written in Nim and Python: https://github.com/chvancooten/NimPlant</li>
          <li>reverse_ssh - A Fast, Stable Reverse Shell Handler: https://github.com/NHAS/reverse_ssh | https://research.aurainfosec.io/pentest/rssh/</li>
          <li>Pyramid - a Python HTTP/S server that can deliver encrypted files (chacha, xor), load in-memory dependencies of offensive tooling such as Bloodhound-py, secretsdump, LaZagne, Pythonnet, DonPAPI, pythonmemorymodule, paramiko, pproxy and Python cradle that can download, decrypt and execute in memory Pyramid modules: https://github.com/naksyn/Pyramid</li>
          <li>resocks - a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed (e.g. due to NAT): https://github.com/RedTeamPentesting/resocks</li>
                    <li>Outline - lets anyone create, run, and share access to their own VPN. Outline is designed to be resistant to blocking.: https://getoutline.org/</li>
          <li>RedGuard - provide a better C2 channel hiding solution for the red team, that provides the flow control for the C2 channel, blocks the "malicious" analysis traffic, and better completes the entire attack task: https://github.com/wikiZ/RedGuard</li>
          <li>RedWarden - was created to solve the problem of IR/AV/EDRs/Sandboxes evasion on the C2 redirector layer. It's intended to supersede classical Apache2 + mod_rewrite setups used for that purpose: https://github.com/mgeeky/RedWarden</li>
          <li>RedditC2 - Abusing Reddit API to host the C2 traffic: https://github.com/kleiton0x00/RedditC2</li>
          <li>skyhook - a REST-driven utility used to smuggle files into and out of networks defended by IDS implementations. It comes with a pre-packaged web client that uses a blend of React, vanilla JS, and web assembly to manage file transfers: https://github.com/blackhillsinfosec/skyhook</li>
          <li>BounceBack - a powerful, highly customizable and configurable reverse proxy with WAF functionality for hiding your C2/phishing/etc infrastructure from blue teams, sandboxes, scanners, etc: https://github.com/D00Movenok/BounceBack</li>
          <li>gsocket - the Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other: https://github.com/hackerschoice/gsocket</li>
           </span>
          </p3>
       
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
      <li>sharphound-all-flags explained: https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html</li>
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
      <li>DonPAPI - Dumping revelant information on compromised targets without AV detection: https://github.com/login-securite/DonPAPI</li>
      <li>Invisi-Shell - hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging, Module logging, Transcription, AMSI) by hooking .Net assemblies: https://github.com/OmerYa/Invisi-Shell</li>
      <li>pyrdp - a Python Remote Desktop Protocol (RDP) Monster-in-the-Middle (MITM) tool and library: https://github.com/GoSecure/pyrdp</li>
      <li>aDLL - a binary analysis tool focused on the automatic discovery of DLL Hijacking vulnerabilities: https://github.com/ideaslocas/aDLL</li>
      <li>tactical-exploitation - provides a smoother and more reliable way of compromising targets by leveraging process vulnerabilities, while minimizing attack detection and other undesired side effects: https://github.com/0xdea/tactical-exploitation</li>
      <li>moonwalk -  a 400 KB single-binary executable that can clear your traces while penetration testing a Unix machine: https://github.com/mufeedvh/moonwalk</li>
      <li>Viper - a graphical intranet penetration tool, which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration: https://github.com/FunnyWolf/Viper</li>
      <li>CandyPotato -  leverages the privilege escalation chain based on certain COM Servers, using a MiTM listener hosted on 127.0.0.1, and it works when you have SeImpersonate or SeAssignPrimaryToken privileges. By default, JuicyPotato uses the BITS service CLSID, and provides other tools (a set of PowerShell and Batch scripts), to enumerate and test other CLSIDs: https://github.com/klezVirus/CandyPotato</li>
      <li>Diamorphine - a LKM rootkit for Linux Kernels 2.6.x/3.x/4.x/5.x and ARM64: https://github.com/m0nad/Diamorphine</li>
      <li>TripleCross - a Linux eBPF rootkit that demonstrates the offensive capabilities of the eBPF technology: https://github.com/h3xduck/TripleCross</li>
            <li>MrKaplan - a tool aimed to help red teamers to stay hidden by clearing evidence of execution. It works by saving information such as the time it ran, snapshot of files and associate each evidence to the related user: https://github.com/Idov31/MrKaplan</li>
                <li>Freeze -  a payload creation tool used for circumventing EDR security controls to execute shellcode in a stealthy manner. Freeze utilizes multiple techniques to not only remove Userland EDR hooks, but to also execute shellcode in such a way that it circumvents other endpoint monitoring controls: https://github.com/optiv/Freeze</li>
      <li>garble - produce a binary that works as well as a regular build, but that has as little information about the original source code as possible: https://github.com/burrowers/garble</li>
      <li>shennina - an automated host exploitation framework. The mission of the project is to fully automate the scanning, vulnerability scanning/analysis, and exploitation using Artificial Intelligence: https://github.com/mazen160/shennina</li>
      <li>shell-backdoor - collection of shell backdoors: https://github.com/beruangsalju/shell-backdoor</li>
      <li>SSH-Snake - a powerful tool designed to perform automatic network traversal using SSH private keys discovered on systems, with the objective of creating a comprehensive map of a network and its dependencies, identifying to what extent a network can be compromised using SSH and SSH private keys starting from a particular system: https://github.com/MegaManSec/SSH-Snake</li>
      <li>ThievingFox - a collection of post-exploitation tools to gather credentials from various password managers and windows utilities: https://github.com/Slowerzs/ThievingFox</li>
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
          <li>How to set up gophish to evade security controls: https://www.sprocketsecurity.com/blog/never-had-a-bad-day-phishing-how-to-set-up-gophish-to-evade-security-controls</li>
          <li>The Ultimate Guide to Phishing - Learn how to Phish using EvilGinx2 and GoPhish: https://sidb.in/2021/08/03/Phishing-0-to-100.html</li>
          <li>SniperPhish -  a phishing toolkit for pentester or security professionals to enhance user awareness by simulating real-world phishing attacks. SniperPhish helps to combine both phishing emails and phishing websites you created to centrally track user actions: https://github.com/GemGeorge/SniperPhish</li>
          <li>phishmonger - Phishing platform designed for pentesters. This tool allows us to craft phishing emails in Outlook, clone them quickly, automatically template them for mass distribution, test email templates, schedule phishing campaigns, and track phishing results. Phishmonger is not just GoPhish in Node! You do not have to set up a separate mail server. Phishmonger itself is a mail server: https://github.com/fkasler/phishmonger</li>
          <li>awsssome_phish - phish aws sso code with dynamic url creation with lambda function: https://github.com/sebastian-mora/awsssome_phish</li>
          <li>Phishious - an open-source Secure Email Gateway (SEG) evaluation toolkit designed for red-teamers and developed by the team at https://caniphish.com. Phishious provides the ability to see how various Secure Email Gateway technologies behave when presented with phishing material: https://github.com/Rices/Phishious</li>
          <li>muraena -  an almost-transparent reverse proxy aimed at automating phishing and post-phishing activities: https://github.com/muraenateam/muraena</li>
          <li>AdvPhishing - phishing with otp bypass techinques: https://github.com/Ignitetch/AdvPhishing</li>
          <li>espoofer - testing tool to bypass SPF, DKIM, and DMARC authentication in email systems: https://github.com/chenjj/espoofer</li>
                    <li>O365-Doppelganger - a quick handy script to harvest credentials of a user during Red Teams: https://github.com/paranoidninja/O365-Doppelganger</li>
          <li>BITB - Browser templates for Browser In The Browser (BITB) attack: https://github.com/mrd0x/BITB</li>
          <li>phishim - a phishing tool which reduces configuration time and bypasses most types of MFA by running a chrome tab on the server that the user unknowingly interacts with: https://github.com/jackmichalak/phishim</li>
          <li>PyPhisher - ultimate phishing tool in python. Includes popular websites like facebook, twitter, instagram, github, reddit, gmail and many others: https://github.com/KasRoudra/PyPhisher</li>
                    <li>phishsticks - a phishing framework for OAuth 2.0 device code authentication grant flow: https://github.com/dunderhay/phishsticks</li>
                    <li>cuddlephish - Weaponized multi-user browser-in-the-middle (BitM) for penetration testers. This attack can be used to bypass multi-factor authentication on many high-value web applications: https://github.com/fkasler/cuddlephish</li>
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
      <li>osmedeus - a Workflow Engine for Offensive Security: https://github.com/j3ssie/osmedeus/</li>
      <li>Cyberonix - a complete resource hub for Cyber Security Community. Our aim is to make this tool an 1 stop solution for all the Hackers out there to get resources of various topics in Cyber Security: https://github.com/TeamMetaxone/Cyberonix</li>
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
    <li>PeTeReport - an open-source application vulnerability reporting tool designed to assist pentesting/redteaming efforts, by simplifying the task of writting and generation of reports: https://github.com/1modm/petereport</li>
    <li>ThreatPursuit-VM - MANDIANT THREAT INTELLIGENCE VM: https://github.com/fireeye/ThreatPursuit-VM</li>
    <li>KQL Internals: https://identityandsecuritydotcom.files.wordpress.com/2020/08/kql_internals_hk.pdf </li>
    <li>jarm - an active Transport Layer Security (TLS) server fingerprinting tool(by CRM): https://github.com/salesforce/jarm</li>
    <li>BruteShark - a Network Forensic Analysis Tool (NFAT) that performs deep processing and inspection of network traffic (mainly PCAP files): https://github.com/odedshimon/BruteShark </li>
    <li>Name-that-hash - will name that hash type: https://github.com/HashPals/Name-That-Hash</li>
    <li>Windows & Active Directory Exploitation Cheat Sheet and Command Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference/</li>
    <li>nzyme - a free and open WiFi defense system that detects and physically locates threats using an easy to build and deploy sensor system: https://www.nzyme.org/</li>
    <li>Certified Pre-Owned - Abusing Active Directory Certificate Services: https://posts.specterops.io/certified-pre-owned-d95910965cd2</li>
    <li>pimpmykali - a shell script that fixes bunch a bugs on a Kali Linux virtual machines https://github.com/Dewalt-arch/pimpmykali</li>
    <li>The Cyber Plumber's Handbook - the definitive guide to Secure Shell (SSH) tunneling, port redirection, and bending traffic like a boss: https://github.com/opsdisk/the_cyber_plumbers_handbook</li>
     <li>RedEye - n open-source analytic tool developed by CISA and DOE’s Pacific Northwest National Laboratory to assist Red Teams with visualizing and reporting command and control activities: https://github.com/cisagov/RedEye/</li>
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
          <li>Security Onion 2 - free and open source Linux distribution for threat hunting, enterprise security monitoring, and log management. It includes TheHive, Playbook and Sigma, Fleet and osquery, CyberChef, Elasticsearch, Logstash, Kibana, Suricata, Zeek, Wazuh, and many other security tools: https://securityonionsolutions.com/software/ | https://docs.securityonion.net/en/2.3/about.html</li>
            <li>unfetter: https://github.com/unfetter-analytic/unfetter </li>
             <li>portspoof: https://github.com/drk1wi/portspoof </li>
          <li>GeoLogonalyzer - a utility to perform location and metadata lookups on source IP addresses of remote access logs: https://github.com/fireeye/GeoLogonalyzer </li>
          <li>Dejavu - open source deception framework which can be used to deploys deploy multiple interactive decoys: https://github.com/bhdresh/Dejavu</li>
          <li>fireeye capa - detects capabilities in executable files. You run it against a PE file or shellcode and it tells you what it thinks the program can do: https://github.com/fireeye/capa </li>
          <li>gravwell-community-edition: https://www.gravwell.io/blog/gravwell-community-edition</li>
          <li>Dsiem - Dsiem is a security event correlation engine for ELK stack, allowing the platform to be used as a       dedicated and full-featured SIEM system: https://github.com/defenxor/dsiem </li>
          <li>siembol - provides a scalable, advanced security analytics framework based on open-source big data technologies. Siembol normalizes, enriches, and alerts on data from various sources, which allows security teams to respond to attacks before they become incidents: https://github.com/G-Research/siembol</li>
          <li>thehive-project - A scalable, open source and free Security Incident Response Platform, tightly integrated with MISP: https://thehive-project.org/ </li>
          <li>Sigma - generic and open signature format that allows you to describe relevant log events in a straight forward manner: https://github.com/Neo23x0/sigma | https://github.com/socprime/SigmaUI </li>
          <li>opencti - Unified platform for all levels of Cyber Threat Intelligence: https://github.com/OpenCTI-Platform/opencti</li>
          <li>wazuh - enterprise-ready security monitoring solution for threat detection, integrity monitoring, incident response and compliance: https://wazuh.com/</li>
          <li>spidertrap - Trap web crawlers and spiders in an infinite set of dynamically generated webpage: https://github.com/adhdproject/adhdproject.github.io/blob/master/Tools/Spidertrap.md </li>
          <li>ElastAlert - a simple framework for alerting on anomalies, spikes, or other patterns of interest from data in Elasticsearch: https://github.com/Yelp/elastalert</li>
          <li>glastof - is a Python web application honeypot founded by Lukas Rist:https://github.com/mushorg/glastopf </li>
          <li>riotpot - an interoperable medium interaction honeypot, primarily focused on the emulation IoT and OT protocols, although, it is also capable of emulating other services: https://github.com/aau-network-security/riotpot</li>
          <li>compot - is a low interactive server side Industrial Control Systems honeypot designed to be easy to deploy, modify and extend: http://conpot.org/ </li>
          <li>jimi - an automation first no-code platform designed and developed originally for Security Orchestration and Response: https://github.com/z1pti3/jimi</li>
          <li>Malcolm - an easily deployable network analysis tool suite for full packet capture artifacts (PCAP files) and Zeek logs: https://github.com/idaholab/Malcolm/blob/master/README.md</li>
          <li>HoneyDB - provides real time data of honeypot activity. This data comes from honeypot sensors deployed globally on the Internet: https://honeydb.io/</li>
          <li>saferwall -  malware analysis platform: https://github.com/saferwall/saferwall </li>
          <li>secureCodeBox - a docker based, modularized toolchain for continuous security scans of your software project: https://github.com/secureCodeBox/secureCodeBox</li>
          <li>NERVE - Network Exploitation, Reconnaissance & Vulnerability Engine: https://github.com/PaytmLabs/nerve</li>
          <li>CHAPS - is a PowerShell script for checking system security settings where additional software and assessment tools, such as Microsoft Policy Analyzer, cannot be installed: https://github.com/cutaway-security/chaps</li>
          <li>Brim - open source desktop application for security and network specialists. Brim makes it easy to search and analyze data from packet captures like those created by Wireshark and structured logs, especially from the Zeek network analysis framework: https://github.com/brimsec/brim </li>
          <li>openuba - A FLEXIBLE OPEN SOURCE UEBA PLATFORM USED FOR SECURITY ANALYTICS: http://openuba.org/</li>
          <li>Intel Owl - OSINT solution to get threat intelligence data about a specific file, an IP or a domain from a single API at scale: https://github.com/intelowlproject/IntelOwl</li>
          <li>Intrigue Core - open attack surface enumeration engine. It integrates and orchestrates a wide variety of  security data sources, distilling them into a normalized object model: https://core.intrigue.io/</li>
          <li>Awesome CobaltStrike Defence: https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence | https://thedfirreport.com/2022/01/24/cobalt-strike-a-defenders-guide-part-2/</li>
          <li>Crossfeed - a tool that continuously enumerates and monitors an organization's public-facing attack surface in order to discover assets and flag potential security flaws: https://github.com/cisagov/crossfeed</li>
          <li>Awesome Incident Response - https://github.com/meirwah/awesome-incident-response</li>
          <li>qiling - an advanced binary emulation framework. Emulate multi-platforms: Windows, MacOS, Linux, BSD, UEFI, DOS, MBR, Ethereum Virtual Machine: https://github.com/qilingframework/qiling</li>
          <li>ssh-audit - a tool for ssh server & client configuration auditing: https://github.com/jtesta/ssh-audit</li>
          <li>IVRE - an open-source framework for network recon. It relies on open-source well-known tools (Nmap, Masscan, ZGrab2, ZDNS and Zeek (Bro)) to gather data (network intelligence), stores it in a database (MongoDB is the recommended backend), and provides tools to analyze it: https://ivre.rocks/</li>
          <li>pcf - Pentest Collaboration Framework - an opensource, cross-platform and portable toolkit for automating routine processes when carrying out various works for testing: https://gitlab.com/invuls/pentest-projects/pcf</li>
          <li>Somnium - a script to test prevention and detection of network threats: https://github.com/asluppiter/Somnium</li>
                    <li>dradis-ce - an open-source collaboration framework, tailored to InfoSec teams: https://github.com/dradis/dradis-ce</li>
          <li>APTRS (Automated Penetration Testing Reporting System) - The tool allows Penetration testers to create a report directly without using the Traditional Docx file. It also provides an approach to keeping track of the projects and vulnerabilities: https://github.com/Anof-cyber/APTRS</li>
          <li>osquery-defense-kit- production-ready detection & response queries for osquery: https://github.com/chainguard-dev/osquery-defense-kit</li>
          <li>sandboxprofiler - collect information of internet-connected sandboxes, no backend needed.
This is achieved using telegram and interact.sh to collect data, however custom listeners are also supported: https://gitlab.com/brn1337/sandboxprofiler</li>
<li>vectr - facilitates tracking of your red and blue team testing activities to measure detection and prevention capabilities across different attack scenarios: https://vectr.io/</li>
<li>hash(HTTP Agnostic Software Honeypot) - a framework for creating and launching low interactive honeypots: https://github.com/DataDog/hash</li>
<li>DIAL (Did I Alert Lambda?) - a centralized security misconfiguration detection framework which completely runs on AWS Managed services like AWS API Gateway, AWS Event Bridge & AWS Lambda: https://github.com/CRED-CLUB/DIAL</li>
<li>modpot - a modular web application honeypot framework written in Golang and making use of gin framework. It is the antithesis to honeydet in many ways and allows the user to deploy simple html/js honeypots that mimic web applications in order to detect requests and form entries that are related to attacks: https://github.com/referefref/modpot</li>
            </span>
            </p3>
            </ul><br>


<h3><b>Web & API Security</h3></b>
<ul>
<li>Automatic API Attack Tool - Imperva's customizable API attack tool takes an API specification as an input, and generates and runs attacks that are based on it as an output: https://github.com/imperva/automatic-api-attack-tool</li>
<li>Taipan - an automated web application vulnerability scanner that allows to identify web vulnerabilities in an automatic fashion: https://github.com/enkomio/Taipan/blob/master/README.md </li>
<li>fuzz-lightyear -  pytest-inspired, DAST framework, capable of identifying vulnerabilities in a distributed, micro-service ecosystem through stateful Swagger fuzzing: https://github.com/Yelp/fuzz-lightyear/blob/master/README.md</li>
<li>GoSpider - gast web spider written in Go: https://github.com/jaeles-project/gospider</li>
<li>XSS-Freak - XSS scanner fully written in python3. It crawls the website for all possible links and directories to expand its attack scope. Then it searches them for input tags and then launches a bunch of XSS payloads: https://github.com/hacker900123/XSS-Freak</li>
<li>vulnx - Intelligent Bot Auto Shell Injector that detects vulnerabilities in multiple types of Cms: https://github.com/anouarbensaad/vulnx</li>
<li>Astra - REST API penetration testing tool: https://github.com/flipkart-incubator/Astra</li>
<li>finalrecon - fast and simple python script for web reconnaissance: https://github.com/thewhiteh4t/finalrecon</li>
  <li>Payloads - A collection of web attack payloads: https://github.com/foospidy/payloads </li>
  <li>AuthMatrix - an extension to Burp Suite that provides a simple way to test authorization in web applications and web services: https://github.com/SecurityInnovation/AuthMatrix</li>
  <li>shhgit - finds secrets and sensitive files across GitHub (including Gists), GitLab and BitBucket committed in near real time: https://github.com/eth0izzle/shhgit</li>
  <li>Sken - One tool to do all scans. Sken packages and manages open source scanners across all scan types, adds a SaaS orchestration layer and automates them in CI/CD: https://www.sken.ai/ </li>
  <li>Hack-Tools - the all-in-one Red Team browser extension for Web Pentesters: https://github.com/LasCC/Hack-Tools</li>
  <li>feroxbuster - a simple, fast, recursive content discovery tool written in Rust: https://github.com/epi052/feroxbuster</li>
  <li>Jaeles - a powerful, flexible and easily extensible framework written in Go for building your own Web Application Scanner: https://github.com/jaeles-project/jaeles</li>
  <li>tamper.dev - an extension that allows you to edit HTTP/HTTPS requests and responses as they happen without the need of a proxy: https://tamper.dev/ </li>
  <li>proxify - Swiss Army Knife Proxy for rapid deployments. Supports multiple operations such as request/response dump, filtering and manipulation via DSL language, upstream HTTP/Socks5 proxy: https://github.com/projectdiscovery/proxify</li>
  <li>XSSTRON - Powerful Chromium Browser to find XSS Vulnerabilites automatically while browsing web: https://github.com/RenwaX23/XSSTRON</li>
  <li>AutoRepeater - Automated HTTP Request Repeating With Burp Suite: https://github.com/nccgroup/AutoRepeater</li>
<li>xsshunter - allows you to find all kinds of cross-site scripting vulnerabilities, including the often-missed blind XSS. The service works by hosting specialized XSS probes which, upon firing, scan the page and send information about the vulnerable page to the XSS Hunter service: https://xsshunter.com/</li>
  <li>vajra - automated web hacking framework to automate boring recon tasks and same scans for multiple target during web applications penetration testing. Vajra has highly customizable target scope based scan feature: https://github.com/r3curs1v3-pr0xy/vajra</li>
  <li>MindAPI - a mindmap which combines years of experience in testing API security: https://github.com/dsopas/MindAPI</li>
  <li>gotestwaf - Go project to test different web application firewalls (WAF) for detection logic and bypasses: https://github.com/wallarm/gotestwaf</li>
  <li>kiterunner - API and content discovery at lightning fast speeds, bruteforcing routes/endpoints in modern applications: https://github.com/assetnote/kiterunner</li>
  <li>Epiphany - a pre-engagement \ self-assessment tool to identify weak spots of a web property from a DDoS attacker perspective: https://github.com/Cyberlands-io/epiphany</li>
  <li>jwtXploiter - a tool to test security of JSON Web Tokens. Test a JWT against all known CVEs: https://github.com/DontPanicO/jwtXploiter</li>
  <li>rengine - An automated reconnaissance framework for web applications with focus on highly configurable streamlined recon process via Engines, recon data correlation and organization, continuous monitoring, backed by database and simple yet intuitive User Interfac: https://github.com/yogeshojha/rengine</li>
  <li>graphw00f - inspired by wafw00f is the GraphQL fingerprinting tool for GQL endpoints, it sends a mix of benign and malformed queries to determine the GraphQL engine running behind the scenes. graphw00f will provide insights into what security defences each technology provides out of the box, and whether they are on or off by default: https://github.com/dolevf/graphw00f</li>
  <li>changeme - ocuses on detecting default and backdoor credentials and not necessarily common credentials. It's default mode is to scan HTTP default credentials, but has support for other credentials: https://github.com/ztgrace/changeme</li>
  <li>keyhacks - shows ways in which particular API keys found on a Bug Bounty Program can be used, to check if they are valid: https://github.com/streaak/keyhacks</li>
  <li>SSRFmap - SSRF are often used to leverage actions on other services, this framework aims to find and exploit these services easily. SSRFmap takes a Burp request file as input and a parameter to fuzz: https://github.com/swisskyrepo/SSRFmap</li>
  <li>PayloadsAllTheThings - A list of useful payloads and bypasses for Web Application Security. Feel free to improve with your payloads and techniques: https://github.com/swisskyrepo/PayloadsAllTheThings</li>
  <li>cookiemonster -  command-line tool and API for decoding and modifying vulnerable session cookies from several different frameworks. It is designed to run in automation pipelines which must be able to efficiently process a large amount of these cookies to quickly discover vulnerabilities. Additionally, CookieMonster is extensible and can easily support new cookie formats: https://github.com/iangcarroll/cookiemonster/</li>
  <li>forbidden - Bypass 4xx HTTP response status codes. Based on PycURL: https://github.com/ivan-sincek/forbidden</li>
  <li>nginxpwner - a simple tool to look for common Nginx misconfigurations and vulnerabilities: https://github.com/stark0de/nginxpwner</li>
  <li>XSRFProbe - an advanced Cross Site Request Forgery (CSRF/XSRF) Audit and Exploitation Toolkit. Equipped with a powerful crawling engine and numerous systematic checks, it is able to detect most cases of CSRF vulnerabilities, their related bypasses and futher generate (maliciously) exploitable proof of concepts with each found vulnerability: https://github.com/0xInfection/XSRFProbe</li>
  <li>fuzz300 - this tool does collect all the entry-points for the target website and then tryes to find open redirect vulnerability: https://github.com/d34db33f-1007/fuzz300</li>
  <li>Awesome WebSockets Security - a collection of CVEs, research, and reference materials related to WebSocket security: https://github.com/PalindromeLabs/awesome-websocket-security</li>
  <li>STEWS - a tool suite for security testing of WebSockets: https://github.com/PalindromeLabs/STEWS</li>
  <li>authz0 - an automated authorization test tool. Unauthorized access can be identified based on URLs and Roles & Credentials: https://github.com/hahwul/authz0</li>
  <li>OAUTHScan -  is a Burp Suite Extension written in Java with the aim to provide some automatic security checks, which could be useful during penetration testing on applications implementing OAUTHv2 and OpenID standards: https://github.com/akabe1/OAUTHScan</li>
  <li>TamperThemAll - a tampered payload generator to Fuzz Web Application Firewalls for Testing and Bypassing: https://github.com/francescolacerenza/TamperThemAll</li>
  <li>API Security Empire - mindmaps, tips & tricks, resources and every thing related to API Security and API Penetration Testing: https://github.com/cyprosecurity/API-SecurityEmpire</li>
  <li>Arjun - HTTP Parameter Discovery Suite: https://github.com/s0md3v/Arjun</li>
  <li>httploot - an automated tool which can simultaneously crawl, fill forms, trigger error/debug pages and "loot" secrets out of the client-facing code of sites: https://github.com/redhuntlabs/httploot</li>
  <li>Request smuggler - http request smuggling vulnerability scanner: https://github.com/Sh1Yo/request_smuggler</li>
  <li>GraphCrawler - the most powerful automated testing toolkit for any GraphQL endpoint: https://github.com/gsmith257-cyber/GraphCrawler</li>
    <li>dalfox - an powerful open source XSS scanning tool and parameter analyzer and utility that fast the process of detecting and verify XSS flaws: https://github.com/hahwul/dalfox</li>
  <li>hakoriginfinder - Tool for discovering the origin host behind a reverse proxy. Useful for bypassing WAFs and other reverse proxies: https://github.com/hakluke/hakoriginfinder</li>
  <li>JavaScript obfuscator - a powerful free obfuscator for JavaScript, containing a variety of features which provide protection for your source code: https://github.com/javascript-obfuscator/javascript-obfuscator</li>
  <li>WebHackersWeapons - a collection of awesome tools used by Web hackers: https://github.com/hahwul/WebHackersWeapons</li>
  <li>awesome-api-security - a collection of awesome API Security tools and resources. The focus goes to open-source tools and resources that benefit all the community: https://github.com/arainho/awesome-api-security</li>
  <li>jwt-reauth - Burp plugin to cache authentication tokens from an "auth" URL, and then add them as headers on all requests going to a certain scope: https://github.com/nccgroup/jwt-reauth</li>
  <li>guardara - a comprehensive dynamic testing tool to find bugs and zero-day vulnerabilities in custom/proprietary products, protocols, web services and applications, and complex environments: https://guardara-community.gitlab.io/documentation/docs/intro</li>
  <li>JAW - prototype implementation of property graphs for JavaScript based on the esprima parser, and the EsTree SpiderMonkey Spec. JAW can be used for analyzing the client-side of web applications and JavaScript-based programs: https://github.com/SoheilKhodayari/JAW</li>
  <li>graphicator - a GraphQL "scraper" / extractor. The tool iterates over the introspection document returned by the targeted GraphQL endpoint, and then re-structures the schema in an internal form so it can re-create the supported queries: https://github.com/cybervelia/graphicator</li>
  <li>caido - A lightweight web security auditing toolkit built from the ground up in Rust: https://caido.io/</li>
  <li>firefly - an advanced black-box fuzzer and not just a standard asset discovery tool. Firefly provides the advantage of testing a target with a large number of built-in checks to detect behaviors in the target: https://github.com/Brum3ns/firefly</li>
  <li>recollapse - a helper tool for black-box regex fuzzing to bypass validations and discover normalizations in web applications: https://github.com/0xacb/recollapse</li>
  <li>IPRotate_Burp_Extension - Extension for Burp Suite which uses AWS API Gateway to change your IP on every request: https://github.com/RhinoSecurityLabs/IPRotate_Burp_Extension</li>
  <li>burp-vps-proxy - a Burp Suite extension that allows for the automatic creation and deletion of upstream SOCKS5 proxies on popular cloud providers from within Burp Suite: https://github.com/d3mondev/burp-vps-proxy</li>
  <li>waf-bypass - an open source tool to analyze the security of any WAF for False Positives and False Negatives using predefined and customizable payloads: https://github.com/nemesida-waf/waf-bypass</li>
  <li>metlo - an open-source API security platform: https://github.com/metlo-labs/metlo</li>
  <li>burp-vps-proxy - a Burp Suite extension that allows for the automatic creation and deletion of upstream SOCKS5 proxies on popular cloud providers from within Burp Suite: https://github.com/d3mondev/burp-vps-proxy</li>
    <li>dastardly - a lightweight web application security scanner for your CI/CD pipeline: https://portswigger.net/burp/dastardly</li>
  <li>burp-awesome-tls - this extension hijacks Burp's HTTP/TLS stack and allows you to spoof any browser fingerprint in order to make it more powerful and less prone to fingerprinting by all kinds of WAFs: https://github.com/sleeyax/burp-awesome-tls</li>
  <li>burpgpt - leverages the power of AI to detect security vulnerabilities that traditional scanners might miss: https://github.com/aress31/burpgpt</li>
  <li>GraphQLmap - a scripting engine to interact with a graphql endpoint for pentesting purposes: https://github.com/swisskyrepo/GraphQLmap</li>
  <li>graphquail - a Burp Suite extension that offers a toolkit for testing GraphQL endpoints: https://github.com/forcesunseen/graphquail</li>
  <li>route-detect - find authentication (authn) and authorization (authz) security bugs in web application routes: https://github.com/mschwager/route-detect</li>
  <li>OWASP OFFAT(OFFensive Api Tester) - automatically Tests for vulnerabilities after generating tests from openapi specification file: https://github.com/OWASP/OFFAT</li>
  <li>Swagger-EZ - a tool geared towards pentesting APIs using OpenAPI definitions: https://github.com/RhinoSecurityLabs/Swagger-EZ</li>
  <li>schemathesis - a tool that automates your API testing to catch crashes and spec violations: https://github.com/schemathesis/schemathesis</li>
  <li>reaper - a reconnaissance and attack proxy, built to be a modern, lightweight, and efficient equivalent to Burp Suite/ZAP etc: https://github.com/ghostsecurity/reaper</li>
  <li>sj - a command line tool designed to assist with auditing of exposed Swagger/OpenAPI definition files by checking the associated API endpoints for weak authentication: https://github.com/BishopFox/sj</li>
  <li>[fingerprint-suite - a handcrafted assembly of tools for browser fingerprint generation and injection: ](https://github.com/apify/fingerprint-suite)</li>
  <li>[GAP-Burp-Extension - an evolution of the original getAllParams extension for Burp. Not only does it find more potential parameters for you to investigate, but it also finds potential links to try these parameters on, and produces a target specific wordlist to use for fuzzing: ](https://github.com/xnl-h4ck3r/GAP-Burp-Extension)</li>
  <li>[xsshunter - a working and easy to install fork of XSSHunter](https://github.com/rs-loves-bugs/xsshunter)</li>
  <li>sessionprobe - a multi-threaded pentesting tool designed to assist in evaluating user privileges in web applications. It takes a user's session token and checks for a list of URLs if access is possible, highlighting potential authorization issues: https://github.com/dub-flow/sessionprobe</li>
  <li>apidetector - a powerful and efficient tool designed for testing exposed Swagger endpoints in various subdomains with unique smart capabilities to detect false-positives: https://github.com/brinhosa/apidetector</li>
  <li>mitmproxy2swagger - a tool for automatically converting mitmproxy captures to OpenAPI 3.0 specifications: https://github.com/alufers/mitmproxy2swagger</li>
  <li>restler-fuzzer -the first stateful REST API fuzzing tool for automatically testing cloud services through their REST APIs and finding security and reliability bugs in these services: https://github.com/microsoft/restler-fuzzer</li>
  <li>BypassFuzzer - this tool performs various checks via headers, path normalization, verbs, etc. to attempt to bypass ACL's or URL validation: https://github.com/intrudir/BypassFuzzer</li>
  <li>nomore403 - an innovative tool designed to help cybersecurity professionals and enthusiasts bypass HTTP 40X errors encountered during web security assessments: https://github.com/devploit/nomore403</li>
  <li>bypass-url-parser - tool that tests MANY url bypasses to reach a 40X protected page: https://github.com/laluka/bypass-url-parser</li>
  <li>Gecko - is a powerful Chrome extension designed to automate the discovery of Client-Side Path Traversals (CSPT) in web applications. It seamlessly integrates with Chrome DevTools and provides a user-friendly interface for identifying and analyzing CSPT vulnerabilities: https://github.com/vitorfhc/gecko | https://vitorfalcao.com/posts/automating-cspt-discovery | https://github.com/doyensec/CSPTPlayground</li>
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
<li>PESD-Exporter-Extension - generate security-oriented sequence diagrams and fine-grained parsed traffic from Burp Suite Proxy history: https://github.com/doyensec/PESD-Exporter-Extension</li>
</ul></br>

<h3><b>Cloud Security</h3></b>
<ul>
<li>serverless-prey - a collection of serverless functions (FaaS), that, once launched to a cloud environment and invoked, establish a TCP reverse shell, enabling the user to introspect the underlying container: https://github.com/pumasecurity/serverless-prey </li>
<li>Deepfence Runtime Threat Mapper - is a subset of the Deepfence cloud native workload protection platform, released as a community edition: https://github.com/deepfence/ThreatMapper/blob/master/README.md</li>
<li>Dow Jones Hammer - a multi-account cloud security tool for AWS. It identifies misconfigurations and insecure data exposures within most popular AWS resources, across all regions and accounts: https://github.com/dowjones/hammer/blob/master/README.md</li>
<li>SkyArk -  a cloud security project with two main scanning modules- AzureStealth | AWStealth: https://github.com/cyberark/SkyArk </li>
<li>serverless-prey - a collection of serverless functions (FaaS), that, once launched to a cloud environment and invoked, establish a TCP reverse shell, enabling the user to introspect the underlying container: https://github.com/pumasecurity/serverless-prey</li>
<li>Prowler - AWS Security Toola command line tool for AWS Security Best Practices Assessment, Auditing, Hardening and Forensics Readiness Tool: https://github.com/toniblyx/prowler</li>
<li>cloudsploit (Aqua) - an open-source project designed to allow detection of security risks in cloud infrastructure accounts: https://github.com/aquasecurity/cloudsploit </li>
<li>deepfence SecretScanner - helps users scan their container images or local directories on hosts and outputs JSON file with details of all the secrets found: https://github.com/deepfence/SecretScanner </li>
<li>OpenCSPM - an open-source platform for gaining deeper insight into your cloud configuration and metadata to help understand and reduce risk over time: https://github.com/OpenCSPM/opencspm </li>
<li>endgame - An AWS Pentesting tool that `let`s you use one-liner commands to backdoor an AWS account's resources with a rogue AWS account - or share the resources with the entire Internet: https://endgame.readthedocs.io/en/latest/ </li>
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
<li>Roadtools -  a framework to interact with Azure AD. It currently consists of a library (roadlib) and the ROADrecon Azure AD exploration tool: https://github.com/dirkjanm/ROADtools </li>
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
<li>azucar - a multi-threaded plugin-based tool to help you assess the security of your Azure Cloud environment: https://github.com/nccgroup/azucar</li>
<li>TokenTactics - Azure JSON Web Token ("JWT") Manipulation Toolset: https://github.com/rvrsh3ll/TokenTactics</li>
<li>Microsoft365_devicePhish - Abusing Microsoft 365 OAuth Authorization Flow for Phishing Attack: https://github.com/bigb0sss/Microsoft365_devicePhish</li>
<li>Spray365 -  a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD): https://github.com/MarkoH17/Spray365</li>
<li>AzureHunter - Powershell module to run threat hunting playbooks on data from Azure and O365 for Cloud Forensics purposes: https://github.com/darkquasar/AzureHunter</li>
<li>TREVORspray - a modular password sprayer with threading, SSH proxying, loot modules, and more: https://github.com/blacklanternsecurity/TREVORspray</li>
<li>aadcookiespoof - cookie replay client for testing Azure AD Identity Protection: https://github.com/jsa2/aadcookiespoof</li>
<li>SSOh-No - this tool is designed to enumerate users, password spray and perform brute force attacks against any organisation that utilises Azure AD or O365: https://github.com/optionalCTF/SSOh-No</li>
<li>Go365 - a tool designed to perform user enumeration* and password guessing attacks on organizations that use Office365 (now/soon Microsoft365). Go365 uses a unique SOAP API endpoint on login.microsoftonline.com that most other tools do not use: https://github.com/optiv/Go365</li>
<li>BlueHound - a tool that helps blue teams pinpoint the security issues that actually matter. By combining information about user permissions, network access and unpatched vulnerabilities, BlueHound reveals the paths attackers would take if they were inside your networkhttps://github.com/zeronetworks/BlueHound | https://zeronetworks.com/blog/bluehound-community-driven-resilience/</li>
<li><[GraphRunner - a post-exploitation toolset for interacting with the Microsoft Graph API: ](https://github.com/dafthack/GraphRunner)/li>
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
<li>codepen - a social development environment for front-end designers and developers. Build and deploy a website, show off your work, build test cases to learn and debug, and find inspiration: https://codepen.io/: https://codepen.io/</li>
<li>[CodeSandbox - consistent development environments that boost productivity and empower collaboration: ](https://codesandbox.io/)</li>
<li>json path finder: https://jsonpath.com/ </li>
<li>json query language: https://jmespath.org/ </li>
<li>A tool that generates graph diagrams from JSON objects: https://jsoncrack.com/editor | https://github.com/AykutSarac/jsoncrack.com</li>
<li>repl.it - online Python compiler: https://repl.it/languages/Python%3F__s=ws9cqndijs3fipi6sacu</li>
<li>Playgrounds by codedamn are free in-browser IDE environments: https://codedamn.com/playgrounds</li>
<li>codesandbox - supercharge your workflow with instant cloud development environments: https://codesandbox.io/</li>
<li>dillinger - live markdown editor https://dillinger.io/ </li>
<li>glitch -  the friendly community where everyone codes together: https://glitch.com/</li>
<li>JS lint: https://jshint.com/</li>
<li>JSON schema data generator: https://json-schema-faker.js.org/ </li>
  <li>graphql-playground: https://github.com/graphql/graphql-playground</li>
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
  <li>HTTP API Development Tools: https://github.com/yosriady/api-development-tools</li>
    <li>Cherrybomb - a CLI tool that helps you avoid undefined user behavior by validating your API specifications: https://www.blstsecurity.com/</li>
    <li>Sample Swagger files: http://rackerlabs.github.io/wadl2swagger/openstack.html</li>
    <li>swagroutes - a command-line tool that extracts and lists API routes from Swagger files in YAML or JSON format: https://github.com/amalmurali47/swagroutes</li>
    <li>Altair GraphQL Client -  debug GraphQL queries and implementations - taking care of the hard part so you can focus on actually getting things done: https://altairgraphql.dev/</li>
    <li>openapi-devtools - effortlessly discover API behaviour with a Chrome extension that automatically generates OpenAPI specifications in real time for any app or website: https://github.com/AndrewWalsh/openapi-devtools</li>
    <li>graphql-voyager: https://graphql-kit.com/graphql-voyager/</li>
    <li>Bruno - opensource IDE for exploring and testing APIs: https://github.com/usebruno/bruno</li>
    <li>Stay up to date with a community-driven list of high-quality, modern tools for OpenAPI: https://openapi.tools/</li>
  </ul>
  
</br>
<p2><b>Password Lists</b></p2>
<ul>
<li>https://wiki.skullsecurity.org/index.php?title=Passwords</li>
<li>Seclists - https://github.com/danielmiessler/SecLists</li>
<li>Probable-Wordlists: https://github.com/berzerk0/Probable-Wordlists</li>
</ul>

<p2><b><u>Stress Test / Web Traffic Simulation / Test Automation</u></b><p2>
<li>https://loader.io/</li>
<li>https://a.blazemeter.com/app/sign-in</li>
<li>https://artillery.io/</li>
<li>locust - Define user behaviour with Python code, and swarm your system with millions of simultaneous users: https://locust.io/</li>
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
<li>hey - a tiny program that sends some load to a web application: https://github.com/rakyll/hey</li>
 <li>vegeta - a versatile HTTP load testing tool built out of a need to drill HTTP services with a constant request rate. It can be used both as a command line utility and a library: https://github.com/tsenart/vegeta</li>
 <li>ddosify - high-performance load testing tool: https://github.com/ddosify/ddosify | https://ddosify.com/blog/testing-the-performance-of-user-authentication-flow</li>
