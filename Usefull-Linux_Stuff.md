<b><u>How to setup vlans:</u></b><br>
<ul>
<li><b>sudo apt-get install vlan</b></li>
<li><b>sudo modprobe 8021q</b></li>
<li><b>sudo vconfig add {interface name} {vlan id}</b></li>
<li>Edit /etc/network/interfaces <br>
auto {interface name}.{vlan id}<br>
iface {interface name}.{vlan id} inet static<br>
vlan-raw-device eth0</li>
</ul>

<b><u>Install and run VNC on kali on AWS</u></b><br>
<li><b>sudo apt-get install xfce4 xfce4-goodies tightvncservern</b></li>
<li><b>apt-get install gnome-core kali-defaults kali-root-login desktop-base</b></li>
<li>Set the resolution - <b>tightvncserver –geometry 1650x1280</b></li>
<li><b>nano ~/.vnc/xstartup</b>
<ul>
#!/bin/sh</br>
</br>
# Uncomment the following two lines for normal desktop:</br>
unset SESSION_MANAGER</br>
# exec /etc/X11/xinit/xinitrc</br>
unset DBUS_SESSION_BUS_ADDRESS</br>
startxfce4 &</br>
</br>
[ -x /etc/vnc/xstartup ] && exec /etc/vnc/xstartup</br>
[ -r $HOME/.Xresources ] && xrdb $HOME/.Xresources</br>
xsetroot -solid grey</br>
vncconfig -iconic &</br>
# x-terminal-emulator -geometry 80x24+10+10 -ls -title "$VNCDESKTOP Desktop" &</br>
# x-window-manager &</br>
</ul>
<li>Set the SSH tunnel using putty: <b>Connection-->SSH-->Tunnels--> 5901 AWS-Public-DNS(not the IP!):5901</b></li>
Fix tab completion issue:
<ul>
<li>edit: <b>~/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-keyboard-shortcuts.xml</b></li>
<li>Search for the following prepertity and unset it: <b>&lt;property name="&lt;Super&gt;Tab" type="string" value="switch_window_key"/></b></br>
<b>&lt;property name="&lt;Super&gt;Tab" type="string" value="empty"/></b></li>
<li>restart xfce or the server for the effect to take place</li>
</ul>

<b><u>Install Node.js on Linux</b></u>
<ul>
<li> Verify that you have all required tools</br>
<b>sudo apt-get install python g++ make checkinstall fakeroot</b></li>
<li>Create tmp dir and switch to it</br>
<b>src=$(mktemp -d) && cd $src</b></li>
<li> Download the latest version of Node</br>
<b>wget -N http://nodejs.org/dist/node-latest.tar.gz<b></li>
<li>Extract the content of the tar file</br>
<b>tar xzvf node-latest.tar.gz && cd node-v*</b></li>
<li> Run configuration</br>
<b>./configure</b></li>
<li>Create .deb for Node</br>
<b>sudo fakeroot checkinstall -y --install=no --pkgversion $(echo $(pwd) | sed -n -re's/.+node-v(.+)$/\1/p') make -j$(($(nproc)+1)) install</b></li>
<li> Replace [node_*] with the name of the generated .deb package of the previous step</br>
<b>sudo dpkg -i node_*</b></li>
</ul>

