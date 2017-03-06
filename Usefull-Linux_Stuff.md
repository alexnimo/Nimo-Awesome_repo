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

