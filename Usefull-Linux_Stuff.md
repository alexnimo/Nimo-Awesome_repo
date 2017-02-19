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


