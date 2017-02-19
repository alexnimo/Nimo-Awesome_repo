<b><u>How to setup vlans:</u></b><br>
<ul>
<li><b>sudo apt-get install vlan</b></li>
<li><b>sudo modprobe 8021q</b></li>
<li><b>sudo vconfig add {interface name} {vlan id}</b></li>
<li><b>Edit /etc/network/interfaces</b>
auto {interface name}.{vlan id}
iface {interface name}.{vlan id} inet static
vlan-raw-device eth0
</ul>


