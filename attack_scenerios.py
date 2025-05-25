#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import os
import time

def create_topology():
    # Create an empty network with a remote controller
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch, link=TCLink)

    # Add controller
    info('*** Adding controller\n')
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    # Add a single switch
    info('*** Adding switch\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow10')

    # Add hosts
    info('*** Adding hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')  # Attacker
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')  # Victim
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')  # Snort IDS

    # Add links
    info('*** Adding links\n')
    net.addLink(h1, s1)
    net.addLink(s1, h2)
    net.addLink(s1, h3)

    # Start network
    info('*** Starting network\n')
    net.build()
    c0.start()
    s1.start([c0])
    # Configure services on h2
    info('*** Setting up services on victim (h2)\n')
    h2.cmd('apt-get update')
    h2.cmd('apt-get install -y apache2 openssh-server inetutils-inetd telnetd sshpass')
    h2.cmd('echo "<h1>Welcome</h1>" > /var/www/html/index.html')
    h2.cmd('service apache2 start')
    h2.cmd('mkdir -p /var/run/sshd')
    h2.cmd('echo "root:root" | chpasswd')
    h2.cmd('sed -i "s/PermitRootLogin prohibit-password/PermitRootLogin yes/" /etc/ssh/sshd_config')
    h2.cmd('service ssh start')
    h2.cmd('echo "telnet stream tcp nowait root /usr/sbin/tcpd /usr/sbin/in.telnetd" >> /etc/inetd.conf')
    h2.cmd('service openbsd-inetd restart')
    h2.cmd('python3 -m http.server 80 &')
    # Configure Snort on h3
    info('*** Setting up Snort on h3\n')
    
    # Create Snort configuration directory on h3
    h3.cmd('mkdir -p /tmp/snort/etc')
    h3.cmd('mkdir -p /tmp/snort/log')
    h3.cmd('mkdir -p /tmp/snort/rules')
    
    # Create snort.conf file - enhanced for better logging
    with open('/tmp/snort/etc/snort.conf', 'w') as f:
        f.write("""
# Snort Configuration for Monitoring between h1 and h2

# Network settings
ipvar HOME_NET 10.0.0.0/24
ipvar EXTERNAL_NET any

# Server settings
portvar HTTP_PORTS [80,8080]
portvar SSH_PORTS 22

# Path to rules
var RULE_PATH /tmp/snort/rules
var LOG_PATH /tmp/snort/log

# Set up decoder
config disable_decode_alerts
config disable_tcpopt_experimental_alerts
config disable_tcpopt_obsolete_alerts
config disable_tcpopt_ttcp_alerts
config disable_tcpopt_alerts
config disable_ipopt_alerts

# Output configuration - more verbose logging
output alert_fast: /tmp/snort/log/alert.fast
output log_tcpdump: /tmp/snort/log/snort.log
output alert_csv: /tmp/snort/log/alert.csv timestamp,msg,src,srcport,dst,dstport,proto,ethsrc,ethdst
output alert_syslog: host=localhost facility=local5 level=alert
output unified2: filename /tmp/snort/log/unified2.log, limit 128, nostamp

# Dynamic libraries
# Note: Comment these out if not available in your installation
# dynamicpreprocessor directory /usr/local/lib/snort_dynamicpreprocessor/
# dynamicengine /usr/local/lib/snort_dynamicengine/libsf_engine.so
# dynamicdetection directory /usr/local/lib/snort_dynamicrules

# Preprocessors
preprocessor frag3_global: max_frags 65536
preprocessor frag3_engine: policy windows detect_anomalies overlap_limit 10 min_fragment_length 100 timeout 180

preprocessor stream5_global: track_tcp yes, track_udp yes, track_icmp no
preprocessor stream5_tcp: policy windows, use_static_footprint_sizes
preprocessor stream5_udp: ignore_any_rules

#preprocessor http_inspect: global iis_unicode_map unicode.map 1252
#preprocessor http_inspect_server: server default \\
#    profile all ports { 80 8080 } oversize_dir_length 500 \\
#    server_flow_depth 0 client_flow_depth 0 

# Include rules
include $RULE_PATH/local.rules
""")
    
    # Create enhanced local.rules file with more specific rules
    with open('/tmp/snort/rules/local.rules', 'w') as f:
        f.write("""

# ICMP detection
alert icmp any any -> any any (msg:"Generic ICMP detected"; sid:1000010; rev:1;)
alert icmp any any <> any any (msg:"Bidirectional ICMP"; sid:1000015; rev:1;)

# TCP detection for port 80 and 22
alert tcp any any -> any 80 (msg:"Generic TCP to port 80"; sid:1000011; rev:1;)
alert tcp any any -> any 22 (msg:"Generic TCP to port 22"; sid:1000012; rev:1;)

# HTTP content inspection (more flexible)
alert tcp any any -> any 80 (content:"union select"; nocase; msg:"SQLi attempt"; sid:1000013; rev:1;)
alert tcp any any -> any 80 (content:"<script>"; nocase; msg:"XSS attempt"; sid:1000014; rev:1;)

# SSH brute force
alert tcp any any -> any 22 (flags:S; detection_filter:track by_src, count 5, seconds 60; msg:"SSH brute force"; sid:1000016; rev:1;)

# Port scan detection
alert tcp any any -> any any (flags:S; detection_filter:track by_src, count 5, seconds 2; msg:"Port scan attempt"; sid:1000017; rev:1;)

""")
    # Create unicode.map file (required by http_inspect)
    with open('/tmp/snort/etc/unicode.map', 'w') as f:
        f.write("""
# Minimal unicode map for HTTP inspect
#
# Format: <code_page> <unicode> <ascii>
1252 0x00a0 0x20
""")

    h3.cmd('ifconfig h3-eth0 promisc up')
    h3.cmd('pkill -f snort')
    time.sleep(1)
    h3.cmd('snort -c /tmp/snort/etc/snort.conf -i h3-eth0 -A console -K ascii -v > /tmp/snort/log/alert.mk &')
    time.sleep(2)

    info('*** Testing connectivity\n')
    net.pingAll()

    info('\n*** Running attack scenarios ***\n')
    info('Scenario 1: ICMP ping\n')
    h1.cmd('ping -c 5 10.0.0.2')

    info('Scenario 2: HTTP GET\n')
    h1.cmd('curl http://10.0.0.2/')

    info('Scenario 3: SQL Injection\n')
    h1.cmd('curl "http://10.0.0.2/index.html?id=1 union select user,password from users"')

    info('Scenario 4: XSS\n')
    h1.cmd('curl "http://10.0.0.2/index.html?xss=<script>alert(1)</script>"')

    info('Scenario 5: SSH Brute Force\n')
    for i in range(6):
        h1.cmd('sshpass -p wrongpass ssh -o StrictHostKeyChecking=no root@10.0.0.2 -p 22 "exit"')

    info('Scenario 6: Telnet Login\n')
    h1.cmd('echo "quit" | telnet 10.0.0.2 23')

    info('\n*** Waiting for Snort to log alerts ***\n')
    time.sleep(5)

    alerts = h3.cmd('cat /tmp/snort/log/alert.fast')
    info('Snort Alerts:\n%s\n' % alerts)

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()
