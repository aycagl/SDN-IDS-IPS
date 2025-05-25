"""
Enhanced POX controller script for SDN Snort monitoring with blocking capability.
Forwards traffic between h1 and h2, mirrors it to h3 for IDS, and blocks malicious IPs.
"""
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
from pox.forwarding.l2_learning import LearningSwitch
from pox.web.webcore import launch
import threading
import time

log = core.getLogger()

# Monitored IPs and MACs
ATTACKER_IP = "10.0.0.1"
VICTIM_IP = "10.0.0.2"
SNORT_MAC = "00:00:00:00:00:03"

class SnortMonitor(LearningSwitch):
    def __init__(self, connection, transparent):
        LearningSwitch.__init__(self, connection, transparent)
        self.blocked_ips = set()
        log.info("[SnortMonitor] Initialized for %s", dpid_to_str(connection.dpid))
        
        # Install default flow rule for blocked IPs checking
        self.install_default_rules()
    
    def install_default_rules(self):
        """Install default flow rules for the switch"""
        try:
            # Install a low-priority rule that allows normal traffic
            msg = of.ofp_flow_mod()
            msg.priority = 1  # Low priority
            msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
            self.connection.send(msg)
            log.info("[SnortMonitor] Default controller rule installed")
        except Exception as e:
            log.error("[SnortMonitor] Failed to install default rules: %s", str(e))
    
    def block_ip(self, ip_to_block):
        """Install flow rule to block traffic from specific IP"""
        try:
            if ip_to_block in self.blocked_ips:
                log.info("[SnortMonitor] IP %s already blocked", ip_to_block)
                return True
            
            # Create flow mod message to drop packets from blocked IP
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match()
            msg.match.dl_type = 0x0800  # IPv4
            msg.match.nw_src = IPAddr(ip_to_block)
            msg.priority = 1000  # High priority to override other rules
            # Empty actions list means drop the packet
            msg.actions = []
            
            self.connection.send(msg)
            self.blocked_ips.add(ip_to_block)
            
            log.info("[SnortMonitor] ✓ BLOCKED IP: %s", ip_to_block)
            return True
            
        except Exception as e:
            log.error("[SnortMonitor] Failed to block IP %s: %s", ip_to_block, str(e))
            return False
    
    def unblock_ip(self, ip_to_unblock):
        """Remove flow rule that blocks specific IP"""
        try:
            if ip_to_unblock not in self.blocked_ips:
                log.info("[SnortMonitor] IP %s is not blocked", ip_to_unblock)
                return True
            
            # Create flow mod message to delete the blocking rule
            msg = of.ofp_flow_mod()
            msg.command = of.OFPFC_DELETE
            msg.match = of.ofp_match()
            msg.match.dl_type = 0x0800  # IPv4
            msg.match.nw_src = IPAddr(ip_to_unblock)
            
            self.connection.send(msg)
            self.blocked_ips.remove(ip_to_unblock)
            
            log.info("[SnortMonitor] ✓ UNBLOCKED IP: %s", ip_to_unblock)
            return True
            
        except Exception as e:
            log.error("[SnortMonitor] Failed to unblock IP %s: %s", ip_to_unblock, str(e))
            return False
    
    def is_blocked(self, ip):
        """Check if an IP is currently blocked"""
        return ip in self.blocked_ips
    
    def _handle_PacketIn(self, event):
        """Override parent method to add blocking logic"""
        try:
            packet = event.parsed
            if not packet.parsed:
                log.warning("Ignoring incomplete packet")
                return
            
            # Learn MAC to port mapping like the base class
            self.macToPort[packet.src] = event.port
            
            ip_packet = packet.find('ipv4')
            if ip_packet:
                src_ip = str(ip_packet.srcip)
                dst_ip = str(ip_packet.dstip)
                
                # Check if source IP is blocked
                if src_ip in self.blocked_ips:
                    log.info("[SnortMonitor] Dropped packet from blocked IP: %s", src_ip)
                    return  # Drop the packet
                
                # Monitor and mirror traffic between h1 and h2
                if ((src_ip == ATTACKER_IP and dst_ip == VICTIM_IP) or
                    (src_ip == VICTIM_IP and dst_ip == ATTACKER_IP)):
                    
                    proto = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(ip_packet.protocol, str(ip_packet.protocol))
                    log.info("Monitored Traffic: %s > %s [%s]", src_ip, dst_ip, proto)
                    
                    dst_mac = str(packet.dst)
                    out_port = self.macToPort.get(packet.dst)
                    snort_port = self.macToPort.get(EthAddr(SNORT_MAC))
                    
                    msg = of.ofp_packet_out(data=event.ofp)
                    
                    # Forward to destination
                    if out_port:
                        msg.actions.append(of.ofp_action_output(port=out_port))
                    else:
                        log.warning("Unknown output port for dst MAC: %s", dst_mac)
                    
                    # Mirror to Snort
                    if snort_port and snort_port != out_port:
                        msg.actions.append(of.ofp_action_output(port=snort_port))
                    elif not snort_port:
                        log.warning("Snort port unknown; mirroring skipped")
                    
                    self.connection.send(msg)
                    return
                    
        except Exception as e:
            log.error("Error in PacketIn: %s", str(e), exc_info=True)
        
        # Fallback to LearningSwitch default behavior
        return LearningSwitch._handle_PacketIn(self, event)
    
    def handleConnectionDown(self, event):
        log.warning("Switch disconnected: %s", dpid_to_str(event.dpid))

class snort_monitor(object):
    def __init__(self, transparent=False):
        core.openflow.addListeners(self)
        self.transparent = transparent
        self.switches = {}  # Store switch instances
        log.info("[snort_monitor] Controller initialized with blocking capability")
    
    def _handle_ConnectionUp(self, event):
        log.info("Switch %s has connected", dpid_to_str(event.dpid))
        switch = SnortMonitor(event.connection, self.transparent)
        self.switches[event.dpid] = switch
    
    def _handle_ConnectionDown(self, event):
        if event.dpid in self.switches:
            del self.switches[event.dpid]
        log.info("Switch %s has disconnected", dpid_to_str(event.dpid))
    
    def block_ip_on_all_switches(self, ip_to_block):
        """Block IP on all connected switches"""
        success_count = 0
        for dpid, switch in self.switches.items():
            if switch.block_ip(ip_to_block):
                success_count += 1
        
        log.info("[snort_monitor] Blocked IP %s on %d/%d switches", 
                ip_to_block, success_count, len(self.switches))
        return success_count > 0
    
    def unblock_ip_on_all_switches(self, ip_to_unblock):
        """Unblock IP on all connected switches"""
        success_count = 0
        for dpid, switch in self.switches.items():
            if switch.unblock_ip(ip_to_unblock):
                success_count += 1
        
        log.info("[snort_monitor] Unblocked IP %s on %d/%d switches", 
                ip_to_unblock, success_count, len(self.switches))
        return success_count > 0
    
    def get_blocked_ips(self):
        """Get list of all blocked IPs across switches"""
        all_blocked = set()
        for switch in self.switches.values():
            all_blocked.update(switch.blocked_ips)
        return list(all_blocked)

# Global controller instance for external access
controller_instance = None

def get_controller():
    """Get the controller instance for external scripts"""
    return controller_instance

def block_attacker_ip(ip):
    """External function to block an IP address"""
    if controller_instance:
        return controller_instance.block_ip_on_all_switches(ip)
    else:
        log.error("Controller not initialized")
        return False

def unblock_attacker_ip(ip):
    """External function to unblock an IP address"""
    if controller_instance:
        return controller_instance.unblock_ip_on_all_switches(ip)
    else:
        log.error("Controller not initialized")
        return False

def launch(transparent=False):
    global controller_instance
    
    import pox.openflow.discovery
    import pox.openflow.spanning_tree
    
    log.info("Launching Enhanced Snort Monitor with blocking capability...")
    
    # Launch required components
    pox.openflow.discovery.launch()
    pox.openflow.spanning_tree.launch()
    
    # Create and register controller
    controller_instance = snort_monitor('True' == str(transparent))
    core.registerNew(snort_monitor, 'True' == str(transparent))
    
    log.info("Enhanced Snort Monitor running with automatic blocking enabled.")
