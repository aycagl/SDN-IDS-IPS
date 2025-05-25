#!/usr/bin/env python3
"""
Improved Integrated Blocking System with Rule Management
Handles existing OpenFlow rules and persistent state management.
"""

import time
import re
import threading
import os
import sys
import json
from collections import defaultdict
from pathlib import Path

log_file = Path("/tmp/snort/log/alert.log")
blocked_log = Path("/tmp/snort/log/blocked_ips.log")
if log_file.exists():
    os.popen("rm /tmp/snort/log/alert.log")
if blocked_log.exists():
    os.popen("rm /tmp/snort/log/blocked_ips.log")

    
class ImprovedBlockingSystem:
    def __init__(self, alert_log_path="/tmp/snort/log/alert.log"):
        self.alert_log_path = alert_log_path
        self.exist_lines = []
        self.blocked_ips = set()
        self.alert_counts = defaultdict(int)
        self.last_position = 0
        self.running = False
        
        # Persistent state files
        self.state_file = "/tmp/snort/ips_state.json"
        self.blocked_log_file = "/tmp/snort/log/blocked_ips.log"
        
        # Configuration
        self.BLOCK_THRESHOLD = 3
        self.CHECK_INTERVAL = 0.01
        
        print(f"[IPS] Improved Blocking System initialized")
        print(f"[IPS] Monitoring: {alert_log_path}")
        
        # Initialize system
        self.initialize_system()
        
    def initialize_system(self):
        """Initialize system and clean up any existing rules"""
        print("[IPS] Initializing system...")
        
        # Clean up any existing blocking rules
        self.cleanup_existing_rules()
        
        # Load previous state if exists
        self.load_previous_state()
        
        # Reset alert log position to avoid reprocessing old alerts
        self.reset_log_position()
        
        print("[IPS] System initialization complete")
    
    def cleanup_existing_rules(self):
        """Remove any existing high-priority blocking rules"""
        try:
            print("[IPS] Cleaning up existing OpenFlow rules...")
            
            # Remove all high-priority rules (our blocking rules)
            os.system("ovs-ofctl del-flows s1 'priority=1000' 2>/dev/null")
            
            # Also try to remove any rules with our specific pattern
            os.system("ovs-ofctl del-flows s1 'nw_src=10.0.0.1' 2>/dev/null")
            
            print("[IPS] Existing rules cleaned up")
            
        except Exception as e:
            print(f"[IPS] Rule cleanup warning: {e}")
    
    def load_previous_state(self):
        """Load previous blocking state from file"""
        try:
            if os.path.exists(self.state_file):
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    
                # Note: We don't restore blocked_ips because we cleaned the rules
                # But we can restore alert counts if needed
                self.alert_counts = defaultdict(int, state.get('alert_counts', {}))
                
                print(f"[IPS] Previous state loaded: {len(self.alert_counts)} IPs have alert history")
            else:
                print("[IPS] No previous state found - starting fresh")
                
        except Exception as e:
            print(f"[IPS] Could not load previous state: {e}")
    
    def save_current_state(self):
        """Save current state to file"""
        try:
            state = {
                'blocked_ips': list(self.blocked_ips),
                'alert_counts': dict(self.alert_counts),
                'timestamp': time.time()
            }
            
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2)
                
        except Exception as e:
            print(f"[IPS] Could not save state: {e}")
    
    def reset_log_position(self):
        """Reset log position to current end to avoid processing old alerts"""
        try:
            if os.path.exists(self.alert_log_path):
                with open(self.alert_log_path, 'r') as f:
                    f.seek(0, 2)  # Seek to end
                    self.last_position = f.tell()
                print(f"[IPS] Log position reset - will monitor new alerts only")
            else:
                print(f"[IPS] Alert log not found yet - will start monitoring when created")
        except Exception as e:
            print(f"[IPS] Could not reset log position: {e}")
    
    def extract_attacker_ip(self, alert_line):
        """Extract attacker IP from Snort alert line"""
        ip_pattern = r'.* (?:(\w+\.\w+\.\w+\.\w+) -> (\w+\.\w+\.\w+\.\w+))'
        match = re.search(ip_pattern, alert_line)
        
        if match:
            src_ip = match.group(1)
            dst_ip = match.group(2)
            
            if src_ip == "10.0.0.1":  # h1 - attacker
                return src_ip
            elif src_ip not in ["10.0.0.2", "10.0.0.3"]:  # Not victim or IDS
                return src_ip
        
        return None
    
    def verify_rule_installed(self, ip_to_block):
        """Verify that the blocking rule was actually installed"""
        try:
            result = os.popen(f"ovs-ofctl dump-flows s1 | grep 'nw_src={ip_to_block}'").read()
            return len(result.strip()) > 0
        except:
            return False
    
    def create_blocking_rule(self, ip_to_block):
        """Create OpenFlow blocking rule with verification"""
        try:
            print(f"[IPS] Installing blocking rule for {ip_to_block}")
            
            # Method 1: Direct OVS command
            cmd = f"ovs-ofctl add-flow s1 'priority=1000,ip,nw_src={ip_to_block},actions=drop'"
            result = os.system(cmd)
            
            if result == 0:
                # Verify the rule was installed
                if self.verify_rule_installed(ip_to_block):
                    print(f"[IPS] Blocking rule verified for {ip_to_block}")
                    return True
                else:
                    print(f"[IPS] Rule installation verification failed for {ip_to_block}")
            
            # Method 2: Alternative command format
            cmd2 = f"ovs-ofctl add-flow s1 priority=1000,ip,nw_src={ip_to_block},actions=drop"
            result2 = os.system(cmd2)
            
            if result2 == 0 and self.verify_rule_installed(ip_to_block):
                print(f"[IPS] Blocking rule installed (method 2) for {ip_to_block}")
                return True
                
            return False
            
        except Exception as e:
            print(f"[IPS] Error installing blocking rule: {e}")
            return False
    
    def block_attacker(self, ip_to_block):
        """Block attacker with enhanced verification"""
        if ip_to_block in self.blocked_ips:
            print(f"[IPS] {ip_to_block} already blocked in current session")
            return True
        
        print(f"[IPS] INITIATING BLOCK FOR {ip_to_block}")
        
        # Install blocking rule
        if self.create_blocking_rule(ip_to_block):
            self.blocked_ips.add(ip_to_block)
            
            # Log the blocking action
            log_entry = f"{time.strftime('%Y-%m-%d %H:%M:%S')} - BLOCKED: {ip_to_block} (Alert count: {self.alert_counts[ip_to_block]})\n"
            
            os.makedirs(os.path.dirname(self.blocked_log_file), exist_ok=True)
            with open(self.blocked_log_file, 'a') as f:
                f.write(log_entry)
            
            # Save current state
            self.save_current_state()
            
            print(f"[IPS] {ip_to_block} SUCCESSFULLY BLOCKED")
            print(f"[IPS] Block logged to {self.blocked_log_file}")
            
            return True
        else:
            print(f"[IPS] FAILED TO BLOCK {ip_to_block}")
            return False
    
    def process_new_alerts(self):
        """Process new alerts from Snort log"""
        try:
            if not os.path.exists(self.alert_log_path):
                return
            
            unique_lines = []

            with open(self.alert_log_path, 'r') as f:
                new_lines = f.readlines()
                for line in new_lines:
                    if line not in self.exist_lines:
                        unique_lines.append(line)
                self.last_position = f.tell()
            
            for line in unique_lines:
                self.exist_lines.append(line)
                line = line.strip()
                if not line or line.startswith('='):
                    continue
                
                attacker_ip = self.extract_attacker_ip(line)
                
                if attacker_ip and attacker_ip not in self.blocked_ips:
                    self.alert_counts[attacker_ip] += 1
                    
                    print(f"[IPS] Alert #{self.alert_counts[attacker_ip]} from {attacker_ip}")
                    print(f"[IPS] Alert: {line[:80]}...")
                        
                    if self.alert_counts[attacker_ip] >= self.BLOCK_THRESHOLD:
                        print(f"[IPS] THRESHOLD REACHED for {attacker_ip} ({self.alert_counts[attacker_ip]} alerts)")
                        self.block_attacker(attacker_ip)
        
        except Exception as e:
            print(f"[IPS] Error processing alerts: {e}")
    
    def monitoring_loop(self):
        """Main monitoring loop"""
        print("[IPS]  Starting monitoring loop...")
        while self.running:
            self.process_new_alerts()
            time.sleep(self.CHECK_INTERVAL)
    
    def start(self):
        """Start the IPS system"""
        if self.running:
            print("[IPS] Already running!")
            return
        
        print("[IPS] Starting Improved Blocking System...")
        self.running = True
        
        self.monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
        print("[IPS] System active - monitoring for NEW attacks...")
        print(f"[IPS] Will block after {self.BLOCK_THRESHOLD} alerts from same IP")
    
    def stop(self):
        """Stop the IPS system"""
        print("[IPS] Stopping system...")
        self.running = False
        
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join(timeout=5)
        
        # Save final state
        self.save_current_state()
        print("[IPS] System stopped and state saved")
    
    def get_status(self):
        """Get current system status"""
        return {
            "running": self.running,
            "blocked_ips": list(self.blocked_ips),
            "alert_counts": dict(self.alert_counts),
            "total_alerts": sum(self.alert_counts.values())
        }
    
    def show_current_rules(self):
        """Show current OpenFlow rules"""
        print("[IPS]  Current OpenFlow Rules:")
        os.system("ovs-ofctl dump-flows s1")
    
    def manual_unblock(self, ip):
        """Manually unblock an IP"""
        try:
            cmd = f"ovs-ofctl del-flows s1 'nw_src={ip}'"
            result = os.system(cmd)
            
            if result == 0:
                self.blocked_ips.discard(ip)
                print(f"[IPS] {ip} unblocked")
                return True
            else:
                print(f"[IPS] Failed to unblock {ip}")
                return False
                
        except Exception as e:
            print(f"[IPS] Error unblocking {ip}: {e}")
            return False

def main():
    """Main execution function"""
    print("=" * 70)
    print("  IMPROVED INTRUSION PREVENTION SYSTEM (IPS)")
    print("=" * 70)
    print(" Features:")
    print("   • Automatic cleanup of old blocking rules")
    print("   • State persistence across restarts")
    print("   • Enhanced rule verification")
    print("   • Monitors only NEW alerts (not old ones)")
    print("=" * 70)
    print("Press Ctrl+C to stop the system")
    print("=" * 70)
    
    ips = ImprovedBlockingSystem()
    
    try:
        ips.start()
        
        # Status reporting loop
        while True:
            time.sleep(15)  # Report every 15 seconds
            status = ips.get_status()
            
            if status["blocked_ips"] or status["alert_counts"]:
                print(f"\n[IPS] STATUS UPDATE:")
                if status["blocked_ips"]:
                    print(f"   Blocked IPs: {status['blocked_ips']}")
                if status["alert_counts"]:
                    print(f"   Alert counts: {status['alert_counts']}")
                print(f"   Total alerts processed: {status['total_alerts']}")
            else:
                print(f"[IPS] Monitoring... (no alerts yet)")
    
    except KeyboardInterrupt:
        print(f"\n[IPS] Shutdown signal received...")
        os.popen("ovs-ofctl del-flows s1")
        ips.stop()
        print(f"[IPS] System safely shut down")
    
    except Exception as e:
        print(f"[IPS] Unexpected error: {e}")
        ips.stop()

if __name__ == "__main__":
