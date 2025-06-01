import subprocess
import threading
import time
import re
from datetime import datetime, timezone
from database import SessionLocal
from models import Log, Setting
from models.logs import ActionType


class FirewallLogMonitor:
    """Service for monitoring firewall logs from kernel and recording to database"""
    
    def __init__(self):
        self.is_running = False
        self.monitor_thread = None
        self.stop_event = threading.Event()
        
    def start_monitoring(self):
        """Start the firewall log monitoring thread"""
        if self.is_running:
            return
            
        self.is_running = True
        self.stop_event.clear()
        self.monitor_thread = threading.Thread(target=self._monitor_logs, daemon=True)
        self.monitor_thread.start()
        
        # Log that monitoring started
        db = SessionLocal()
        Log.create_rule_log(db, ActionType.update, None, "Firewall log monitoring started", mode="manual")
        Log.cleanup_old_logs(db)
        db.close()
    
    def stop_monitoring(self):
        """Stop the firewall log monitoring thread"""
        if not self.is_running:
            return
            
        self.stop_event.set()
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.is_running = False
        
        # Log that monitoring stopped
        db = SessionLocal()
        Log.create_rule_log(db, ActionType.update, None, "Firewall log monitoring stopped", mode="manual")
        Log.cleanup_old_logs(db)
        db.close()
    
    def _monitor_logs(self):
        """Monitor kernel logs for DNSniper firewall activity"""
        try:
            # Use journalctl to follow kernel logs for DNSniper entries
            cmd = [
                "sudo", "journalctl", "-f", "-k", "--no-pager",
                "-g", "DNSniper"  # Filter for DNSniper entries
            ]
            
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True,
                universal_newlines=True
            )
            
            while not self.stop_event.is_set():
                try:
                    # Check if process is still alive
                    if process.poll() is not None:
                        break
                    
                    # Read line with timeout
                    line = process.stdout.readline()
                    if line:
                        self._process_log_line(line.strip())
                    else:
                        # Small sleep to prevent busy waiting
                        time.sleep(0.1)
                        
                except Exception as e:
                    db = SessionLocal()
                    Log.create_error_log(db, f"Error reading firewall logs: {e}", context="FirewallLogMonitor._monitor_logs", mode="manual")
                    Log.cleanup_old_logs(db)
                    db.close()
                    time.sleep(1)  # Wait before retrying
            
        except Exception as e:
            db = SessionLocal()
            Log.create_error_log(db, f"Failed to start firewall log monitoring: {e}", context="FirewallLogMonitor._monitor_logs", mode="manual")
            Log.cleanup_old_logs(db)
            db.close()
        finally:
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
    
    def _process_log_line(self, line: str):
        """Process a single log line from kernel"""
        try:
            # Check if firewall logging is enabled
            db = SessionLocal()
            logging_enabled = Setting.get_setting(db, "logging_enabled", False)
            
            if not logging_enabled:
                db.close()
                return
            
            # Parse DNSniper firewall log entries
            # Expected format: ... kernel: DNSniper DROP_SRC: IN=... SRC=X.X.X.X DST=Y.Y.Y.Y ...
            # or: ... kernel: DNSniper6 DROP_SRC: IN=... SRC=... DST=... ...
            
            if "DNSniper" in line and ("DROP_SRC" in line or "DROP_DST" in line):
                # Extract information from the log line
                timestamp = datetime.now(timezone.utc)
                
                # Determine action type and direction
                if "DROP_SRC" in line:
                    action = ActionType.block
                    direction = "SRC"
                elif "DROP_DST" in line:
                    action = ActionType.block
                    direction = "DST"
                else:
                    db.close()
                    return
                
                # Extract source and destination IPs
                src_match = re.search(r'SRC=([^\s]+)', line)
                dst_match = re.search(r'DST=([^\s]+)', line)
                
                src_ip = src_match.group(1) if src_match else "unknown"
                dst_ip = dst_match.group(1) if dst_match else "unknown"
                
                # Determine which IP was blocked
                blocked_ip = src_ip if direction == "SRC" else dst_ip
                
                # Create firewall log entry
                message = f"Firewall {action.value}: {direction}={blocked_ip} (SRC={src_ip} → DST={dst_ip})"
                Log.create_firewall_log(db, action, message, ip_address=blocked_ip, mode="manual")
                Log.cleanup_old_logs(db)
            
            db.close()
            
        except Exception as e:
            db = SessionLocal()
            Log.create_error_log(db, f"Error processing firewall log line: {e}", context="FirewallLogMonitor._process_log_line", mode="manual")
            Log.cleanup_old_logs(db)
            db.close()

    def restart_if_needed(self):
        """Restart monitoring based on current logging settings"""
        db = SessionLocal()
        try:
            logging_enabled = Setting.get_setting(db, "logging_enabled", False)
            
            if logging_enabled and not self.is_running:
                # Start monitoring if logging is enabled but not running
                self.start_monitoring()
                Log.create_rule_log(db, ActionType.update, None, "Firewall log monitoring started due to settings change", mode="manual")
                Log.cleanup_old_logs(db)
            elif not logging_enabled and self.is_running:
                # Stop monitoring if logging is disabled but still running
                self.stop_monitoring()
                Log.create_rule_log(db, ActionType.update, None, "Firewall log monitoring stopped due to settings change", mode="manual")
                Log.cleanup_old_logs(db)
        finally:
            db.close()


# Global instance
firewall_log_monitor = FirewallLogMonitor() 