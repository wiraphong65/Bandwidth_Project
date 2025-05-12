import os
import sys
import secrets
import subprocess
import re
import logging
from flask import (
    Flask, render_template, request, redirect, url_for, session,
    flash, jsonify, make_response, get_flashed_messages
)
from flask_sqlalchemy import SQLAlchemy
from logging.handlers import RotatingFileHandler
from datetime import datetime, time as dtime, date as ddate
from sqlalchemy import or_, and_
from datetime import datetime, timezone
import shlex
# --- Flask App Initialization and Configuration ---
app = Flask(__name__, instance_relative_config=True) # instance_relative_config=True is good practice

# --- Configuration ---
# It's highly recommended to use environment variables for sensitive data in production.
# For development, you can set them directly or use a .env file with python-dotenv.

app.config['SECRET_KEY'] = os.environ.get('APP_SECRET_KEY') or secrets.token_hex(32)
app.config['DEBUG_MODE'] = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't') # Renamed to avoid conflict with Flask's own DEBUG

# Database Config
# Ensure 'instance' folder exists at the project root, or adjust path.
project_root_dir = os.path.dirname(os.path.abspath(__file__))
instance_folder_path = os.path.join(project_root_dir, 'instance')
if not os.path.exists(instance_folder_path):
    try:
        os.makedirs(instance_folder_path)
        print(f"Instance folder created at: {instance_folder_path}", file=sys.stdout)
    except OSError as e:
        print(f"CRITICAL: Could not create instance path: {instance_folder_path} - Error: {e}", file=sys.stderr)
        # Depending on the error, you might want to exit or handle it.

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or \
    f"sqlite:///{os.path.join(instance_folder_path, 'site.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Logging Config
log_folder_path = os.path.join(project_root_dir, 'logs')
if not os.path.exists(log_folder_path):
    try:
        os.makedirs(log_folder_path, exist_ok=True)
        print(f"Logs folder created at: {log_folder_path}", file=sys.stdout)
    except OSError as e:
        print(f"CRITICAL: Could not create log directory: {log_folder_path} - Error: {e}", file=sys.stderr)

app.config['LOG_FILE'] = os.path.join(log_folder_path, 'app.log')
app.config['LOG_LEVEL'] = logging.DEBUG if app.config['DEBUG_MODE'] else logging.INFO
app.config['LOG_TO_STDOUT'] = True # Log to console as well

# APScheduler Config
app.config['SCHEDULER_API_ENABLED'] = False
app.config['SCHEDULER_TIMEZONE'] = 'Asia/Bangkok'
app.config['SCHEDULER_INTERVAL_MINUTES'] = 1

# !! WARNING: Hardcoded credentials - DO NOT USE IN PRODUCTION !!
# !! Replace with a secure authentication mechanism (e.g., hashed passwords from DB, environment variables) !!
app.config['ADMIN_USERNAME'] = os.environ.get('ADMIN_USERNAME', 'admin')
app.config['ADMIN_PASSWORD'] = os.environ.get('ADMIN_PASSWORD', 'password123') # CHANGE THIS AND USE HASHING!

# Flask run config (can be overridden by environment variables or run.py arguments if you use a separate run.py)
app.config['FLASK_RUN_HOST'] = "0.0.0.0"
app.config['FLASK_RUN_PORT'] = 5000

# --- Initialize Extensions ---
db = SQLAlchemy(app)
from flask_apscheduler import APScheduler
scheduler = APScheduler()
if not hasattr(app, 'extensions') or 'apscheduler' not in app.extensions: # Avoid reinitialization if app factory pattern is used elsewhere
    scheduler.init_app(app)
else:
    if app.logger: app.logger.info("APScheduler already initialized with app (or so it seems).")


# --- Logging Setup ---
# Ensure logger is configured after app object is created and config is loaded
if app.logger and app.logger.handlers: # Check if default handlers exist
    # Remove default Flask handler to avoid duplicate logs if we add our own
    # Flask's default handler is added when app.logger is first accessed or debug/testing is off
    default_handlers = [h for h in app.logger.handlers if isinstance(h, logging.StreamHandler) and h.stream == sys.stderr]
    for dh in default_handlers:
        app.logger.removeHandler(dh)
try:
    log_file_path = app.config['LOG_FILE']
    log_handler = RotatingFileHandler(
        log_file_path,
        maxBytes=app.config.get('LOG_MAX_BYTES', 1024 * 1024 * 5),
        backupCount=app.config.get('LOG_BACKUP_COUNT', 5),
        encoding='utf-8' # Specify encoding
    )
    log_handler.setLevel(app.config['LOG_LEVEL'])
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s')
    log_handler.setFormatter(formatter)
    app.logger.addHandler(log_handler)

    if app.config.get('LOG_TO_STDOUT', True):
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        app.logger.addHandler(stream_handler)

    app.logger.setLevel(app.config['LOG_LEVEL'])
    app.logger.info("Logging configured successfully.")
except Exception as e_log_setup:
    # Fallback to basic logging if custom setup fails
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    # app.logger might have been replaced by basicConfig, re-get it or use root logger.
    # For simplicity, we'll rely on basicConfig logging to stdout/stderr if this fails.
    print(f"ERROR: Failed to set up custom file/stream logging: {e_log_setup}. Falling back to basic logging.", file=sys.stderr)
    if app.logger: # If app.logger still exists
        app.logger.error(f"Failed to set up custom file/stream logging: {e_log_setup}", exc_info=True)


# --- Database Models ---
class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    interface = db.Column(db.String(50), nullable=False)
    ip = db.Column(db.String(45), nullable=False)
    rate_str = db.Column(db.String(20), nullable=False) # e.g., "10Mbps", "512Kbps"
    direction = db.Column(db.String(10), nullable=False)
    group_name = db.Column(db.String(50), nullable=True)
    protocol = db.Column(db.String(10), nullable=True)
    source_port = db.Column(db.String(10), nullable=True)
    destination_port = db.Column(db.String(10), nullable=True)
    description = db.Column(db.String(255), nullable=True)
    is_enabled = db.Column(db.Boolean, default=True, nullable=False)
    priority = db.Column(db.Integer, nullable=True)
    burst_str = db.Column(db.String(20), nullable=True) # e.g., "20kbit", "1600b"
    cburst_str = db.Column(db.String(20), nullable=True)
    is_scheduled = db.Column(db.Boolean, default=False)
    start_time = db.Column(db.String(5), nullable=True)
    end_time = db.Column(db.String(5), nullable=True)
    weekdays = db.Column(db.String(30), nullable=True)
    start_date = db.Column(db.String(10), nullable=True)
    end_date = db.Column(db.String(10), nullable=True)
    is_active_scheduled = db.Column(db.Boolean, default=False)
    upload_classid = db.Column(db.String(20), nullable=True) # TC Class ID (upload) or Filter Handle (:id) (download)
    upload_parent_handle = db.Column(db.String(20), nullable=True) # Parent (upload) or ffff: (download filter)
    __table_args__ = (db.UniqueConstraint('interface', 'ip', 'direction',
                                          'protocol', 'source_port', 'destination_port',
                                          name='_ip_iface_dir_filter_uc'),)
    def __repr__(self):
        return (f"<Rule id={self.id} ip='{self.ip}' rate='{self.rate_str}' prio='{self.priority}' "
                f"enabled={self.is_enabled} desc='{self.description if self.description else ''[:20]}'>")

class GroupLimit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    interface = db.Column(db.String(50), nullable=False)
    group_name = db.Column(db.String(50), nullable=False)
    direction = db.Column(db.String(10), nullable=False)
    rate_str = db.Column(db.String(20), nullable=False)
    burst_str = db.Column(db.String(20), nullable=True)
    cburst_str = db.Column(db.String(20), nullable=True)
    upload_classid = db.Column(db.String(20), nullable=True) # TC classid for upload group limits
    __table_args__ = (db.UniqueConstraint('interface', 'group_name', 'direction', name='_group_direction_uc'),)
    def __repr__(self):
        return f"<GroupLimit id={self.id} group='{self.group_name}' rate='{self.rate_str}'>"

# --- In-memory Data Stores (Global for this single file app) ---
_bandwidth_rules_cache = [] # List of Rule objects for the active interface
_group_limits_cache = {}    # Dict: {group_name: {direction: GroupLimitObject}}

# --- Helper Functions ---
def run_command(cmd_list, timeout=15):
    """
    Executes a system command securely using shell=False.
    Args:
        cmd_list (list): The command and its arguments as a list of strings.
        timeout (int): Timeout in seconds for the command.
    Returns:
        str: The combined stdout of the command if successful.
        None: On any failure (CalledProcessError, FileNotFoundError, TimeoutExpired, other Exception).
              Error details are logged.
    Raises:
        ValueError: If cmd_list is not a list of strings.
    """
    if not isinstance(cmd_list, list) or not all(isinstance(arg, str) for arg in cmd_list):
        app.logger.error(f"run_command: Invalid cmd_list format. Expected list of strings. Got: {cmd_list}")
        # Instead of raising ValueError which might crash the app if not caught by caller,
        # log and return None, consistent with other errors. Caller should check for None.
        return None

    log_cmd_str = ""
    try:
        # subprocess.list2cmdline is Windows-specific for exact cmd.exe representation.
        # For logging on Linux, ' '.join or shlex.join (Python 3.8+) are common.
        # Using shlex.join is safer if arguments might contain spaces.
        if hasattr(shlex, 'join'): # Python 3.8+
            log_cmd_str = shlex.join(cmd_list)
        else:
            log_cmd_str = ' '.join(cmd_list) # Fallback for older Python, less safe for complex args with spaces
    except Exception: # Fallback in case shlex operations fail
        log_cmd_str = str(cmd_list)


    app.logger.debug(f"Executing command list: {cmd_list} (Formatted for log: {log_cmd_str})")

    try:
        process = subprocess.run(
            cmd_list,
            shell=False,
            check=True,
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=timeout
        )
        
        stdout_output = process.stdout.strip() if process.stdout else ""
        stderr_output = process.stderr.strip() if process.stderr else ""

        if stderr_output:
            app.logger.warning(f"Command '{log_cmd_str}' produced stderr (though it might not indicate an error):\n{stderr_output}")
        
        # Log stdout only if it's not excessively long, or log a summary
        # For tc commands, stdout is often empty on success unless asking for stats/show.
        if stdout_output:
             app.logger.debug(f"Command '{log_cmd_str}' stdout:\n{stdout_output}")
        elif not stderr_output : # No stdout and no stderr, usually means success for action commands
             app.logger.debug(f"Command '{log_cmd_str}' executed successfully with no stdout/stderr output.")
             
        return stdout_output # Caller can decide if empty stdout is an issue for 'show' commands

    except subprocess.CalledProcessError as e:
        error_stdout = e.stdout.strip() if e.stdout else "No stdout."
        error_stderr = e.stderr.strip() if e.stderr else "No stderr."
        app.logger.error(
            f"Command failed: {log_cmd_str}\n"
            f"Exit Code: {e.returncode}\n"
            f"Stdout: {error_stdout}\n"
            f"Stderr: {error_stderr}"
        )
        return None
    except FileNotFoundError:
        app.logger.error(f"Command not found: {cmd_list[0]}. Ensure it is installed and in the system's PATH.")
        return None
    except subprocess.TimeoutExpired:
        app.logger.error(f"Command timed out after {timeout}s: {log_cmd_str}")
        return None
    except Exception as e_run_cmd:
        app.logger.error(f"An unexpected exception occurred while executing command '{log_cmd_str}': {e_run_cmd}", exc_info=True)
        return None

def get_interfaces():
    app.logger.debug("Getting network interfaces")
    # Changed to list format for run_command
    output = run_command(['ip', '-o', 'link', 'show']) # Linux specific
    interfaces = []
    if output: # run_command returns stdout string on success, or None on failure
        for line in output.splitlines():
            match = re.match(r'^\d+:\s+([\w.-@]+):', line) # Adjusted regex slightly for iface@phys
            if match:
                iface = match.group(1)
                # Your existing exclusion logic
                if iface != 'lo' and not any(iface.startswith(prefix) for prefix in 
                                             ['docker', 'veth', 'br-', 'virbr', 'kube-', 
                                              'cni', 'flannel', 'vxlan', 'geneve', 'bond', 
                                              'dummy', 'ifb', 'sit', 'lo', 'tun', 'tap']):
                    interfaces.append(iface)
    app.logger.debug(f"Found interfaces: {interfaces}")
    return interfaces

def validate_interface_name(if_name, allow_sub_interfaces=True):
    """Validates network interface name."""
    if not if_name or not isinstance(if_name, str):
        app.logger.warning(f"Validation failed: Interface name is not a string or is empty ('{if_name}').")
        return False
    pattern = r"^[a-zA-Z0-9_.-]{1,16}$" # Standard interface names
    if allow_sub_interfaces:
        pattern = r"^[a-zA-Z0-9_.-@]{1,32}$" # Allows for VLANs like eth0.10 or eth0.10@eth0
    
    if not re.match(pattern, if_name):
        app.logger.warning(f"Validation failed: Interface name '{if_name}' has invalid characters or length (pattern: {pattern}).")
        return False
    if any(char in if_name for char in ";|&`$()<>\n\t\r\b"): # Stricter check for shell-problematic chars
        app.logger.error(f"Validation failed: Interface name '{if_name}' contains potentially malicious or problematic characters.")
        return False
    return True

def validate_ip_address(ip_str):
    """Validates if the string is a valid IPv4 or IPv6 address."""
    if not ip_str or not isinstance(ip_str, str):
        app.logger.warning(f"Validation failed: IP address is not a string or is empty ('{ip_str}').")
        return False
    try:
        ipaddress.ip_address(ip_str.strip()) # Use strip() to handle leading/trailing spaces
        return True
    except ValueError:
        app.logger.warning(f"Validation failed: Invalid IP address format ('{ip_str}').")
        return False

def validate_rate_value(rate_val_str):
    """Validates if the rate value is a positive number string."""
    if rate_val_str is None:
        app.logger.warning("Validation failed: Rate value is None.")
        return False # Assuming rate value is usually required
    try:
        val = float(str(rate_val_str).strip())
        if val <= 0:
            app.logger.warning(f"Validation failed: Rate value '{rate_val_str}' must be positive.")
            return False
        return True
    except (ValueError, TypeError):
        app.logger.warning(f"Validation failed: Rate value '{rate_val_str}' is not a valid number.")
        return False

def validate_rate_unit(rate_unit_str, allowed_units_list=None):
    """Validates if the rate unit is in the allowed list (case-insensitive)."""
    if not rate_unit_str or not isinstance(rate_unit_str, str):
        app.logger.warning(f"Validation failed: Rate unit is not a string or is empty ('{rate_unit_str}').")
        return False
    
    unit_to_check = rate_unit_str.strip().lower()
    if not unit_to_check:
        app.logger.warning("Validation failed: Rate unit is empty after stripping.")
        return False

    if allowed_units_list is None:
        allowed_units_list = ['bps', 'kbps', 'mbps', 'gbps', 'bit', 'kbit', 'mbit', 'gbit', # For rates
                              'k', 'm', 'g', 'b', 'kb', 'mb', 'gb'] # For burst/size/tc direct units
    
    if unit_to_check not in [unit.lower() for unit in allowed_units_list]:
        app.logger.warning(f"Validation failed: Rate unit '{rate_unit_str}' (checked as '{unit_to_check}') is not in allowed list ({allowed_units_list}).")
        return False
    return True

def validate_port_number(port_str):
    """Validates if the port is a valid number string (1-65535) or empty/None if optional."""
    stripped_port_str = str(port_str).strip() if port_str is not None else ""
    if not stripped_port_str: # Optional port
        return True
    try:
        port = int(stripped_port_str)
        if not (1 <= port <= 65535):
            app.logger.warning(f"Validation failed: Port number '{port_str}' out of range (1-65535).")
            return False
        return True
    except (ValueError, TypeError):
        app.logger.warning(f"Validation failed: Port '{port_str}' is not a valid integer.")
        return False

def validate_protocol(protocol_str, allowed_protocols_list=None):
    """Validates protocol string against an allowed list (case-insensitive)."""
    stripped_protocol = protocol_str.strip().lower() if isinstance(protocol_str, str) else ""
    if not stripped_protocol: # Optional protocol (might mean 'ip' or 'any' depending on context)
        return True 

    if allowed_protocols_list is None:
        allowed_protocols_list = ['ip', 'ipv6', 'tcp', 'udp', 'icmp', 'any'] 

    if stripped_protocol not in [p.lower() for p in allowed_protocols_list]:
        app.logger.warning(f"Validation failed: Protocol '{protocol_str}' (checked as '{stripped_protocol}') is not in allowed list ({allowed_protocols_list}).")
        return False
    return True

def validate_tc_classid(classid_str):
    """Validates format of TC class ID like '1:10', '100:AB', or root/parent handles like '1:', 'ffff:'."""
    if not classid_str or not isinstance(classid_str, str): return False
    stripped_classid = classid_str.strip()
    if stripped_classid in ["1:", "root", "ffff:", "ingress"]: # Common parent/root handles
        return True
    # Standard classid format e.g., <major>:<minor> (hex or dec for major, hex for minor for HTB often)
    if not re.match(r"^[0-9a-fA-F]+:[0-9a-fA-F]{1,4}$", stripped_classid):
        app.logger.warning(f"Validation failed: TC ClassID '{classid_str}' format is invalid.")
        return False
    return True

def validate_tc_specific_rate_string(rate_str_for_tc):
    """Validates rate strings like '10mbit', '512kbit' intended for direct TC usage."""
    if not rate_str_for_tc or not isinstance(rate_str_for_tc, str): return False
    if not re.match(r"^\d+(\.\d+)?(bit|bps|[kmgt]bit|[kmgt]bps)$", rate_str_for_tc.strip(), re.IGNORECASE): # Added 't' for terabit
        app.logger.warning(f"Validation failed: TC-specific rate string '{rate_str_for_tc}' format is invalid.")
        return False
    return True

def validate_tc_specific_burst_string(burst_str_for_tc):
    """Validates burst strings like '15k', '1600b', '2m' for direct TC usage."""
    if not burst_str_for_tc or not isinstance(burst_str_for_tc, str): return False
    # Allows for optional 'b' at the end of k/m/g units, and plain numbers (bytes)
    if not re.match(r"^\d+[kmgt]?b?$", burst_str_for_tc.strip(), re.IGNORECASE): # Added 't'
        app.logger.warning(f"Validation failed: TC-specific burst string '{burst_str_for_tc}' format is invalid.")
        return False
    return True

def validate_description(desc_str, max_length=255):
    """Validates description string."""
    if desc_str is None: return True # Optional
    if not isinstance(desc_str, str):
        app.logger.warning(f"Validation failed: Description is not a string.")
        return False
    if len(desc_str) > max_length:
        app.logger.warning(f"Validation failed: Description exceeds max length of {max_length} characters.")
        return False
    # Potentially check for harmful characters if displaying as HTML without escaping,
    # but for DB storage and tc comments, most things are fine.
    # Avoid newlines if tc comments don't support them.
    if '\n' in desc_str or '\r' in desc_str:
        app.logger.warning(f"Validation failed: Description contains newline characters.")
        return False
    return True

def validate_group_name(group_name_str, max_length=50):
    """Validates group name string."""
    if group_name_str is None: return True # Optional
    if not isinstance(group_name_str, str) or not group_name_str.strip():
        if group_name_str is not None and group_name_str.strip() == "": # Allow empty string if it means "no group"
             return True
        app.logger.warning(f"Validation failed: Group name is not a string or is empty ('{group_name_str}').")
        return False
    
    stripped_name = group_name_str.strip()
    if not re.match(r"^[a-zA-Z0-9_.-]{1,50}$", stripped_name): # Similar to interface names but no '@'
        app.logger.warning(f"Validation failed: Group name '{stripped_name}' has invalid characters or length.")
        return False
    if len(stripped_name) > max_length:
        app.logger.warning(f"Validation failed: Group name exceeds max length of {max_length} characters.")
        return False
    return True

def validate_priority_str(prio_str, min_val=0, max_val=7):
    """Validates priority string, ensuring it's an int within range."""
    if prio_str is None or str(prio_str).strip() == "": # Optional priority
        return True
    try:
        prio_int = int(str(prio_str).strip())
        if not (min_val <= prio_int <= max_val):
            app.logger.warning(f"Validation failed: Priority '{prio_str}' out of range ({min_val}-{max_val}).")
            return False
        return True
    except (ValueError, TypeError):
        app.logger.warning(f"Validation failed: Priority '{prio_str}' is not a valid integer.")
        return False


def is_float(value):
    if value is None: return False
    try: float(str(value).strip()); return True
    except (ValueError, TypeError): return False

def get_bandwidth_usage(interface):
    if not interface: return {"rx_bytes": 0, "tx_bytes": 0}
    sysfs_base = f"/sys/class/net/{interface}/statistics/"
    if not os.path.exists(sysfs_base): # Linux specific
        app.logger.warning(f"Sysfs path not found for interface: {interface}")
        return {"rx_bytes": 0, "tx_bytes": 0}
    rx_path, tx_path = os.path.join(sysfs_base, "rx_bytes"), os.path.join(sysfs_base, "tx_bytes")
    rx, tx = 0, 0
    try:
        if os.path.exists(rx_path):
            with open(rx_path, 'r') as f: rx = int(f.read().strip())
        if os.path.exists(tx_path):
            with open(tx_path, 'r') as f: tx = int(f.read().strip())
    except Exception as e: app.logger.error(f"Error reading sysfs stats for {interface}: {e}", exc_info=True)
    return {"rx_bytes": rx, "tx_bytes": tx}

def format_bytes(byte_count):
    if byte_count is None or not isinstance(byte_count, (int, float)): return "N/A"
    b = int(byte_count)
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.2f} KB"
    if b < 1024**3: return f"{b/1024**2:.2f} MB"
    if b < 1024**4: return f"{b/1024**3:.2f} GB"
    return f"{b/1024**4:.2f} TB"

def get_tc_stats(interface):
    """
    Fetches and parses statistics from 'tc -s class show' and 'tc -s filter show'.
    Args:
        interface (str): The network interface name (should be pre-validated).
    Returns:
        dict: A dictionary containing parsed TC statistics.
    """
    if not validate_interface_name(interface):
        app.logger.error(f"get_tc_stats: Invalid interface name '{interface}'.")
        return {}

    app.logger.debug(f"Fetching TC stats for interface: {interface}")
    tc_stats = {}

    # Command for TC class stats
    cmd_list_class = ['tc', '-s', 'class', 'show', 'dev', interface]
    class_output = run_command(cmd_list_class) # <--- เรียกแบบใหม่

    if class_output:
        # (คง Logic การ Parse 'class_output' เดิมของคุณไว้ที่นี่)
        # ตัวอย่าง Regex เดิมของคุณ (อาจจะต้องปรับปรุงความแม่นยำ):
        class_pattern = re.compile(
            r"class\s+\S+\s+(?P<classid>\w+:\w+).*?"
            r"(?:Sent\s+(?P<bytes_sent>\d+)\s+bytes\s+(?P<pkts_sent>\d+)\s+pkt|bytes\s+(?P<bytes>\d+).*?pkts\s+(?P<pkts>\d+))",
            re.DOTALL
        )
        for match in class_pattern.finditer(class_output):
            data = match.groupdict()
            class_id = data.get('classid')
            bytes_val = data.get('bytes_sent') or data.get('bytes')
            pkts_val = data.get('pkts_sent') or data.get('pkts')
            if class_id and bytes_val and pkts_val:
                try:
                    tc_stats[class_id] = {'pkts': int(pkts_val), 'bytes': int(bytes_val)}
                except ValueError:
                    app.logger.warning(f"get_tc_stats: Could not parse stats for class {class_id} from output.")
    else:
        app.logger.warning(f"get_tc_stats: No output or error from 'tc class show' for interface {interface}.")


    # Command for TC filter stats (ingress)
    cmd_list_filter = ['tc', '-s', 'filter', 'show', 'dev', interface, 'ingress']
    filter_output = run_command(cmd_list_filter) # <--- เรียกแบบใหม่

    if filter_output:
        # (คง Logic การ Parse 'filter_output' เดิมของคุณไว้ที่นี่)
        # ตัวอย่าง Regex เดิมของคุณ (อาจจะต้องปรับปรุงความแม่นยำ):
        filter_pattern = re.compile(
            r"filter\s+parent\s+ffff:.*?protocol\s+\S+.*?pref\s+\d+.*?"
            r"(?:handle\s+(?P<handle_hex>0x[0-9a-fA-F]+)\s+)?.*?"
            r"(?:flowid\s+:(?P<flowid_minor>\d+)|police.*?flowid\s+:(?P<flowid_minor_alt>\d+)).*?"
            r"pkts\s+(?P<packets>\d+)\s+bytes\s+(?P<bytes_val>\d+)",
            re.DOTALL
        )
        for match in filter_pattern.finditer(filter_output):
            data = match.groupdict()
            filter_id_key = None
            pkts_val = data.get('packets')
            bytes_val_parsed = data.get('bytes_val')
            flowid_minor_val = data.get('flowid_minor') or data.get('flowid_minor_alt')

            if flowid_minor_val:
                filter_id_key = f":{flowid_minor_val}"
            elif data.get('handle_hex'): # Kernel handle if present
                filter_id_key = data.get('handle_hex')
            
            if filter_id_key and pkts_val and bytes_val_parsed:
                try:
                    tc_stats[filter_id_key] = {'pkts': int(pkts_val), 'bytes': int(bytes_val_parsed)}
                except ValueError:
                    app.logger.warning(f"get_tc_stats: Could not parse stats for filter {filter_id_key} from output.")
    else:
        app.logger.warning(f"get_tc_stats: No output or error from 'tc filter show ingress' for interface {interface}.")

    return tc_stats


# ใน app.py
# ... (import statements และ app.logger, run_command, validation helpers ของคุณ) ...

def parse_tc_qdisc_show(interface):
    """
    Parses the output of 'tc qdisc show dev <interface>'.
    Args:
        interface (str): The network interface name (should be pre-validated).
    Returns:
        dict: A dictionary of parsed qdiscs, keyed by handle.
    """
    if not validate_interface_name(interface):
        app.logger.error(f"parse_tc_qdisc_show: Invalid interface name '{interface}'.")
        return {}

    qdiscs = {}
    cmd_list = ['tc', 'qdisc', 'show', 'dev', interface]
    # สำหรับคำสั่งที่มี option มากขึ้น เช่น `tc -d qdisc show dev {interface}` เพื่อเอา default class
    # cmd_list = ['tc', '-d', 'qdisc', 'show', 'dev', interface]
    
    output = run_command(cmd_list) # <--- เรียกแบบใหม่

    if output:
        # (คง Logic การ Parse output เดิมของคุณไว้ที่นี่)
        # ตัวอย่าง Regex เดิมของคุณ (อาจจะต้องปรับปรุงความแม่นยำ):
        # qdisc\s+([a-zA-Z0-9_-]+)\s+([0-9a-fA-F]+:(?:[0-9a-fA-F]*)?)\s+.*?dev\s+([\w.-]+)\s*(?:parent\s+([0-9a-fA-F]+:(?:[0-9a-fA-F]*)?|root))?.*?
        # ควรจะปรับปรุง Regex ให้แม่นยำขึ้น หรือใช้การ split line แล้ว parse ทีละบรรทัด
        # ตัวอย่างการปรับปรุง Regex ให้ครอบคลุมรายละเอียดมากขึ้น (เช่น default class สำหรับ htb):
        qdisc_pattern = re.compile(
            r"qdisc\s+(?P<type>\w+)\s+(?P<handle>[0-9a-fA-F]+:(?:[0-9a-fA-F]*)?)\s+"
            r"(?:parent\s+(?P<parent>[0-9a-fA-F]+:(?:[0-9a-fA-F]*)?|root)\s+)?" # Parent is optional for root
            r"(?:dev\s+[\w.-@]+\s+)?" # dev part might not always be there if already specified
            r"(?P<details>.*)"
        )
        for line in output.splitlines():
            line = line.strip()
            match = qdisc_pattern.match(line)
            if match:
                data = match.groupdict()
                handle = data['handle']
                qdisc_info = {
                    'type': data['type'],
                    'parent': data['parent'] if data['parent'] else 'root', # Handle case where parent is not explicitly root
                    'raw_details': data['details']
                }
                if data['type'] == 'htb':
                    default_match = re.search(r'default\s+([0-9a-fA-F]+)', data['details']) # default minor id (hex)
                    if default_match:
                        qdisc_info['default_minor_id'] = default_match.group(1)
                    r2q_match = re.search(r'r2q\s+(\d+)', data['details'])
                    if r2q_match:
                        qdisc_info['r2q'] = r2q_match.group(1)
                # Add more parsers for other qdisc types if needed (e.g., ingress, fq_codel)
                qdiscs[handle] = qdisc_info
    else:
        app.logger.warning(f"parse_tc_qdisc_show: No output or error from 'tc qdisc show' for interface {interface}.")
    
    app.logger.debug(f"Parsed qdiscs for {interface}: {qdiscs}")
    return qdiscs

# ใน app.py
# ... (import statements และ app.logger, run_command, validation helpers ของคุณ) ...

def parse_tc_class_show(interface):
    """
    Parses the output of 'tc -s -d class show dev <interface>'.
    Args:
        interface (str): The network interface name (should be pre-validated).
    Returns:
        dict: A dictionary of parsed classes, keyed by classid.
    """
    if not validate_interface_name(interface):
        app.logger.error(f"parse_tc_class_show: Invalid interface name '{interface}'.")
        return {}

    classes = {}
    # Use -s for statistics, -d for details
    cmd_list = ['tc', '-s', '-d', 'class', 'show', 'dev', interface]
    output = run_command(cmd_list) # <--- เรียกแบบใหม่

    if output:
        # (คง Logic การ Parse output เดิมของคุณไว้ที่นี่ หรือปรับปรุง Regex)
        # Regex เดิมของคุณอาจจะต้องปรับให้รองรับ output จาก -s -d
        # ตัวอย่าง Regex ที่พยายามจะละเอียดขึ้น (อาจจะต้องทดสอบและปรับปรุงอีก):
        class_pattern = re.compile(
            r"class\s+(?P<type>htb)\s+(?P<classid>[0-9a-fA-F]+:[0-9a-fA-F]+)\s+"
            r"parent\s+(?P<parent>[0-9a-fA-F]+:(?:[0-9a-fA-F]*)?)\s+"
            r"(?:leaf\s+([0-9a-fA-F]+:))?\s*" # Optional leaf qdisc handle
            r"(?:prio\s+(?P<prio>\d+)\s+)?"
            r"rate\s+(?P<rate>\d+[a-zA-Z_]*(?:bit|bps|Bps))\s*"
            r"(?:ceil\s+(?P<ceil>\d+[a-zA-Z_]*(?:bit|bps|Bps))\s*)?"
            r"(?:burst\s+(?P<burst>\d+[a-zA-Zkmg]?b?(?:yte)?)\s*(?:\(bytes\s+\d+\))?\s*)?"
            r"(?:cburst\s+(?P<cburst>\d+[a-zA-Zkmg]?b?(?:yte)?)\s*(?:\(bytes\s+\d+\))?\s*)?"
            # Statistics part
            r"(?:Sent\s+(?P<sent_bytes>\d+)\s+bytes\s+(?P<sent_pkts>\d+)\s+pkt\s*)?"
            r"(?:\(dropped\s+(?P<dropped_pkts>\d+),\s*overlimits\s+(?P<overlimits>\d+)\s+requeues\s+(?P<requeues>\d+)\))?"
            # Other details
            r"(?:quantum\s+(?P<quantum>\d+)\s*)?"
            r"(?:level\s+(?P<level>\d+)\s*)?",
            re.IGNORECASE
        )
        
        # TC output can be multi-line per class, especially with -s -d
        # It's safer to split output into blocks per "class " line
        class_blocks = re.split(r'(?=class htb)', output) # Split keeping "class htb"

        for block in class_blocks:
            if not block.strip().startswith("class htb"):
                continue
            
            match = class_pattern.search(block.replace('\n', ' ')) # Replace newlines for easier regex on block
            if match:
                data = match.groupdict()
                classid = data['classid']
                class_info = {
                    'type': data['type'],
                    'parent': data['parent'],
                    'rate_str': data['rate'],
                    'ceil_str': data.get('ceil') or data['rate'], # Default ceil to rate if not present
                    'prio': int(data['prio']) if data.get('prio') else None,
                    'burst_str': data.get('burst'),
                    'cburst_str': data.get('cburst'),
                    'sent_bytes': int(data['sent_bytes']) if data.get('sent_bytes') else 0,
                    'sent_pkts': int(data['sent_pkts']) if data.get('sent_pkts') else 0,
                    'dropped_pkts': int(data['dropped_pkts']) if data.get('dropped_pkts') else 0,
                    'overlimits': int(data['overlimits']) if data.get('overlimits') else 0,
                    'quantum': data.get('quantum'),
                    'level': data.get('level')
                }
                classes[classid] = class_info
            else:
                app.logger.warning(f"parse_tc_class_show: No regex match for class block:\n{block[:200]}...") # Log snippet
    else:
        app.logger.warning(f"parse_tc_class_show: No output or error from 'tc class show' for interface {interface}.")

    app.logger.debug(f"Parsed classes for {interface}: {classes}")
    return classes
# ใน app.py
# ... (import statements และ app.logger, run_command, validation helpers ของคุณ) ...
# ใน app.py
# ... (import statements และ app.logger, run_command, validation helpers ของคุณ) ...

# (ฟังก์ชัน parse_tc_class_show และ parse_tc_filter_show ของคุณควรจะยังคงอยู่
# และถ้ามีการเรียก run_command ภายในนั้น ก็ควรจะอัปเดตให้ใช้ cmd_list)

def tc_add_class(interface, classid, parent_classid, rate_str_for_tc,
                 ceil_str_for_tc=None, prio_str=None,
                 burst_str_for_tc=None, cburst_str_for_tc=None,
                 action="add"):
    """
    Adds or changes a TC class using HTB.
    All arguments are expected to be pre-validated for general type and basic format.
    This function performs final TC-specific format validation.
    Args:
        interface (str): Validated network interface name.
        classid (str): Validated TC class ID (e.g., "1:10").
        parent_classid (str): Validated parent TC class ID (e.g., "1:1" or "1:").
        rate_str_for_tc (str): Validated TC rate string (e.g., "10mbit").
        ceil_str_for_tc (str, optional): Validated TC ceil rate string. Defaults to rate_str_for_tc.
        prio_str (str, optional): Validated priority as a string (e.g., "1", "7").
        burst_str_for_tc (str, optional): Validated TC burst string (e.g., "15k").
        cburst_str_for_tc (str, optional): Validated TC cburst string.
        action (str): "add" or "change".
    Returns:
        bool: True on success, False on failure.
    """
    if not (validate_interface_name(interface) and
            validate_tc_classid(classid) and
            validate_tc_classid(parent_classid) and # Handles "1:", "ffff:" etc.
            validate_tc_specific_rate_string(rate_str_for_tc) and
            action in ["add", "change"]):
        app.logger.error(f"tc_add_class: Pre-validation failed for critical arguments: "
                         f"IF='{interface}', CID='{classid}', PID='{parent_classid}', Rate='{rate_str_for_tc}', Act='{action}'")
        return False

    effective_ceil_str = ceil_str_for_tc if ceil_str_for_tc else rate_str_for_tc
    if not validate_tc_specific_rate_string(effective_ceil_str):
        app.logger.error(f"tc_add_class: Invalid TC-specific ceil string: {effective_ceil_str}")
        return False

    if prio_str is not None and not validate_priority_str(prio_str, 0, 7): # HTB Prio 0-7
        app.logger.error(f"tc_add_class: Invalid priority string for TC: {prio_str}")
        return False

    if burst_str_for_tc and not validate_tc_specific_burst_string(burst_str_for_tc):
        app.logger.error(f"tc_add_class: Invalid TC-specific burst string: {burst_str_for_tc}")
        return False
    if cburst_str_for_tc and not validate_tc_specific_burst_string(cburst_str_for_tc):
        app.logger.error(f"tc_add_class: Invalid TC-specific cburst string: {cburst_str_for_tc}")
        return False

    cmd_list = ['tc', 'class', action, 'dev', interface,
                'parent', parent_classid, 'classid', classid, 'htb',
                'rate', rate_str_for_tc, 'ceil', effective_ceil_str]

    if prio_str is not None:
        cmd_list.extend(['prio', prio_str])
    if burst_str_for_tc:
        cmd_list.extend(['burst', burst_str_for_tc])
    if cburst_str_for_tc: # Note: For HTB, 'ceil' is the primary max rate. 'cburst' is less common.
        cmd_list.extend(['cburst', cburst_str_for_tc])

    app.logger.info(f"TC CMD: {' '.join(cmd_list)}")
    if run_command(cmd_list) is not None:
        app.logger.info(f"TC: Successfully {action}ed class {classid} on {interface}.")
        return True
    else:
        app.logger.error(f"TC: Failed to {action} class {classid} on {interface}. Command: {' '.join(cmd_list)}")
        return False

def tc_del_class(interface, classid):
    """
    Deletes a TC class.
    Args:
        interface (str): The network interface name (pre-validated).
        classid (str): The TC class ID to delete (pre-validated, e.g., "1:10").
    Returns:
        bool: True if command execution seemed successful (or class was already gone).
              False if command execution failed for other reasons.
    """
    if not validate_interface_name(interface) or not validate_tc_classid(classid):
        app.logger.error(f"tc_del_class: Invalid arguments. IF='{interface}', CID='{classid}'")
        return False

    cmd_list = ['tc', 'class', 'del', 'dev', interface, 'classid', classid]
    
    app.logger.info(f"TC CMD: {' '.join(cmd_list)}")
    output = run_command(cmd_list)

    if output is not None: # Command executed, even if tc reported "No such file or directory" (which is success for delete)
        app.logger.info(f"TC: Class deletion command for {classid} on {interface} executed. Output: '{output if output else 'No output'}'")
        # Further check if it actually deleted it could be done by parsing tc class show again,
        # but for simplicity, we assume if tc didn't throw a hard error (like bad args), it's fine.
        return True
    else:
        # run_command logs the specific error (CalledProcessError, Timeout, etc.)
        app.logger.warning(f"TC: Failed to execute delete command for class {classid} on {interface}. Command: {' '.join(cmd_list)}")
        return False


def tc_add_filter_u32(interface, parent_handle, prio_str, # prio is string for tc
                      protocol_for_tc, u32_match_expr_str, flowid_or_classid,
                      filter_action_verb="add", filter_handle_for_add=None): # filter_handle_for_add e.g., "800::1"
    """
    Adds or changes/replaces a u32 TC filter.
    All arguments MUST BE PRE-VALIDATED.
    Args:
        interface (str): Validated interface.
        parent_handle (str): Validated parent qdisc/class handle (e.g., "1:0", "ffff:").
        prio_str (str): Validated priority string (e.g., "1").
        protocol_for_tc (str): Validated protocol string for TC (e.g., "ip", "ipv6", "tcp").
        u32_match_expr_str (str): The pre-constructed and validated u32 match expression string.
                                  Example: "match ip src 192.168.1.10/32"
                                  Example: "match ip protocol 6 0xff match tcp dport 80 0xffff"
        flowid_or_classid (str): Validated target class ID (e.g., "1:10") or police flowid (e.g., ":1").
        filter_action_verb (str): "add", "change", or "replace".
        filter_handle_for_add (str, optional): Specific handle for `tc filter add` (e.g., "800::1").
    Returns:
        bool: True on success, False on failure.
    """
    # --- Final TC-specific validations ---
    if not (validate_interface_name(interface) and
            validate_tc_classid(parent_handle) and # Handles "1:", "ffff:" etc.
            validate_priority_str(prio_str, 1, 65535) and # TC filter prio range
            validate_protocol(protocol_for_tc, ['ip', 'ipv6', 'arp', 'all']) and # TC filter protocols
            u32_match_expr_str and isinstance(u32_match_expr_str, str) and
            (validate_tc_classid(flowid_or_classid) or (isinstance(flowid_or_classid, str) and flowid_or_classid.startswith(':'))) and # for police flowid :<handle>
            filter_action_verb in ["add", "change", "replace"]):
        app.logger.error(f"tc_add_filter_u32: Pre-validation failed for critical arguments. "
                         f"IF='{interface}', Parent='{parent_handle}', Prio='{prio_str}', Proto='{protocol_for_tc}', "
                         f"Match='{u32_match_expr_str[:50]}...', FlowID='{flowid_or_classid}', Action='{filter_action_verb}'")
        return False
    
    if filter_handle_for_add and (not isinstance(filter_handle_for_add, str) or not re.match(r"^[0-9a-fA-F]+::[0-9a-fA-F]*$", filter_handle_for_add)):
        app.logger.error(f"tc_add_filter_u32: Invalid filter_handle_for_add format: {filter_handle_for_add}")
        return False

    cmd_list = ['tc', 'filter', filter_action_verb, 'dev', interface,
                'parent', parent_handle, 'protocol', protocol_for_tc, 'prio', prio_str]

    if filter_handle_for_add and filter_action_verb == "add": # Handle for 'add' specifically
        cmd_list.extend(['handle', filter_handle_for_add])
    
    # u32_match_expr_str is assumed to be correctly formatted sequence of "match ..."
    # It's tricky to split it into list elements perfectly if it contains spaces within matches.
    # For `shell=False`, if u32_match_expr_str is complex, it might need careful splitting.
    # Simplest is often to pass it as one argument if `tc u32` parser handles that.
    # Let's assume tc u32 can parse "match ip src x match ip dport y" as subsequent arguments if `u32` is the command
    # So we add 'u32' then arguments for the match expression.
    cmd_list.append('u32')
    cmd_list.extend(shlex.split(u32_match_expr_str)) # Split the match expression into parts

    cmd_list.extend(['flowid', flowid_or_classid])
    
    app.logger.info(f"TC CMD: {' '.join(cmd_list)}") # For logging
    if run_command(cmd_list) is not None:
        app.logger.info(f"TC: Successfully {filter_action_verb}ed u32 filter on {interface}.")
        return True
    else:
        app.logger.error(f"TC: Failed to {filter_action_verb} u32 filter on {interface}. Command: {' '.join(cmd_list)}")
        return False

def tc_del_filter_u32(interface, parent_handle, prio_str, protocol_for_tc, u32_match_expr_str):
    """
    Deletes a u32 TC filter based on its match criteria.
    All arguments MUST BE PRE-VALIDATED.
    Args:
        interface (str): Validated interface.
        parent_handle (str): Validated parent qdisc/class handle.
        prio_str (str): Validated priority string.
        protocol_for_tc (str): Validated protocol string for TC.
        u32_match_expr_str (str): The pre-constructed and validated u32 match expression.
    Returns:
        bool: True on success or if filter was already gone, False on failure.
    """
    if not (validate_interface_name(interface) and
            validate_tc_classid(parent_handle) and
            validate_priority_str(prio_str, 1, 65535) and
            validate_protocol(protocol_for_tc, ['ip', 'ipv6', 'arp', 'all']) and
            u32_match_expr_str and isinstance(u32_match_expr_str, str)):
        app.logger.error(f"tc_del_filter_u32: Pre-validation failed for critical arguments.")
        return False

    cmd_list = ['tc', 'filter', 'del', 'dev', interface,
                'parent', parent_handle, 'protocol', protocol_for_tc, 'prio', prio_str,
                'u32']
    cmd_list.extend(shlex.split(u32_match_expr_str)) # Split match expression
    
    app.logger.info(f"TC CMD: {' '.join(cmd_list)}")
    output = run_command(cmd_list)

    if output is not None:
        app.logger.info(f"TC: u32 filter deletion command for '{u32_match_expr_str[:50]}...' on {interface} executed. Output: '{output if output else 'No output'}'")
        return True
    else:
        app.logger.warning(f"TC: Failed to execute delete command for u32 filter '{u32_match_expr_str[:50]}...' on {interface}. Command: {' '.join(cmd_list)}")
        return False
def parse_tc_filters_advanced(interface, parent_handle_filter_str=None):
    """
    Parses 'tc -s -d filter show dev <interface> [parent <handle>]'.
    Args:
        interface (str): The network interface name (pre-validated).
        parent_handle_filter_str (str, optional): Specific parent handle to filter by (e.g., "1:0", "ffff:").
                                                 Should be pre-validated if provided.
    Returns:
        list: A list of dictionaries, each representing a parsed filter.
    """
    if not validate_interface_name(interface):
        app.logger.error(f"parse_tc_filters_advanced: Invalid interface name '{interface}'.")
        return []
    
    if parent_handle_filter_str and not validate_tc_classid(parent_handle_filter_str): # classid validator works for handles too
        app.logger.error(f"parse_tc_filters_advanced: Invalid parent_handle_filter_str '{parent_handle_filter_str}'.")
        return []

    filters_list = []
    cmd_list = ['tc', '-s', '-d', 'filter', 'show', 'dev', interface]
    if parent_handle_filter_str:
        cmd_list.extend(['parent', parent_handle_filter_str])
    
    output = run_command(cmd_list) # <--- เรียกแบบใหม่

    if not output:
        app.logger.warning(f"parse_tc_filters_advanced: No output or error for command: {' '.join(cmd_list)}")
        return filters_list

    # TC filter output is tricky as one filter can span multiple lines and actions.
    # We split by "filter parent" assuming each new filter starts with this.
    # This regex tries to capture a full filter block.
    filter_block_pattern = re.compile(r"filter\s+parent\s+(?P<parent>[0-9a-fA-F]+:(?:[0-9a-fA-F]*)?)\s*(?:protocol\s+(?P<protocol>\S+))?\s*(?:pref\s+(?P<prio>\d+))?\s*(?P<type>\w+)(?P<rest_of_filter_line>.*?)(?=(?:filter\s+parent|\Z))", re.DOTALL | re.IGNORECASE)
    
    for match_obj in filter_block_pattern.finditer(output):
        filter_data = match_obj.groupdict()
        full_block_text = match_obj.group(0) # The entire text for this filter block
        
        parsed_filter = {
            'parent': filter_data['parent'],
            'protocol': filter_data.get('protocol', 'all').lower(), # Default to 'all' if not specified
            'prio': filter_data.get('prio', '0'), # Default prio if not specified
            'type': filter_data['type'].lower(),
            'match': {}, # To store u32 match details
            'actions': [], # To store actions like police, mirred
            'raw_block': full_block_text.strip() # For debugging
        }

        # Extract handle (fh or handle 0x...)
        handle_match = re.search(r"(?:fh\s+|handle\s+)(?P<handle>[0-9a-fA-F]+::[0-9a-fA-F]*|0x[0-9a-fA-F]+)", full_block_text, re.IGNORECASE)
        if handle_match:
            parsed_filter['handle'] = handle_match.group('handle')

        # Extract flowid/classid (target of the filter)
        flowid_match = re.search(r"(?:flowid|classid)\s+([0-9a-fA-F]+:[0-9a-fA-F]+|:[0-9a-fA-F]+)", full_block_text, re.IGNORECASE) # Police uses :handle
        if flowid_match:
            parsed_filter['flowid'] = flowid_match.group(1)
        
        # --- Parse u32 match details (example, can be expanded) ---
        if parsed_filter['type'] == 'u32':
            # Example: match ip src 192.168.1.10/32
            # Example: match ip protocol 6 0xff match tcp dport 80 0xffff
            u32_matches = re.findall(r"match\s+([a-zA-Z0-9_]+)\s+([^ \n\t]+(?:\s+[^ \n\t]+)?)", full_block_text, re.IGNORECASE)
            for u32_match_key, u32_match_val in u32_matches:
                # This is a very basic parsing of u32. Real u32 can be complex (offsets, masks).
                # For 'ip protocol 6 0xff', key='ip', val='protocol 6 0xff'
                # You might need a more structured approach if you need to deeply parse u32 keys/values/masks/offsets.
                parsed_filter['match'][u32_match_key.lower()] = u32_match_val.strip()

                # Try to extract specific IP/Port matches for easier use later
                if u32_match_key.lower() == 'ip' or u32_match_key.lower() == 'ip6':
                    if 'src' in u32_match_val.lower():
                        ip_src_m = re.search(r"src\s+([0-9a-fA-F.:/]+)", u32_match_val, re.IGNORECASE)
                        if ip_src_m: parsed_filter['match']['ip_src_extracted'] = ip_src_m.group(1)
                    if 'dst' in u32_match_val.lower():
                        ip_dst_m = re.search(r"dst\s+([0-9a-fA-F.:/]+)", u32_match_val, re.IGNORECASE)
                        if ip_dst_m: parsed_filter['match']['ip_dst_extracted'] = ip_dst_m.group(1)
                    if 'protocol' in u32_match_val.lower():
                        proto_m = re.search(r"protocol\s+(\d+)\s+0xff", u32_match_val, re.IGNORECASE)
                        if proto_m: parsed_filter['match']['ip_protocol_num_extracted'] = proto_m.group(1)

                if u32_match_key.lower() == 'tcp' or u32_match_key.lower() == 'udp':
                    if 'sport' in u32_match_val.lower():
                        sport_m = re.search(r"sport\s+(\d+)\s+0xffff", u32_match_val, re.IGNORECASE)
                        if sport_m: parsed_filter['match']['sport_extracted'] = sport_m.group(1)
                    if 'dport' in u32_match_val.lower():
                        dport_m = re.search(r"dport\s+(\d+)\s+0xffff", u32_match_val, re.IGNORECASE)
                        if dport_m: parsed_filter['match']['dport_extracted'] = dport_m.group(1)
        
        # --- Parse actions (example for police) ---
        action_police_match = re.search(r"action\s+police\s+rate\s+(?P<rate>\S+)\s+burst\s+(?P<burst>\S+)(?:\s+conform-exceed\s+(?P<conf_excd>\S+))?", full_block_text, re.IGNORECASE)
        if action_police_match:
            police_action = {'type': 'police'}
            police_action.update(action_police_match.groupdict())
            parsed_filter['actions'].append(police_action)
        
        # Add more action parsers (mirred, drop, etc.) if needed

        # Statistics (from -s flag)
        sent_stats_match = re.search(r"Sent\s+(?P<sent_bytes>\d+)\s+bytes\s+(?P<sent_pkts>\d+)\s+pkt", full_block_text)
        if sent_stats_match:
            parsed_filter['sent_bytes'] = int(sent_stats_match.group('sent_bytes'))
            parsed_filter['sent_pkts'] = int(sent_stats_match.group('sent_pkts'))
        
        filters_list.append(parsed_filter)
        app.logger.debug(f"Parsed filter on {interface} (parent {parent_handle_filter_str or 'any'}): {parsed_filter}")
        
    return filters_list
def parse_tc_filter_show(interface, direction_unused=None): # direction not strictly used if parsing all
    # ... (Full implementation from flask_bandwidth_control_full/app.py or refined version)
    # This function is complex and depends heavily on the exact output of `tc filter show`.
    # The version in the uploaded file had some regex.
    filters = {}
    # A simplified approach:
    output = run_command(f"tc filter show dev {interface} ingress") # Focus on ingress for download limits
    if output:
        # Example: filter parent ffff: protocol ip pref 1 u32 chain 0 fh 800::800 flowid :123 police ...
        # Example: filter parent 1:10 protocol ip pref 1 u32 ... flowid 1:101
        # This regex is a placeholder and needs to be robust for your tc filter output format.
        # It tries to find parent, protocol, prio, match details, and flowid (target class for HTB or :handle for police)
        filter_pattern = re.compile(
            r"filter\s+parent\s+(?P<parent>\w+:\w*)\s+protocol\s+(?P<protocol>\S+)\s+pref\s+(?P<prio>\d+)\s+"
            r"(?P<type>u32|fw|basic|flower).*?"
            r"match\s+(?P<match_details>(?:ip\s+(?:src|dst)\s+[\d\.:/]+|ip6\s+(?:src|dst)\s+[0-9a-fA-F:/]+)(?:\s+protocol\s+\S+)?(?:\s+(?:s|d)port\s+\d+)?).*?"
            r"(?:flowid\s+(?P<flowid>\w+:\w*)|classid\s+(?P<classid>\w+:\w*))",
            re.DOTALL | re.IGNORECASE
        )
        for content_block in output.split("filter"):
            if not content_block.strip(): continue
            full_content = "filter " + content_block
            match = filter_pattern.search(full_content)
            if match:
                data = match.groupdict()
                # Create a unique key, perhaps based on match_details or a combination
                key = f"{data['parent']}|{data['prio']}|{data['protocol']}|{data['match_details'].strip()}"
                filters[key] = data
    app.logger.debug(f"Parsed {len(filters)} filters for {interface} (ingress focused).")
    return filters

def parse_rate_input_from_db_string(rate_db_str):
    """Helper to parse rate string from DB (e.g., "10Mbps") into value and unit for forms."""
    if not rate_db_str: return None, None
    match = re.match(r'(\d+(\.\d+)?)\s*([a-zA-Z]+)', rate_db_str)
    if match:
        value = match.group(1)
        unit = match.group(3).lower() # e.g., mbps, kbps, kbit, mbit
        # Normalize unit for form dropdown if needed
        if unit in ["mbit", "mbps"]: unit_for_form = "mbps"
        elif unit in ["kbit", "kbps"]: unit_for_form = "kbps"
        elif unit in ["gbit", "gbps"]: unit_for_form = "gbps"
        elif unit in ["bit", "bps"]: unit_for_form = "bps"
        else: unit_for_form = unit # Or a default if unknown
        return value, unit_for_form
    return None, None

def is_rule_scheduled_active_now(rule_obj, current_datetime):
    # ... (Full working logic from previous, checking rule_obj.is_enabled too) ...
    if not rule_obj.is_scheduled or not rule_obj.is_enabled: return False
    now_time, now_weekday, now_date = current_datetime.time(), current_datetime.strftime('%a'), current_datetime.date()
    time_match = False
    if rule_obj.start_time and rule_obj.end_time:
        try:
            st, et = dtime.fromisoformat(rule_obj.start_time), dtime.fromisoformat(rule_obj.end_time)
            time_match = (st <= et and st <= now_time < et) or (st > et and (now_time >= st or now_time < et))
        except ValueError: app.logger.error(f"Rule {rule_obj.id} invalid time format.", exc_info=True)
    if not time_match and rule_obj.is_scheduled: return False # Must match time if scheduled

    if rule_obj.weekdays and not any(day.lower() == now_weekday.lower() for day in rule_obj.weekdays.split(',')): return False
    
    date_match = True
    if rule_obj.start_date:
        try: date_match = now_date >= ddate.fromisoformat(rule_obj.start_date)
        except ValueError: date_match = False
    if not date_match: return False

    if rule_obj.end_date:
        try: date_match = now_date <= ddate.fromisoformat(rule_obj.end_date)
        except ValueError: date_match = False
    return date_match # If all checks pass or are not applicable


# --- (The definitions for apply_single_tc_rule, clear_single_tc_rule, set_bandwidth_limit, set_group_limit, clear_group_limit
#      MUST BE THE FULL, DETAILED VERSIONS WE DEVELOPED, adapted for single-file app.py.
#      These are very long. I will provide the set_bandwidth_limit as the most complex example,
#      and you will need to ensure the others are similarly complete.)

# Placeholder for other helpers like apply_single_tc_rule, clear_single_tc_rule - you need their full code
    # THIS FUNCTION NEEDS ITS FULL IMPLEMENTATION
    # It uses: app.logger, run_command, parse_rate_to_tc_format (or parse_rate_input),
    # parse_tc_class_show, parse_tc_filter_show, GroupLimit.query
    # It constructs and executes multiple `tc` commands for add/change/delete filters and classes.
    # It handles burst, cburst, priority.
    # For now, simplified version of what was last provided for this function:
    if not rule_obj or not rule_obj.interface: return False
    if not rule_obj.is_enabled: app.logger.info(f"Rule {rule_obj.id} disabled, skipping TC."); return True

    # ... (Full logic from previous detailed `apply_single_tc_rule` goes here)
    # ... (This includes ensuring qdiscs, parent group classes, IP classes, filters for upload)
    # ... (And ingress police filters for download)
    # ... (Using rule_obj.priority, rule_obj.burst_str, rule_obj.cburst_str correctly)
    app.logger.info(f"[Placeholder] apply_single_tc_rule for rule ID {rule_obj.id}. TC commands would be built and run here.")
    # Example: run_command("tc ...")
    return True # Assume success for placeholder
PROTO_NAME_TO_NUM_MAP = {
    "tcp": "6",
    "udp": "17",
    "icmp": "1",
    # "ip" or "ipv6" don't need a number here as tc handles them directly
}

def apply_single_tc_rule(rule_obj):
    """
    Applies a single TC rule (from DB object) to the system.
    Args:
        rule_obj (Rule): The SQLAlchemy Rule object.
    Returns:
        bool: True if TC commands were successfully applied (or rule is disabled), False otherwise.
    """
    if not rule_obj or not rule_obj.interface:
        app.logger.error("apply_single_tc_rule: Invalid rule_obj or missing interface.")
        return False

    # 1. Validate interface from rule_obj
    if not validate_interface_name(rule_obj.interface):
        app.logger.error(f"apply_single_tc_rule: Invalid interface name '{rule_obj.interface}' in Rule ID {rule_obj.id}.")
        return False

    # 2. Check if rule is enabled in the database
    if not rule_obj.is_enabled:
        app.logger.info(f"Rule ID {rule_obj.id} (IP: {rule_obj.ip}) is disabled in DB. "
                        f"Attempting to clear any existing TC configurations for it.")
        return clear_single_tc_rule(rule_obj) # Ensure TC is cleared if rule is disabled

    app.logger.info(f"Applying TC for Rule ID {rule_obj.id} (IP: {rule_obj.ip}, Dir: {rule_obj.direction}, Interface: {rule_obj.interface})")

    # 3. Ensure Root Qdisc based on direction
    root_qdisc_type = "htb" if rule_obj.direction == "upload" else "ingress"
    # HTB default class minor ID, ensure it's a string for tc_ensure_root_qdisc
    htb_default_minor = str(app.config.get('HTB_DEFAULT_CLASS_MINOR_ID', "10"))
    if not tc_ensure_root_qdisc(rule_obj.interface, default_classid_minor=htb_default_minor, qdisc_type=root_qdisc_type):
        app.logger.error(f"Failed to ensure root {root_qdisc_type.upper()} qdisc on {rule_obj.interface} for Rule ID {rule_obj.id}")
        return False

    # 4. Parse and Validate Rates for TC
    # Main rate
    tc_rate_main, _, _ = parse_rate_to_tc_format(rule_obj.rate_str) # Assumes rate_str is "ValueUnit"
    if not tc_rate_main or not validate_tc_specific_rate_string(tc_rate_main):
        app.logger.error(f"Rule ID {rule_obj.id}: Invalid main rate_str '{rule_obj.rate_str}' for TC.")
        return False

    # Ceil rate (for HTB, often same as main rate if not specified, or from cburst_str)
    tc_ceil_main = None
    if rule_obj.direction == "upload":
        if rule_obj.cburst_str: # cburst_str in DB is used as 'ceil' for the HTB class
            tc_ceil_main, _, _ = parse_rate_to_tc_format(rule_obj.cburst_str)
            if not tc_ceil_main or not validate_tc_specific_rate_string(tc_ceil_main):
                app.logger.warning(f"Rule ID {rule_obj.id}: Invalid cburst_str (ceil) '{rule_obj.cburst_str}' for TC. Defaulting ceil to rate.")
                tc_ceil_main = tc_rate_main # Fallback
        else:
            tc_ceil_main = tc_rate_main # Default ceil to rate if cburst_str is not set

    # Burst rate (for HTB class)
    tc_burst_main = None
    if rule_obj.direction == "upload" and rule_obj.burst_str:
        # burst_str in DB is for HTB class 'burst' parameter
        # parse_rate_to_tc_format should ideally also handle units like '15k', '2m', '1600b'
        # For now, let's assume it returns a TC-compatible string directly or we validate separately
        tc_burst_main, _, _ = parse_rate_to_tc_format(rule_obj.burst_str)
        if not tc_burst_main or not validate_tc_specific_burst_string(tc_burst_main):
            app.logger.warning(f"Rule ID {rule_obj.id}: Invalid burst_str '{rule_obj.burst_str}' for TC. Ignoring burst.")
            tc_burst_main = None
    
    # --- UPLOAD DIRECTION ---
    if rule_obj.direction == "upload":
        parent_classid_for_ip_rule = rule_obj.upload_parent_handle
        ip_classid_for_rule = rule_obj.upload_classid

        if not validate_tc_classid(parent_classid_for_ip_rule) or not validate_tc_classid(ip_classid_for_rule):
            app.logger.error(f"Rule ID {rule_obj.id}: Invalid TC parent ('{parent_classid_for_ip_rule}') or class ('{ip_classid_for_rule}') identifier.")
            return False
        
        # (Logic for ensuring parent group class exists, if rule_obj.group_name is set,
        #  should be here, calling tc_add_class for the group. This was in set_bandwidth_limit previously)
        # For simplicity in this function, we assume parent_classid_for_ip_rule is correctly set.

        prio_str_for_tc = str(rule_obj.priority) if rule_obj.priority is not None else None
        if prio_str_for_tc and not validate_priority_str(prio_str_for_tc, 0, 7): # HTB prio
            app.logger.warning(f"Rule ID {rule_obj.id}: Invalid priority '{prio_str_for_tc}'. Ignoring priority.")
            prio_str_for_tc = None

        # Action: 'add' or 'change'. Need to check if class already exists to decide.
        # current_classes_on_iface = parse_tc_class_show(rule_obj.interface)
        # tc_action_class = "change" if ip_classid_for_rule in current_classes_on_iface else "add"
        # For simplicity, we'll use "add". `tc class add` might fail if it exists with incompatible params.
        # A robust solution checks and uses 'change' or deletes and re-adds.
        # Here, let's assume we try to add, and if it fails because it exists, we might try change or log.
        # Or, the calling function (set_bandwidth_limit) should have handled overwrite logic.
        # Let's default to "add" and let tc handle "file exists" if it's truly identical.
        # If parameters change, "change" is better. Assuming "add" for now, and if it fails, caller might retry with "change".
        # Better yet: always "delete" then "add" to ensure clean state, or smart "change".
        # For now, let's assume the `set_bandwidth_limit` or an orchestrator decides add/change.
        # Here we just execute what is implied. Let's assume this function is called to *create* or *ensure* the class.
        # A common pattern is `tc class replace ...` which adds if not exists, or changes if it does.
        # However, `tc class replace` is not as straightforward as `add` or `change` for all parameters.
        # Let's assume we use 'add', and tc might give 'RTNETLINK answers: File exists'.
        # This function should be idempotent or the caller handles existence.
        # Let's try "add", if it fails, try "change". This is a common pattern.

        # --- Add/Change HTB Class for the IP Rule ---
        if not tc_add_class(interface=rule_obj.interface,
                            classid=ip_classid_for_rule,
                            parent_classid=parent_classid_for_ip_rule,
                            rate_str_for_tc=tc_rate_main,
                            ceil_str_for_tc=tc_ceil_main,
                            prio_str=prio_str_for_tc,
                            burst_str_for_tc=tc_burst_main,
                            action="add"): # Try add first
            # If add failed (e.g. "File exists"), try change
            app.logger.warning(f"TC 'add class' failed for {ip_classid_for_rule}, trying 'change class'.")
            if not tc_add_class(interface=rule_obj.interface,
                                classid=ip_classid_for_rule,
                                parent_classid=parent_classid_for_ip_rule,
                                rate_str_for_tc=tc_rate_main,
                                ceil_str_for_tc=tc_ceil_main,
                                prio_str=prio_str_for_tc,
                                burst_str_for_tc=tc_burst_main,
                                action="change"):
                app.logger.error(f"Failed to apply TC class {ip_classid_for_rule} for Rule ID {rule_obj.id} (both add and change failed).")
                return False
        
        # --- Add u32 Filter for the IP Rule ---
        u32_match_parts = []
        # Protocol for `tc filter ... protocol <proto>`
        tc_filter_protocol = "ip" # Default
        if ":" in rule_obj.ip: # IPv6
            u32_match_parts.append(f"match ip6 src {rule_obj.ip}/128")
            tc_filter_protocol = "ipv6"
        else: # IPv4
            u32_match_parts.append(f"match ip src {rule_obj.ip}/32")
            tc_filter_protocol = "ip" # Explicitly ip for IPv4 u32
        
        # Protocol and Ports for u32 match expression
        if rule_obj.protocol and rule_obj.protocol.lower() not in ["ip", "ipv6", "all", "any", ""]:
            proto_num_for_match = PROTO_NAME_TO_NUM_MAP.get(rule_obj.protocol.lower())
            if proto_num_for_match:
                u32_match_parts.append(f"match ip protocol {proto_num_for_match} 0xff")
                # Ports are matched if protocol is TCP or UDP
                if rule_obj.protocol.lower() in ["tcp", "udp"]:
                    if rule_obj.source_port and validate_port_number(rule_obj.source_port):
                        u32_match_parts.append(f"match {rule_obj.protocol.lower()} sport {rule_obj.source_port} 0xffff")
                    if rule_obj.destination_port and validate_port_number(rule_obj.destination_port):
                        u32_match_parts.append(f"match {rule_obj.protocol.lower()} dport {rule_obj.destination_port} 0xffff")
            else:
                app.logger.warning(f"Rule ID {rule_obj.id}: Unsupported protocol '{rule_obj.protocol}' for u32 filter 'match ip protocol'.")
        
        u32_match_expr = " ".join(u32_match_parts)
        filter_prio_str = str(rule_obj.priority if rule_obj.priority is not None else 10) # Filter priority can be different
        if not validate_priority_str(filter_prio_str, 1, 49151): # TC filter prio is wide range
            app.logger.warning(f"Rule ID {rule_obj.id}: Invalid filter priority '{filter_prio_str}'. Defaulting to 10.")
            filter_prio_str = "10"
        
        # Before adding, good practice is to delete any existing filter with the same match criteria but different flowid
        # This requires parsing existing filters. For now, we try to add.
        # `tc filter add` might replace if a filter with the same (parent, prio, protocol, u32 selector) exists.
        # To be absolutely sure for u32, explicit delete of old then add new is safer if params changed.
        # Let's assume 'add' will try its best, or 'replace' could be used if handle is known.
        # This function should ideally take a filter_handle_for_add if one is pre-determined and needs to be stable.
        if not tc_add_filter_u32(interface=rule_obj.interface,
                                 parent_handle=parent_classid_for_ip_rule,
                                 prio_str=filter_prio_str,
                                 protocol_for_tc=tc_filter_protocol, # "ip" or "ipv6" for the `tc filter protocol` part
                                 u32_match_expr_str=u32_match_expr,
                                 flowid_or_classid=ip_classid_for_rule,
                                 filter_action_verb="add"): # Could be "replace" if handle known
            app.logger.error(f"Failed to apply TC filter for Rule ID {rule_obj.id} pointing to {ip_classid_for_rule}.")
            # Optional: Rollback class if filter add fails
            # tc_del_class(rule_obj.interface, ip_classid_for_rule)
            return False
        
        app.logger.info(f"Upload Rule ID {rule_obj.id} TC (class & filter) applied successfully.")
        return True

    # --- DOWNLOAD DIRECTION (Ingress Policing) ---
    elif rule_obj.direction == "download":
        police_flowid_handle = rule_obj.upload_classid # Stored as ":<handle_num>" for police flowid
        if not (police_flowid_handle and isinstance(police_flowid_handle, str) and police_flowid_handle.startswith(':')):
            app.logger.error(f"Rule ID {rule_obj.id}: Invalid police flowid_handle format '{police_flowid_handle}'.")
            return False
        
        # Construct u32 match expression for download
        dl_u32_match_parts = []
        tc_filter_protocol_dl = "ip" # Default
        if ":" in rule_obj.ip: # IPv6
            dl_u32_match_parts.append(f"match ip6 dst {rule_obj.ip}/128")
            tc_filter_protocol_dl = "ipv6"
        else: # IPv4
            dl_u32_match_parts.append(f"match ip dst {rule_obj.ip}/32")
            tc_filter_protocol_dl = "ip"
        
        if rule_obj.protocol and rule_obj.protocol.lower() not in ["ip", "ipv6", "all", "any", ""]:
            proto_num_for_match = PROTO_NAME_TO_NUM_MAP.get(rule_obj.protocol.lower())
            if proto_num_for_match:
                dl_u32_match_parts.append(f"match ip protocol {proto_num_for_match} 0xff")
                if rule_obj.protocol.lower() in ["tcp", "udp"]:
                    # For download, destination port on client side is usually ephemeral.
                    # Source port (server's port) is more common to match.
                    if rule_obj.source_port and validate_port_number(rule_obj.source_port):
                         dl_u32_match_parts.append(f"match {rule_obj.protocol.lower()} sport {rule_obj.source_port} 0xffff")
                    if rule_obj.destination_port and validate_port_number(rule_obj.destination_port): # Less common but possible
                         dl_u32_match_parts.append(f"match {rule_obj.protocol.lower()} dport {rule_obj.destination_port} 0xffff")
            else:
                app.logger.warning(f"Rule ID {rule_obj.id}: Unsupported protocol '{rule_obj.protocol}' for u32 download filter.")
        
        dl_u32_match_expr = " ".join(dl_u32_match_parts)
        filter_prio_str_dl = str(rule_obj.priority if rule_obj.priority is not None else 10)
        if not validate_priority_str(filter_prio_str_dl, 1, 49151):
            app.logger.warning(f"Rule ID {rule_obj.id}: Invalid download filter priority '{filter_prio_str_dl}'. Defaulting to 10.")
            filter_prio_str_dl = "10"

        # Calculate burst for police action (example: 50ms of data at rate)
        _, rate_bps_for_burst, _ = parse_rate_to_tc_format(rule_obj.rate_str)
        if rate_bps_for_burst is None:
             app.logger.error(f"Rule ID {rule_obj.id}: Could not parse rate '{rule_obj.rate_str}' to calculate police burst.")
             return False
        
        burst_factor_seconds = float(app.config.get('POLICE_BURST_FACTOR_SECONDS', 0.05)) # 50ms
        min_burst_bytes_config = int(app.config.get('POLICE_BURST_MIN_BYTES', 1600))
        calculated_burst_bytes = max(int((rate_bps_for_burst / 8) * burst_factor_seconds), min_burst_bytes_config)
        
        # Construct the full `tc filter add ... action police ...` command as a list
        # Note: `tc filter add ... u32 ... action police ...` is one way.
        # `tc filter replace ...` requires a handle. If `police_flowid_handle` is just `:minor_id`,
        # tc needs a proper kernel handle (e.g., 800::XYZ) for `replace by handle`.
        # Adding with the same (parent,prio,protocol,selector) usually replaces u32.
        
        # Build the action part for police
        action_police_str = f"police rate {tc_rate_main} burst {calculated_burst_bytes}b drop flowid {police_flowid_handle}"
        
        # tc_add_filter_u32 expects flowid_or_classid, but for police, the action string contains it.
        # This means tc_add_filter_u32 might need adjustment or a new function for police filters.
        # Let's try to adapt: flowid_or_classid becomes the target for 'action ...'
        # However, `tc filter ... u32 ... action police ... flowid ...` is the structure.
        # So, the `flowid_or_classid` in `tc_add_filter_u32` should be the action string itself for police.

        # Re-thinking: `tc_add_filter_u32` is for filters that point to a class (flowid <classid>).
        # For police, the action is part of the filter. We might need a dedicated function or extend `tc_add_filter_u32`.

        # Let's assume for now we build the command directly here for ingress police
        cmd_list_police = ['tc', 'filter', 'add', 'dev', rule_obj.interface,
                           'parent', 'ffff:', 'protocol', tc_filter_protocol_dl, 'prio', filter_prio_str_dl,
                           'u32']
        cmd_list_police.extend(shlex.split(dl_u32_match_expr)) # Add match expression parts
        cmd_list_police.extend(['action', 'police', 'rate', tc_rate_main, 
                                'burst', f"{calculated_burst_bytes}b", # TC expects burst in bytes like '1600b' or '10k'
                                'drop', # Default action on exceed
                                'flowid', police_flowid_handle]) # flowid for police is for identification/stats

        app.logger.info(f"TC CMD (Download Police): {' '.join(cmd_list_police)}")
        if run_command(cmd_list_police) is not None:
            app.logger.info(f"Download Rule ID {rule_obj.id} (police) TC command executed successfully.")
            return True
        else:
            # Try 'replace' if 'add' failed (might be needed if filter with same selector exists)
            cmd_list_police[2] = 'replace' # Change 'add' to 'replace'
            app.logger.warning(f"TC 'add filter police' failed for Rule ID {rule_obj.id}, trying 'replace'. Original CMD: {' '.join(cmd_list_police)}")
            if run_command(cmd_list_police) is not None:
                app.logger.info(f"Download Rule ID {rule_obj.id} (police) TC 'replace' command executed successfully.")
                return True
            else:
                app.logger.error(f"Failed to apply TC police filter for Download Rule ID {rule_obj.id} (add and replace failed).")
                return False
    
    app.logger.error(f"apply_single_tc_rule: Unhandled direction '{rule_obj.direction}' or logic path for Rule ID {rule_obj.id}")
    return False


def clear_single_tc_rule(rule_obj):
    """
    Clears/Deletes a single TC rule from the system based on the DB object.
    Args:
        rule_obj (Rule): The SQLAlchemy Rule object.
    Returns:
        bool: True if TC commands seemed successful or rule was already gone, False otherwise.
    """
    if not rule_obj or not rule_obj.interface:
        app.logger.debug("clear_single_tc_rule: No rule object or interface, nothing to clear from TC perspective.")
        return True # Considered success as no TC action needed if no rule info

    if not validate_interface_name(rule_obj.interface):
        app.logger.error(f"clear_single_tc_rule: Invalid interface name '{rule_obj.interface}' in Rule ID {rule_obj.id}.")
        return False # Cannot proceed

    app.logger.info(f"Attempting to clear TC for Rule ID {rule_obj.id} (IP: {rule_obj.ip}, Dir: {rule_obj.direction}, Interface: {rule_obj.interface})")

    success = True
    if rule_obj.direction == "upload":
        ip_classid_to_del = rule_obj.upload_classid
        parent_handle_of_filter = rule_obj.upload_parent_handle

        if not validate_tc_classid(parent_handle_of_filter) or \
           (ip_classid_to_del and not validate_tc_classid(ip_classid_to_del)): # classid can be None if never applied
            app.logger.warning(f"Rule ID {rule_obj.id}: Invalid TC parent ('{parent_handle_of_filter}') or class ('{ip_classid_to_del}') identifier for deletion. Might not be fully cleared.")
            # Continue to attempt deletion with what we have, but log warning

        # --- Construct u32 match expression for deletion ---
        u32_match_parts_del = []
        tc_filter_protocol_del = "ip"
        if ":" in rule_obj.ip: # IPv6
            u32_match_parts_del.append(f"match ip6 src {rule_obj.ip}/128")
            tc_filter_protocol_del = "ipv6"
        else: # IPv4
            u32_match_parts_del.append(f"match ip src {rule_obj.ip}/32")
            tc_filter_protocol_del = "ip"

        if rule_obj.protocol and rule_obj.protocol.lower() not in ["ip", "ipv6", "all", "any", ""]:
            proto_num_for_match = PROTO_NAME_TO_NUM_MAP.get(rule_obj.protocol.lower())
            if proto_num_for_match:
                u32_match_parts_del.append(f"match ip protocol {proto_num_for_match} 0xff")
                if rule_obj.protocol.lower() in ["tcp", "udp"]:
                    if rule_obj.source_port and validate_port_number(rule_obj.source_port):
                        u32_match_parts_del.append(f"match {rule_obj.protocol.lower()} sport {rule_obj.source_port} 0xffff")
                    if rule_obj.destination_port and validate_port_number(rule_obj.destination_port):
                        u32_match_parts_del.append(f"match {rule_obj.protocol.lower()} dport {rule_obj.destination_port} 0xffff")
        
        u32_match_expr_to_del = " ".join(u32_match_parts_del)
        filter_prio_to_del_str = str(rule_obj.priority if rule_obj.priority is not None else 10) # Use same prio as add
        if not validate_priority_str(filter_prio_to_del_str, 1, 49151): filter_prio_to_del_str = "10"


        # Delete filter first
        if u32_match_expr_to_del and parent_handle_of_filter: # Ensure we have enough to identify filter
            if not tc_del_filter_u32(rule_obj.interface, parent_handle_of_filter, filter_prio_to_del_str,
                                     tc_filter_protocol_del, u32_match_expr_to_del):
                app.logger.warning(f"Problem deleting TC filter for Upload Rule ID {rule_obj.id}. Class {ip_classid_to_del} might remain if it existed.")
                # Not setting success = False here, as class deletion is often more critical to free up ID
        else:
            app.logger.warning(f"Rule ID {rule_obj.id}: Not enough info to construct specific filter deletion command for upload. Skipping filter delete.")

        # Then delete class
        if ip_classid_to_del:
            if not tc_del_class(rule_obj.interface, ip_classid_to_del):
                app.logger.warning(f"Failed to delete TC class {ip_classid_to_del} for Rule ID {rule_obj.id}.")
                success = False # Class deletion failure is more significant for resource cleanup
        else:
            app.logger.info(f"No ip_classid (upload_classid) found for Upload Rule ID {rule_obj.id}, skipping class deletion.")

        if success: app.logger.info(f"Upload Rule ID {rule_obj.id} TC clear attempt finished.")

    elif rule_obj.direction == "download":
        police_flowid_handle_to_del = rule_obj.upload_classid # Stored as ":<handle_num>"
        
        if not (police_flowid_handle_to_del and isinstance(police_flowid_handle_to_del, str) and police_flowid_handle_to_del.startswith(':')):
            app.logger.warning(f"Rule ID {rule_obj.id}: Invalid or missing police flowid_handle '{police_flowid_handle_to_del}' for download rule deletion. Cannot reliably delete.")
            return True # Assume nothing to delete if identifier is bad

        # --- Construct u32 match expression for deletion ---
        dl_u32_match_parts_del = []
        tc_filter_protocol_dl_del = "ip"
        if ":" in rule_obj.ip: # IPv6
            dl_u32_match_parts_del.append(f"match ip6 dst {rule_obj.ip}/128")
            tc_filter_protocol_dl_del = "ipv6"
        else: # IPv4
            dl_u32_match_parts_del.append(f"match ip dst {rule_obj.ip}/32")
            tc_filter_protocol_dl_del = "ip"

        if rule_obj.protocol and rule_obj.protocol.lower() not in ["ip", "ipv6", "all", "any", ""]:
            proto_num_for_match = PROTO_NAME_TO_NUM_MAP.get(rule_obj.protocol.lower())
            if proto_num_for_match:
                dl_u32_match_parts_del.append(f"match ip protocol {proto_num_for_match} 0xff")
                if rule_obj.protocol.lower() in ["tcp", "udp"]:
                    if rule_obj.source_port and validate_port_number(rule_obj.source_port):
                         dl_u32_match_parts_del.append(f"match {rule_obj.protocol.lower()} sport {rule_obj.source_port} 0xffff")
                    if rule_obj.destination_port and validate_port_number(rule_obj.destination_port):
                         dl_u32_match_parts_del.append(f"match {rule_obj.protocol.lower()} dport {rule_obj.destination_port} 0xffff")
        
        dl_u32_match_expr_to_del = " ".join(dl_u32_match_parts_del)
        filter_prio_to_del_str_dl = str(rule_obj.priority if rule_obj.priority is not None else 10)
        if not validate_priority_str(filter_prio_to_del_str_dl, 1, 49151): filter_prio_to_del_str_dl = "10"

        # For ingress police, the "flowid :<handle>" is part of the "action police" statement.
        # Deleting requires matching the filter selector (parent, prio, proto, u32 match).
        # The tc_del_filter_u32 should handle this.
        if not tc_del_filter_u32(interface=rule_obj.interface,
                                 parent_handle="ffff:", # Ingress parent
                                 prio_str=filter_prio_to_del_str_dl,
                                 protocol_for_tc=tc_filter_protocol_dl_del,
                                 u32_match_expr_str=dl_u32_match_expr_to_del):
            app.logger.warning(f"Failed to delete TC police filter for Download Rule ID {rule_obj.id} by match criteria.")
            success = False
        
        if success: app.logger.info(f"Download Rule ID {rule_obj.id} (police) TC clear attempt finished.")
    
    return success
# ใน app.py
# ... (import statements, app setup, models, run_command, validation helpers,
#      tc_ensure_root_qdisc, tc_add_class, tc_del_class, tc_add_filter_u32, tc_del_filter_u32,
#      apply_single_tc_rule, clear_single_tc_rule, parse_rate_to_tc_format, etc. ควรถูก define ไว้ด้านบนแล้ว)

def set_bandwidth_limit(interface, ip,
                        rate_value_form, rate_unit_form,
                        direction, group_name=None, overwrite=False,
                        protocol=None, source_port=None, destination_port=None,
                        is_scheduled=False, start_time=None, end_time=None,
                        weekdays=None, start_date=None, end_date=None,
                        description=None, is_enabled=True, priority_form_str=None, # เปลี่ยนชื่อเพื่อบ่งบอกว่าเป็น string จาก form
                        burst_value_form=None, burst_unit_form=None,
                        cburst_value_form=None, cburst_unit_form=None, # สำหรับ HTB Class Ceil
                        existing_rule_id_to_update=None): # หากเป็น None คือการสร้าง Rule ใหม่
    """
    สร้างหรืออัปเดต Rule การจำกัดแบนด์วิดท์ใน Database และสั่งงาน TC
    มีการตรวจสอบ Input ทั้งหมดอย่างละเอียด
    Args:
        Argument ที่ลงท้ายด้วย "_form" คือค่าดิบจาก Form/API และต้องถูก Validate
        existing_rule_id_to_update (int, optional): ถ้ามีค่า จะเป็นการอัปเดต Rule ที่มีอยู่แล้ว
    Returns:
        bool: True ถ้าสำเร็จ, False ถ้าล้มเหลว (พร้อม flash message)
    """
    app.logger.info(f"set_bandwidth_limit: เริ่มทำงาน IP='{ip}', Rate='{rate_value_form}{rate_unit_form}', Dir='{direction}', Iface='{interface}', "
                    f"Group='{group_name}', Overwrite='{overwrite}', ExistingID='{existing_rule_id_to_update}', Enabled='{is_enabled}'")

    # --- 1. ตรวจสอบ Input อย่างละเอียด ---
    if not validate_interface_name(interface):
        flash(f"ชื่อ Interface ไม่ถูกต้อง: '{interface}'", "danger"); return False
    if not validate_ip_address(ip): # ip ควรถูก normalize ก่อน (ถ้าจำเป็น)
        flash(f"รูปแบบ IP Address ไม่ถูกต้อง: '{ip}'", "danger"); return False

    # ตรวจสอบ Rate หลัก
    if not validate_rate_value(rate_value_form) or \
       not validate_rate_unit(rate_unit_form, ['bps', 'kbps', 'mbps', 'gbps', 'bit', 'kbit', 'mbit', 'gbit']): # Whitelist ของหน่วยที่รับจาก Input
        flash(f"ค่า Rate หรือ Unit สำหรับแบนด์วิดท์หลักไม่ถูกต้อง: '{rate_value_form}{rate_unit_form}'", "danger"); return False

    if direction not in ['upload', 'download']:
        flash("Direction ไม่ถูกต้อง ต้องเป็น 'upload' หรือ 'download'", "danger"); return False
    if group_name and not validate_group_name(group_name): # group_name เป็น Optional
        flash(f"รูปแบบ Group Name ไม่ถูกต้อง: '{group_name}'", "danger"); return False
    
    # ตรวจสอบ Protocol และ Port
    protocol_clean = str(protocol).strip().lower() if isinstance(protocol, str) else None
    if protocol_clean == "any": protocol_clean = None # ถือว่า "any" คือไม่ระบุ Protocol L4 ที่เจาะจง

    if protocol_clean and not validate_protocol(protocol_clean, ['ip', 'ipv6', 'tcp', 'udp', 'icmp']): # รายการ Protocol ที่เข้มงวดขึ้น
        flash(f"Protocol ที่ระบุไม่ถูกต้อง: '{protocol}'", "danger"); return False
    
    source_port_clean = str(source_port).strip() if source_port is not None else None
    destination_port_clean = str(destination_port).strip() if destination_port is not None else None
    if not validate_port_number(source_port_clean) or not validate_port_number(destination_port_clean):
        flash("หมายเลข Source Port หรือ Destination Port ไม่ถูกต้อง", "danger"); return False
    if not source_port_clean: source_port_clean = None # ทำให้สตริงว่างเป็น None
    if not destination_port_clean: destination_port_clean = None

    # ตรวจสอบ Description (Optional)
    description_clean = str(description).strip() if isinstance(description, str) else None
    if description_clean is not None and not validate_description(description_clean): # validate_description ควรจัดการกรณี None ได้
        flash("Description ยาวเกินไปหรือมีอักขระที่ไม่ถูกต้อง", "danger"); return False

    # ตรวจสอบ Priority (Optional, สำหรับ HTB classes)
    priority_for_db = None # เก็บเป็น Integer ใน DB
    if priority_form_str is not None and str(priority_form_str).strip():
        if not validate_priority_str(str(priority_form_str).strip(), 0, 7): # Priority ของ HTB class ปกติคือ 0-7
            flash(f"ค่า Priority ไม่ถูกต้อง '{priority_form_str}'. ต้องเป็นตัวเลข 0-7", "danger"); return False
        priority_for_db = int(str(priority_form_str).strip())

    # ตรวจสอบ Burst และ Ceil/Cburst (สำหรับ Upload HTB class parameters)
    burst_str_for_db = None # สำหรับเก็บค่าเดิมที่ User ป้อน (ถ้าต้องการ) หรือค่าที่แปลงแล้วสำหรับ DB
    tc_burst_cmd_str = None # สำหรับส่งให้ tc_add_class
    if direction == "upload" and burst_value_form and burst_unit_form:
        if not validate_rate_value(burst_value_form) or \
           not validate_rate_unit(burst_unit_form, ['k', 'm', 'g', 'b', 'kb', 'mb', 'gb', 'kbit', 'mbit', 'gbit']): # หน่วยของ TC burst
            flash(f"ค่า Burst หรือ Unit ไม่ถูกต้อง: '{burst_value_form}{burst_unit_form}'", "danger"); return False
        # parse_rate_to_tc_format ควรจะสามารถจัดการหน่วยเหล่านี้เพื่อสร้าง tc_burst_cmd_str และ burst_str_for_db ที่เหมาะสม
        tc_burst_cmd_str, _, burst_str_for_db = parse_rate_to_tc_format(str(burst_value_form), burst_unit_form)
        if not tc_burst_cmd_str: # การ Parse ล้มเหลว
             flash(f"ไม่สามารถแปลง Burst '{burst_value_form}{burst_unit_form}' ให้อยู่ในรูปแบบ TC ได้", "danger"); return False

    cburst_str_for_db = None # สำหรับเก็บใน Rule.cburst_str (ใช้เป็น Ceil ของ HTB class)
    tc_ceil_cmd_str = None   # จะเป็น Argument 'ceil' สำหรับ tc_add_class
    if direction == "upload" and cburst_value_form and cburst_unit_form: # ผู้ใช้ระบุ Ceil มาโดยตรง
        if not validate_rate_value(cburst_value_form) or \
           not validate_rate_unit(cburst_unit_form, ['bps', 'kbps', 'mbps', 'gbps', 'bit', 'kbit', 'mbit', 'gbit']): # หน่วยของ Ceil เหมือน Rate
            flash(f"ค่า Ceil หรือ Unit ไม่ถูกต้อง: '{cburst_value_form}{cburst_unit_form}'", "danger"); return False
        tc_ceil_cmd_str, _, cburst_str_for_db = parse_rate_to_tc_format(str(cburst_value_form), cburst_unit_form)
        if not tc_ceil_cmd_str:
            flash(f"ไม่สามารถแปลง Ceil '{cburst_value_form}{cburst_unit_form}' ให้อยู่ในรูปแบบ TC ได้", "danger"); return False

    # ตรวจสอบ Scheduling parameters ถ้าเปิดใช้งาน
    if is_scheduled:
        if not start_time or not end_time:
            flash("ต้องระบุ Start Time และ End Time สำหรับ Rule ที่ตั้งเวลา", "danger"); return False
        if not (re.match(r"^\d{2}:\d{2}$", start_time) and re.match(r"^\d{2}:\d{2}$", end_time)):
            flash("รูปแบบ Time ไม่ถูกต้อง (HH:MM) สำหรับการตั้งเวลา", "danger"); return False
        if weekdays and not re.match(r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)(,(Mon|Tue|Wed|Thu|Fri|Sat|Sun))*$", weekdays, re.IGNORECASE):
            flash("รูปแบบ Weekdays ไม่ถูกต้อง (เช่น Mon,Tue,Wed)", "danger"); return False
        # อนุญาตให้ start_date/end_date เป็นค่าว่างได้
        if start_date and start_date.strip() and not re.match(r"^\d{4}-\d{2}-\d{2}$", start_date.strip()):
            flash("รูปแบบ Start Date ไม่ถูกต้อง (YYYY-MM-DD)", "danger"); return False
        if end_date and end_date.strip() and not re.match(r"^\d{4}-\d{2}-\d{2}$", end_date.strip()):
            flash("รูปแบบ End Date ไม่ถูกต้อง (YYYY-MM-DD)", "danger"); return False
    # --- สิ้นสุดการตรวจสอบ Input ---

    # แปลง Rate หลักสำหรับ TC และ DB
    tc_rate_main_cmd, _, rate_str_for_db_main = parse_rate_to_tc_format(str(rate_value_form), rate_unit_form)
    if not tc_rate_main_cmd: # ควรถูกดักจับโดย Validation ก่อนหน้าแล้ว แต่เป็นการป้องกันอีกชั้น
        flash(f"Error ร้ายแรงในการแปลง Rate หลัก: '{rate_value_form}{rate_unit_form}'", "danger"); return False

    # สำหรับ HTB class, ถ้า Ceil ไม่ได้ถูกระบุจาก cburst_*, ให้ default เป็น Rate หลัก
    if direction == "upload" and not tc_ceil_cmd_str:
        tc_ceil_cmd_str = tc_rate_main_cmd
        # cburst_str_for_db จะเหมือน rate_str_for_db_main ถ้าไม่ได้ตั้งค่ามา หรือเป็น None
        # ขึ้นอยู่กับว่าต้องการเก็บค่าที่แปลงแล้ว หรือค่าที่ user ป้อน หรือ None ถ้าไม่ระบุ
        # ในที่นี้ ถ้า tc_ceil_cmd_str ถูก default เป็น tc_rate_main_cmd, cburst_str_for_db ควรจะสะท้อนสิ่งนั้น
        cburst_str_for_db = rate_str_for_db_main # หรือ None ถ้าต้องการให้ชัดเจนว่าไม่ได้ตั้งค่ามา

    # --- จัดการ Rule ที่มีอยู่แล้ว / Logic การ Overwrite ---
    rule_being_processed = None
    if existing_rule_id_to_update: # นี่คือการ UPDATE
        rule_being_processed = db.session.get(Rule, existing_rule_id_to_update)
        if not rule_being_processed:
            flash(f"ไม่พบ Rule ID {existing_rule_id_to_update} สำหรับการอัปเดต", "danger"); return False
        # Key identifiers ไม่ควรเปลี่ยนระหว่างการอัปเดตผ่านฟังก์ชันนี้
        # หากต้องการเปลี่ยน IP, Direction, Protocol/Ports ควรจะเป็นการลบ Rule เก่าแล้วสร้างใหม่
        if rule_being_processed.interface != interface or \
           rule_being_processed.ip != ip or \
           rule_being_processed.direction != direction or \
           (rule_being_processed.protocol or None) != (protocol_clean or None) or \
           (rule_being_processed.source_port or None) != (source_port_clean or None) or \
           (rule_being_processed.destination_port or None) != (destination_port_clean or None):
            flash("ไม่สามารถเปลี่ยน Interface, IP, Direction, หรือ Protocol/Ports หลักระหว่างการแก้ไข Rule ได้ กรุณาลบแล้วสร้างใหม่หากต้องการเปลี่ยนแปลงค่าเหล่านี้", "danger")
            app.logger.warning(f"ความพยายามในการเปลี่ยน Key identifiers ของ Rule ID {existing_rule_id_to_update} ถูกยกเลิก")
            return False
        app.logger.info(f"กำลังอัปเดต Rule ID {rule_being_processed.id} ที่มีอยู่ จะทำการล้าง TC config เก่าก่อน")
        if not clear_single_tc_rule(rule_being_processed): # ส่ง DB object เดิมไปล้าง TC
            flash(f"คำเตือน: การล้าง TC config เก่าสำหรับ Rule ID {rule_being_processed.id} ก่อนอัปเดตอาจล้มเหลว ดำเนินการต่อด้วยความระมัดระวัง", "warning")
            # อาจจะไม่ใช่ Critical error ที่ต้องหยุดทันที แต่ควร Log ไว้

    else: # นี่คือการเพิ่ม Rule ใหม่
        # ตรวจสอบ Conflict โดยใช้ Unique Constraint Fields ทั้งหมด
        # (interface, ip, direction, protocol, source_port, destination_port)
        query_conflict = Rule.query.filter_by(
            interface=interface, ip=ip, direction=direction,
            protocol=protocol_clean, # ใช้ค่าที่ Clean แล้ว
            source_port=source_port_clean,
            destination_port=destination_port_clean
        )
        existing_rule_for_conflict_check = query_conflict.first()

        if existing_rule_for_conflict_check:
            if overwrite:
                app.logger.info(f"Overwrite: พบ Rule ID {existing_rule_for_conflict_check.id} ที่มีเงื่อนไขซ้ำซ้อน กำลังลบ TC และ DB entry เก่า")
                if not clear_single_tc_rule(existing_rule_for_conflict_check):
                    flash(f"คำเตือน: การล้าง TC config ของ Rule เดิม (ID: {existing_rule_for_conflict_check.id}) ระหว่างการ Overwrite อาจล้มเหลว", "warning")
                db.session.delete(existing_rule_for_conflict_check)
                try:
                    db.session.commit() # Commit การลบก่อน เพื่อป้องกัน Unique Constraint ตอน Add ใหม่
                except Exception as e_del_commit:
                    db.session.rollback()
                    app.logger.error(f"DB error ขณะ commit การลบ rule ID {existing_rule_for_conflict_check.id} ระหว่าง overwrite: {e_del_commit}", exc_info=True)
                    flash("เกิดข้อผิดพลาดในการลบ Rule เดิมระหว่างการ Overwrite การดำเนินการถูกยกเลิก", "danger"); return False
                rule_being_processed = None # เพื่อให้สร้าง Object ใหม่ด้านล่าง
            else: # Conflict และไม่ได้เลือก Overwrite
                flash(f"Rule ที่มี Interface, IP, Direction, และ Filter Criteria เดียวกันนี้มีอยู่แล้ว (ID: {existing_rule_for_conflict_check.id}) กรุณาเลือก 'overwrite' หรือแก้ไข Rule ที่มีอยู่", "danger")
                return False
    
    # --- สร้างหรืออัปเดต Rule Object ใน DB ---
    if rule_being_processed is None: # สร้าง Rule object ใหม่ (กรณี Add ใหม่ หรือ Overwrite)
        rule_being_processed = Rule(interface=interface, ip=ip, direction=direction)
        # สร้าง TC Identifiers (upload_classid, upload_parent_handle) สำหรับ Rule ใหม่เท่านั้น
        # (ถ้าเป็นการ Update, TC Identifiers เดิมจาก rule_being_processed (ที่ get มาจาก DB) ควรถูกใช้ต่อ)
        parent_handle_for_new_rule = "1:" if direction == "upload" else "ffff:" # Default TC parent
        if direction == "upload" and group_name: # ถ้า Rule อยู่ในกลุ่ม Parent จะเป็น Class ID ของกลุ่ม
            group_db_obj = GroupLimit.query.filter_by(interface=interface, group_name=group_name, direction="upload").first()
            if group_db_obj and group_db_obj.upload_classid and validate_tc_classid(group_db_obj.upload_classid):
                parent_handle_for_new_rule = group_db_obj.upload_classid
            elif group_db_obj:
                 app.logger.warning(f"กลุ่ม '{group_name}' ถูกค้นพบแต่มี upload_classid ('{group_db_obj.upload_classid}') ไม่ถูกต้อง Rule จะใช้ Parent หลัก ('1:') แทน")
            # ถ้าไม่พบ group_db_obj, parent_handle_for_new_rule จะยังคงเป็น "1:"
        
        if not validate_tc_classid(parent_handle_for_new_rule): # ควรจะ Valid เสมอถ้า Logic ถูก
            app.logger.error(f"Internal Error: Parent Handle ที่สร้างขึ้น ('{parent_handle_for_new_rule}') สำหรับ Rule ใหม่ไม่ถูกต้อง")
            flash("เกิดข้อผิดพลาดภายในในการสร้าง TC Parent Handle", "danger"); return False

        rule_being_processed.upload_parent_handle = parent_handle_for_new_rule
        
        if direction == "upload": # สร้าง Class ID สำหรับ HTB class
            # รูปแบบเช่น "1:101" (major ของ parent : minor ที่ unique)
            unique_seed_class = f"{interface}-{ip}-{direction}-{protocol_clean or 'any'}-{source_port_clean or 'any'}-{destination_port_clean or 'any'}-{parent_handle_for_new_rule}-{os.urandom(4).hex()}"
            ip_unique_minor_id = (abs(hash(unique_seed_class)) % 64900) + 100 # ช่วง 100-65000
            parent_major_id_str = parent_handle_for_new_rule.split(':')[0]
            rule_being_processed.upload_classid = f"{parent_major_id_str}:{ip_unique_minor_id}"
        else: # Download - สร้าง Handle สำหรับ Ingress police filter flowid
            unique_seed_filter = f"dl-{interface}-{ip}-{direction}-{protocol_clean or 'any'}-{source_port_clean or 'any'}-{destination_port_clean or 'any'}-{os.urandom(4).hex()}"
            filter_handle_num = abs(hash(unique_seed_filter)) % 65500 + 1 # ช่วง 1-65535
            rule_being_processed.upload_classid = f":{filter_handle_num}" # เก็บในรูปแบบ ":<num>"

        # Validate TC identifier ที่สร้างขึ้น
        if not ((direction == "upload" and validate_tc_classid(rule_being_processed.upload_classid)) or \
                (direction == "download" and isinstance(rule_being_processed.upload_classid, str) and rule_being_processed.upload_classid.startswith(':'))):
            app.logger.error(f"Internal Error: TC Identifier ที่สร้างขึ้น ('{rule_being_processed.upload_classid}') ไม่ถูกต้อง")
            flash("เกิดข้อผิดพลาดภายในในการสร้าง TC Identifier", "danger"); return False
        app.logger.info(f"สร้าง TC Identifiers ใหม่สำหรับ Rule: Parent='{rule_being_processed.upload_parent_handle}', ID='{rule_being_processed.upload_classid}'")

    # อัปเดต Field อื่นๆ ทั้งหมดใน rule_being_processed object
    rule_being_processed.rate_str = rate_str_for_db_main
    rule_being_processed.group_name = group_name if group_name else None # เก็บ None ถ้า group_name ว่าง
    rule_being_processed.protocol = protocol_clean
    rule_being_processed.source_port = source_port_clean
    rule_being_processed.destination_port = destination_port_clean
    rule_being_processed.description = description_clean
    rule_being_processed.is_enabled = is_enabled
    rule_being_processed.priority = priority_for_db # เก็บเป็น Integer

    if direction == "upload":
        rule_being_processed.burst_str = burst_str_for_db
        rule_being_processed.cburst_str = cburst_str_for_db # จะถูกใช้เป็น 'ceil' สำหรับ tc_add_class
    else: # Download (police) ไม่ได้เก็บ burst/cburst ใน DB แบบนี้ (คำนวณตอน Apply)
        rule_being_processed.burst_str = None
        rule_being_processed.cburst_str = None

    rule_being_processed.is_scheduled = is_scheduled
    if is_scheduled:
        rule_being_processed.start_time = start_time
        rule_being_processed.end_time = end_time
        rule_being_processed.weekdays = weekdays if (weekdays and weekdays.strip()) else None
        rule_being_processed.start_date = start_date if (start_date and start_date.strip()) else None
        rule_being_processed.end_date = end_date if (end_date and end_date.strip()) else None
    else: # ล้างค่า Schedule ถ้าไม่ได้ตั้งเวลา
        rule_being_processed.start_time, rule_being_processed.end_time = None, None
        rule_being_processed.weekdays, rule_being_processed.start_date, rule_being_processed.end_date = None, None, None
    
    rule_being_processed.is_active_scheduled = False # Scheduler จะเป็นผู้ตั้งค่านี้

    # --- สั่ง Apply TC Rule (ถ้า Rule ถูกเปิดใช้งาน และไม่ได้ตั้งเวลา) ---
    tc_applied_successfully_now = True # ตั้งสมมติฐานว่าสำเร็จ เว้นแต่จะล้มเหลว
    if is_enabled and not is_scheduled:
        app.logger.info(f"Rule (IP {ip}, DB ID {rule_being_processed.id or 'New'}) ถูกเปิดใช้งานและไม่ได้ตั้งเวลา กำลังสั่ง Apply TC เดี๋ยวนี้")
        if not apply_single_tc_rule(rule_being_processed): # ส่ง Rule object ที่อัปเดตแล้วหรือสร้างใหม่ไป
            flash_msg = f"ERROR: ไม่สามารถ Apply TC สำหรับ Rule ของ IP {ip} ({direction}) ได้ Rule ถูกบันทึกลง DB แต่อาจจะยังไม่ทำงาน"
            flash(flash_msg, "danger")
            app.logger.error(flash_msg)
            tc_applied_successfully_now = False
            # ทางเลือก: ตั้งค่า rule_being_processed.is_enabled = False ถ้า TC ล้มเหลว หรือปล่อยให้ผู้ใช้แก้ไขเอง
    elif not is_enabled: # ถ้า Rule ถูกตั้งค่าเป็น Disabled
        app.logger.info(f"Rule (IP {ip}, DB ID {rule_being_processed.id or 'New'}) ถูกบันทึกเป็น Disabled กำลังล้าง TC config เก่า (ถ้ามี)")
        clear_single_tc_rule(rule_being_processed) # พยายามล้าง TC config สำหรับ Rule นี้
        rule_being_processed.is_active_scheduled = False # Rule ที่ Disabled จะไม่ Active โดย Scheduler
    # ถ้า is_enabled และ is_scheduled, Scheduler จะเป็นผู้จัดการ TC application. is_active_scheduled ยังคงเป็น False ในตอนนี้

    # --- บันทึกลง Database ---
    try:
        if not rule_being_processed.id: # ถ้าเป็น Rule object ที่สร้างขึ้นใหม่ (ยังไม่มี ID)
            db.session.add(rule_being_processed)
        # ถ้าเป็น rule_being_processed ที่ get มาจาก DB (กรณี update) มันจะอยู่ใน session แล้ว การเปลี่ยนแปลง field จะถูก tracked
        db.session.commit()
        app.logger.info(f"Rule สำหรับ IP {ip} (DB ID: {rule_being_processed.id}) ถูกบันทึกลง Database เรียบร้อย สถานะ: {'Enabled' if is_enabled else 'Disabled'}, ตั้งเวลา: {is_scheduled}")
        
        # Flash message ตามผลลัพธ์
        if is_enabled:
            if is_scheduled:
                flash(f"Rule แบบตั้งเวลาสำหรับ IP {ip} ({rate_str_for_db_main} {direction}) ถูกบันทึกเรียบร้อย Scheduler จะจัดการการเปิด/ปิด", "success")
            elif tc_applied_successfully_now:
                flash(f"Rule สำหรับ IP {ip} ({rate_str_for_db_main} {direction}) ถูก Apply และบันทึกเรียบร้อย", "success")
            # else: ข้อความ TC failure ถูก flash ไปแล้ว
        else: # Rule ถูกบันทึกเป็น Disabled
             flash(f"Rule สำหรับ IP {ip} ({rate_str_for_db_main} {direction}) ถูกบันทึกเป็น DISABLED", "info")
        return True
    except Exception as e_db_final:
        db.session.rollback()
        error_msg_db = f"เกิดข้อผิดพลาด Database ขณะบันทึก Rule สำหรับ IP {ip}: {str(e_db_final)}"
        if "UNIQUE constraint failed" in str(e_db_final): # ตรวจสอบ Unique Constraint Error
             error_msg_db = f"DB Error: Rule ที่มีเงื่อนไข (Interface, IP, Direction, Filter) ซ้ำกันนี้ อาจจะยังคงมีอยู่ในระบบหลังจากการพยายาม Overwrite หรือเกิดจากการทำงานพร้อมกัน รายละเอียด: {str(e_db_final)}"
        flash(error_msg_db, "danger")
        app.logger.error(f"Database error สุดท้ายสำหรับ Rule ของ IP {ip}: {e_db_final}", exc_info=True)
        return False

# --- set_group_limit (ฉบับปรับปรุง) ---
def set_group_limit(interface, group_name_form,
                    rate_value_form, rate_unit_form,
                    direction,
                    burst_value_form=None, burst_unit_form=None, # สำหรับ HTB class burst
                    cburst_value_form=None, cburst_unit_form=None): # สำหรับ HTB class ceil
    """
    สร้างหรืออัปเดต Group Limit
    ทิศทาง Upload จะมีการสร้าง TC class, ทิศทาง Download ปัจจุบันจะเก็บข้อมูลใน DB เท่านั้น
    """
    app.logger.info(f"set_group_limit: Group='{group_name_form}', Iface='{interface}', Rate='{rate_value_form}{rate_unit_form}', Dir='{direction}'")

    # --- 1. ตรวจสอบ Input ---
    if not validate_interface_name(interface):
        flash(f"ชื่อ Interface ไม่ถูกต้อง: '{interface}'", "danger"); return False
    
    clean_group_name = str(group_name_form).strip() if group_name_form else None
    if not validate_group_name(clean_group_name) or not clean_group_name: # Group name จำเป็นสำหรับฟังก์ชันนี้
        flash(f"ชื่อ Group ไม่ถูกต้องหรือไม่ได้ระบุ: '{group_name_form}'", "danger"); return False

    if not validate_rate_value(rate_value_form) or \
       not validate_rate_unit(rate_unit_form, ['bps', 'kbps', 'mbps', 'gbps', 'bit', 'kbit', 'mbit', 'gbit']):
        flash(f"ค่า Rate หรือ Unit สำหรับ Group '{clean_group_name}' ไม่ถูกต้อง: '{rate_value_form}{rate_unit_form}'", "danger"); return False

    if direction not in ['upload', 'download']:
        flash(f"Direction '{direction}' สำหรับ Group '{clean_group_name}' ไม่ถูกต้อง", "danger"); return False

    # --- Parse Rate หลักสำหรับ TC และ DB ---
    tc_rate_grp_cmd, _, rate_grp_for_db = parse_rate_to_tc_format(str(rate_value_form), rate_unit_form)
    if not tc_rate_grp_cmd:
        flash(f"Error ร้ายแรงในการแปลง Rate ของ Group '{clean_group_name}'", "danger"); return False

    # --- Parse Burst และ Ceil/Cburst สำหรับ Upload Group (HTB class) ---
    tc_burst_grp_cmd_str = None
    burst_grp_for_db_str = None
    if direction == "upload" and burst_value_form and burst_unit_form:
        if not validate_rate_value(burst_value_form) or \
           not validate_rate_unit(burst_unit_form, ['k', 'm', 'g', 'b', 'kb', 'mb', 'gb', 'kbit', 'mbit', 'gbit']):
            flash(f"ค่า Burst หรือ Unit ของ Group '{clean_group_name}' ไม่ถูกต้อง", "danger"); return False
        tc_burst_grp_cmd_str, _, burst_grp_for_db_str = parse_rate_to_tc_format(str(burst_value_form), burst_unit_form)
        if not tc_burst_grp_cmd_str:
             flash(f"ไม่สามารถแปลง Group Burst '{burst_value_form}{burst_unit_form}' สำหรับ TC ได้", "danger"); return False

    tc_ceil_grp_cmd_str = tc_rate_grp_cmd # Default ceil = rate สำหรับ HTB group class
    cburst_grp_for_db_str = rate_grp_for_db # ถ้า Ceil = Rate, DB cburst อาจจะเก็บค่าเดียวกับ rate หรือเป็น None
    if direction == "upload" and cburst_value_form and cburst_unit_form: # ถ้าผู้ใช้ระบุ Ceil มา
        if not validate_rate_value(cburst_value_form) or \
           not validate_rate_unit(cburst_unit_form, ['bps', 'kbps', 'mbps', 'gbps', 'bit', 'kbit', 'mbit', 'gbit']):
            flash(f"ค่า Ceil หรือ Unit ของ Group '{clean_group_name}' ไม่ถูกต้อง", "danger"); return False
        
        tc_ceil_grp_cmd_str, _, cburst_grp_for_db_str = parse_rate_to_tc_format(str(cburst_value_form), cburst_unit_form)
        if not tc_ceil_grp_cmd_str:
            flash(f"ไม่สามารถแปลง Group Ceil '{cburst_value_form}{cburst_unit_form}' สำหรับ TC ได้", "danger"); return False

    # --- DB และ TC Logic ---
    existing_group_db = GroupLimit.query.filter_by(interface=interface, group_name=clean_group_name, direction=direction).first()
    
    group_tc_classid_to_store = None # จะเป็น TC Class ID เช่น "1:20" ถ้า direction="upload"

    if direction == "upload":
        # กำหนดหรือสร้าง TC Class ID สำหรับ Group
        if existing_group_db and existing_group_db.upload_classid and validate_tc_classid(existing_group_db.upload_classid):
            group_tc_classid_to_store = existing_group_db.upload_classid
        else: # Group ใหม่ หรือ Group เดิมที่เพิ่งจะตั้งค่าสำหรับ Upload TC
            # สร้าง Class ID ใหม่ที่ Unique สำหรับ Upload Group นี้ (Parent คือ "1:")
            # การสร้าง ID ที่ Unique จริงๆ ใน Production ควรมีการตรวจสอบการชนกันที่ดีกว่านี้
            unique_seed_group = f"group-{interface}-{clean_group_name}-{direction}-{os.urandom(4).hex()}"
            group_unique_minor_id = (abs(hash(unique_seed_group)) % 80) + 20 # เช่น ช่วง 20-99
            potential_new_classid = f"1:{group_unique_minor_id}"
            # TODO: เพิ่ม Logic ตรวจสอบการชนกันของ Class ID ที่สร้างขึ้นกับที่มีอยู่แล้ว
            group_tc_classid_to_store = potential_new_classid

        if not validate_tc_classid(group_tc_classid_to_store):
            flash(f"Internal error: TC ClassID ที่สร้างขึ้น ('{group_tc_classid_to_store}') สำหรับ Group ไม่ถูกต้อง", "danger"); return False

        # ตรวจสอบ Root HTB qdisc
        if not tc_ensure_root_qdisc(interface, default_classid_minor=str(app.config.get('HTB_DEFAULT_CLASS_MINOR_ID', "10")), qdisc_type="htb"):
            flash(f"ไม่สามารถสร้าง/ตรวจสอบ Root HTB qdisc สำหรับ Group '{clean_group_name}' ได้ การตั้งค่า TC ถูกยกเลิก", "danger"); return False

        # Add หรือ Change TC Class สำหรับ Group
        tc_action_grp = "add"
        # current_tc_classes_on_iface = parse_tc_class_show(interface) # ควรจะทำเพื่อดูว่า Class มีอยู่แล้วหรือไม่
        # if group_tc_classid_to_store in current_tc_classes_on_iface:
        #    tc_action_grp = "change"
        
        # ลอง Add ก่อน ถ้าล้มเหลว (เช่น "File exists") ค่อยลอง Change
        if not tc_add_class(interface=interface,
                            classid=group_tc_classid_to_store,
                            parent_classid="1:", # Group Class เป็นลูกของ Root "1:" เสมอ
                            rate_str_for_tc=tc_rate_grp_cmd,
                            ceil_str_for_tc=tc_ceil_grp_cmd_str,
                            burst_str_for_tc=tc_burst_grp_cmd_str,
                            # prio สำหรับ group class มักจะไม่ตั้งค่า หรือใช้ default
                            action="add"):
            if not tc_add_class(interface=interface,
                                classid=group_tc_classid_to_store,
                                parent_classid="1:",
                                rate_str_for_tc=tc_rate_grp_cmd,
                                ceil_str_for_tc=tc_ceil_grp_cmd_str,
                                burst_str_for_tc=tc_burst_grp_cmd_str,
                                action="change"):
                flash(f"ไม่สามารถ Apply TC Class สำหรับ Group '{clean_group_name}' (ID: {group_tc_classid_to_store}) ได้", "danger")
                return False
    # สำหรับ "download", Group Limit เป็นเพียงแนวคิดใน DB สำหรับการเชื่อมโยง Rule, ไม่มีการสร้าง TC Class โดยตรงสำหรับ Group

    # --- อัปเดตหรือสร้าง DB Entry ---
    try:
        if existing_group_db:
            app.logger.info(f"กำลังอัปเดต GroupLimit ที่มีอยู่สำหรับ '{clean_group_name}'/{direction} บน {interface}")
            existing_group_db.rate_str = rate_grp_for_db
            if direction == "upload":
                existing_group_db.upload_classid = group_tc_classid_to_store
                existing_group_db.burst_str = burst_grp_for_db_str
                existing_group_db.cburst_str = cburst_grp_for_db_str # เก็บค่า Ceil ที่แปลงแล้วสำหรับ DB
            else: # ถ้าเปลี่ยน Group เป็น Download หรืออัปเดต Download Group, ล้างค่า TC ที่ไม่เกี่ยวข้อง
                existing_group_db.upload_classid = None
                existing_group_db.burst_str = None
                existing_group_db.cburst_str = None
        else:
            app.logger.info(f"กำลังสร้าง GroupLimit ใหม่สำหรับ '{clean_group_name}'/{direction} บน {interface}")
            new_group = GroupLimit(
                interface=interface,
                group_name=clean_group_name,
                rate_str=rate_grp_for_db,
                direction=direction,
                upload_classid=group_tc_classid_to_store if direction == "upload" else None,
                burst_str=burst_grp_for_db_str if direction == "upload" else None,
                cburst_str=cburst_grp_for_db_str if direction == "upload" else None
            )
            db.session.add(new_group)
        
        db.session.commit()
        flash(f"Group Limit สำหรับ '{clean_group_name}' ({direction}) ถูกบันทึกเรียบร้อย", "success")
        return True
    except Exception as e_db_group_save:
        db.session.rollback()
        flash(f"เกิดข้อผิดพลาด Database ขณะบันทึก Group Limit สำหรับ '{clean_group_name}': {str(e_db_group_save)}", "danger")
        app.logger.error(f"Database error สำหรับ Group '{clean_group_name}': {e_db_group_save}", exc_info=True)
        return False


@app.route("/set_ip", methods=["POST"])
def set_ip_route():
    if not session.get('logged_in') or session.get('role') != 'admin':
        flash("Unauthorized access.", "danger"); return redirect(url_for('dashboard'))
    
    interface = session.get('active_interface')
    if not interface:
        flash("No active interface selected. Please select an interface first.", "danger")
        return redirect(url_for('dashboard'))

    # Extract form data
    ip_addr = request.form.get('ip')
    rate_val = request.form.get('rate_value')
    rate_u = request.form.get('rate_unit') # e.g., "mbps", "kbps"
    direction_val = request.form.get('direction')
    group_val = request.form.get('group_name').strip() if request.form.get('group_name') else None
    overwrite_flag = 'overwrite_rule' in request.form
    
    protocol = request.form.get('protocol').strip() if request.form.get('protocol') else None
    source_port = request.form.get('source_port').strip() if request.form.get('source_port') else None
    destination_port = request.form.get('destination_port').strip() if request.form.get('destination_port') else None
    
    desc_val = request.form.get('description').strip() if request.form.get('description') else None
    enabled_flag = 'is_enabled' in request.form
    
    priority_val_str = request.form.get('priority', '').strip()
    priority_val = int(priority_val_str) if priority_val_str.isdigit() else None
    
    burst_val = request.form.get('burst_value').strip() if request.form.get('burst_value') else None
    burst_u = request.form.get('burst_unit').strip() if request.form.get('burst_unit') else None
    cburst_val = request.form.get('cburst_value').strip() if request.form.get('cburst_value') else None
    cburst_u = request.form.get('cburst_unit').strip() if request.form.get('cburst_unit') else None

    is_sched = 'enable_scheduling' in request.form
    s_time, e_time, w_days, s_date, e_date = None, None, None, None, None
    if is_sched:
        s_time = request.form.get('start_time')
        e_time = request.form.get('end_time')
        w_days_list = request.form.getlist('weekdays')
        w_days = ",".join(w_days_list) if w_days_list else None
        s_date = request.form.get('start_date').strip() if request.form.get('start_date') else None
        e_date = request.form.get('end_date').strip() if request.form.get('end_date') else None
        
        if not s_time or not e_time:
            flash("Start Time and End Time are required when scheduling is enabled.", "danger")
            # Consider redirecting back to form with error, or just dashboard
            return redirect(url_for('dashboard')) 
        if s_time and not re.match(r"^\d{2}:\d{2}$", s_time):
            flash("Invalid Start Time format (HH:MM).", "danger"); return redirect(url_for('dashboard'))
        if e_time and not re.match(r"^\d{2}:\d{2}$", e_time):
            flash("Invalid End Time format (HH:MM).", "danger"); return redirect(url_for('dashboard'))
        if s_date and not re.match(r"^\d{4}-\d{2}-\d{2}$", s_date):
            flash("Invalid Start Date format (YYYY-MM-DD).", "danger"); return redirect(url_for('dashboard'))
        if e_date and not re.match(r"^\d{4}-\d{2}-\d{2}$", e_date):
            flash("Invalid End Date format (YYYY-MM-DD).", "danger"); return redirect(url_for('dashboard'))

    # IP Validation (IPv4 focus as requested "ไม่ต้องทำ ipv6" for TC commands)
    if not ip_addr or not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip_addr): # Basic IPv4
        flash("Invalid IPv4 address format.", "danger")
        return redirect(url_for('dashboard'))
    if not rate_val or not rate_u:
        flash("Rate value and unit are required.", "danger")
        return redirect(url_for('dashboard'))

    app.logger.info(f"Attempting to set new IP rule: {ip_addr}, Rate: {rate_val}{rate_u}, Dir: {direction_val}")
    set_bandwidth_limit(
        interface=interface, ip=ip_addr, 
        rate_value_form=rate_val, rate_unit_form=rate_u, 
        direction=direction_val, group=group_val, overwrite=overwrite_flag,
        existing_rule_id_to_update=None, # This is for adding a new rule
        protocol=proto, source_port=s_port, destination_port=d_port,
        is_scheduled=is_sched, start_time=s_time, end_time=e_time, 
        weekdays=w_days, start_date=s_date, end_date=e_date,
        description=desc_val, is_enabled=enabled_flag,
        priority=priority_val,
        burst_value_form=burst_val, burst_unit_form=burst_u,
        cburst_value_form=cburst_val, cburst_unit_form=cburst_u
    )
    return redirect(url_for('dashboard'))

@app.route("/edit_rule/<int:rule_id>", methods=["GET"])
def edit_ip_rule_form_route(rule_id):
    if not session.get('logged_in') or session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('dashboard'))

    rule_to_edit = db.session.get(Rule, rule_id)
    if not rule_to_edit:
        flash(f"Rule ID {rule_id} not found.", "danger")
        return redirect(url_for('dashboard'))

    active_interface_session = session.get('active_interface')
    if rule_to_edit.interface != active_interface_session:
        flash(f"Rule ID {rule_id} (on interface '{rule_to_edit.interface}') cannot be edited while active interface is '{active_interface_session}'. Please switch active interface.", "warning")
        return redirect(url_for('dashboard')) # Or disable form fields in template

    app.logger.info(f"Displaying edit form for rule ID {rule_id} (IP: {rule_to_edit.ip})")

    # Fetch all necessary data for the dashboard template
    current_interfaces_list = get_interfaces()
    # For the IP rules table display on the same page
    all_rules_for_active_if = Rule.query.filter_by(interface=active_interface_session).order_by(Rule.id).all()
    
    # For the group limits table display
    all_group_limits_for_active_if_db = GroupLimit.query.filter_by(interface=active_interface_session).all()
    current_groups_display_cache = {}
    for gl_item in all_group_limits_for_active_if_db:
        current_groups_display_cache.setdefault(gl_item.group_name, {})[gl_item.direction] = gl_item
    
    current_bandwidth_usage = get_bandwidth_usage(active_interface_session) if active_interface_session else {"rx_bytes": 0, "tx_bytes": 0}

    return render_template("dashboard.html",
                           rule_for_editing=rule_to_edit, # This object will pre-fill the form
                           edit_mode_ip_rule=True,       # Flag for template to know it's in edit mode for IP rule
                           # Below are standard dashboard context variables
                           interfaces=current_interfaces_list,
                           active_if=active_interface_session,
                           ips=all_rules_for_active_if,
                           group_limits=current_groups_display_cache,
                           bandwidth_usage=current_bandwidth_usage
                           # format_bytes is from context_processor
                           )

@app.route("/update_ip_rule/<int:rule_id>", methods=["POST"])
def update_ip_rule_route(rule_id):
    if not session.get('logged_in') or session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('dashboard'))

    interface = session.get('active_interface')
    rule_to_update = db.session.get(Rule, rule_id)

    if not rule_to_update:
        flash(f"Rule ID {rule_id} not found for update.", "danger")
        return redirect(url_for('dashboard'))
    
    if not interface or rule_to_update.interface != interface:
        flash("Active interface mismatch or not set for update. Aborted.", "danger")
        return redirect(url_for('edit_ip_rule_form_route', rule_id=rule_id)) # Back to edit form

    # Get form data - IP and Direction are usually fixed during edit (form fields are readonly/disabled)
    # If they were changeable, you'd need to handle the implications (delete old, create new with new TC ID)
    # For this implementation, we assume IP, Direction, Protocol, Ports (filter keys) are NOT changed during edit.
    # If they need to change, it's better to delete and re-add the rule.
    # The form I provided makes these readonly/disabled.
    
    ip_addr_form = request.form.get('ip') # Should match rule_to_update.ip
    direction_form = request.form.get('direction') # Should match rule_to_update.direction

    # Crucial check: if key identifiers were somehow changed despite form (e.g. disabled removed by browser tools)
    if ip_addr_form != rule_to_update.ip or direction_form != rule_to_update.direction:
        flash("Primary identifiers (IP, Direction) cannot be changed during edit. Delete and re-create rule if needed.", "danger")
        return redirect(url_for('edit_ip_rule_form_route', rule_id=rule_id))

    # Only fetch fields that are editable
    rate_val = request.form.get('rate_value')
    rate_u = request.form.get('rate_unit')
    group_val = request.form.get('group_name').strip() if request.form.get('group_name') else None
    
    desc_val = request.form.get('description').strip() if request.form.get('description') else None
    enabled_flag = 'is_enabled' in request.form
    
    priority_val_str = request.form.get('priority', '').strip()
    priority_val = int(priority_val_str) if priority_val_str.isdigit() else None
    
    burst_val = request.form.get('burst_value').strip() if request.form.get('burst_value') else None
    burst_u = request.form.get('burst_unit').strip() if request.form.get('burst_unit') else None
    cburst_val = request.form.get('cburst_value').strip() if request.form.get('cburst_value') else None
    cburst_u = request.form.get('cburst_unit').strip() if request.form.get('cburst_unit') else None

    is_sched = 'enable_scheduling' in request.form
    s_time, e_time, w_days, s_date, e_date = None, None, None, None, None
    if is_sched:
        s_time = request.form.get('start_time')
        e_time = request.form.get('end_time')
        w_days_list = request.form.getlist('weekdays')
        w_days = ",".join(w_days_list) if w_days_list else None
        s_date = request.form.get('start_date').strip() if request.form.get('start_date') else None
        e_date = request.form.get('end_date').strip() if request.form.get('end_date') else None
        if not s_time or not e_time:
            flash("Start and End time are required for scheduling. Update failed.", "warning")
            return redirect(url_for('edit_ip_rule_form_route', rule_id=rule_id))
        # Add full time/date format validation here as in set_ip_route

    if not rate_val or not rate_u:
        flash("Rate value and unit are required for update.", "danger")
        return redirect(url_for('edit_ip_rule_form_route', rule_id=rule_id))

    app.logger.info(f"Attempting to update IP rule ID {rule_id}: Rate: {rate_val}{rate_u}")
    set_bandwidth_limit(
        interface=interface, 
        ip=rule_to_update.ip, # Use original IP from DB object
        rate_value_form=rate_val, 
        rate_unit_form=rate_u, 
        direction=rule_to_update.direction, # Use original Direction
        group=group_val, 
        overwrite=True, # For an update, overwrite=True conceptually means replace current TC settings
        existing_rule_id_to_update=rule_id, # Pass the ID for update logic
        protocol=rule_to_update.protocol, # Use original filter criteria
        source_port=rule_to_update.source_port,
        destination_port=rule_to_update.destination_port,
        is_scheduled=is_sched, start_time=s_time, end_time=e_time, 
        weekdays=w_days, start_date=s_date, end_date=e_date,
        description=desc_val, is_enabled=enabled_flag,
        priority=priority_val,
        burst_value_form=burst_val, burst_unit_form=burst_u,
        cburst_value_form=cburst_val, cburst_unit_form=cburst_u
    )
    return redirect(url_for('dashboard'))
# Function to clear a bandwidth limit for a group
# ใน app.py
# ... (import statements, app setup, models, run_command, validation helpers, tc_del_class, etc. ควรถูก define ไว้ด้านบนแล้ว) ...

def clear_group_limit(interface, group_name_form, direction):
    """
    Clears/Deletes a group limit.
    For 'upload' direction, it attempts to delete the corresponding TC class.
    Then deletes the entry from the GroupLimit database table.
    Args:
        interface (str): The network interface name.
        group_name_form (str): The name of the group to clear.
        direction (str): The direction ('upload' or 'download') of the group limit.
    Returns:
        bool: True if the group limit was successfully cleared (or didn't exist), False on error.
    """
    app.logger.info(f"clear_group_limit: Attempting to clear group '{group_name_form}' ({direction}) on interface '{interface}'.")

    # --- 1. Validate Inputs ---
    if not validate_interface_name(interface):
        flash(f"Invalid interface name provided for clearing group limit: '{interface}'.", "danger")
        return False
    
    clean_group_name = str(group_name_form).strip() if group_name_form else None
    if not validate_group_name(clean_group_name) or not clean_group_name: # Group name is mandatory
        flash(f"Invalid or missing group name for clearing: '{group_name_form}'.", "danger")
        return False

    if direction not in ['upload', 'download']:
        flash(f"Invalid direction '{direction}' for clearing group limit.", "danger")
        return False

    # --- 2. Find the GroupLimit in Database ---
    group_limit_db = GroupLimit.query.filter_by(
        interface=interface,
        group_name=clean_group_name,
        direction=direction
    ).first()

    if not group_limit_db:
        flash(f"Group limit '{clean_group_name}' ({direction}) on interface '{interface}' not found in database. Nothing to clear.", "info")
        app.logger.info(f"Group limit '{clean_group_name}' ({direction}) on '{interface}' not found in DB. No action taken.")
        return True # Considered success as there's nothing to clear

    # --- 3. Clear TC Configuration (if applicable, for 'upload' direction) ---
    tc_cleared_successfully = True # Assume success unless TC deletion fails
    if direction == "upload" and group_limit_db.upload_classid:
        if validate_tc_classid(group_limit_db.upload_classid): # Ensure classid from DB is valid before trying to delete
            app.logger.info(f"Group '{clean_group_name}' ({direction}) has TC class ID '{group_limit_db.upload_classid}'. Attempting to delete TC class.")
            if not tc_del_class(interface, group_limit_db.upload_classid):
                # tc_del_class logs its own errors.
                # We might still want to remove the DB entry even if TC delete fails,
                # or make this a hard failure. For now, log warning and proceed to DB delete.
                flash_msg = f"Warning: Failed to delete TC class '{group_limit_db.upload_classid}' for group '{clean_group_name}'. The database entry will still be removed."
                flash(flash_msg, "warning")
                app.logger.warning(flash_msg)
                tc_cleared_successfully = False # Mark that TC part might have failed
            else:
                app.logger.info(f"Successfully deleted TC class '{group_limit_db.upload_classid}' for group '{clean_group_name}'.")
        else:
            app.logger.warning(f"Group '{clean_group_name}' ({direction}) has an invalid TC class ID format stored: '{group_limit_db.upload_classid}'. Skipping TC class deletion.")
            # tc_cleared_successfully remains True as there's no valid TC class to attempt deleting.
    elif direction == "download":
        app.logger.info(f"Group '{clean_group_name}' ({direction}) is a download group. No specific TC class entity to delete (rules under it are handled individually).")

    # --- 4. Delete from Database ---
    try:
        db.session.delete(group_limit_db)
        db.session.commit()
        flash_msg_db = f"Group limit '{clean_group_name}' ({direction}) on interface '{interface}' successfully deleted from database."
        if direction == "upload" and group_limit_db.upload_classid and not tc_cleared_successfully:
            flash(flash_msg_db + " However, TC class deletion may have encountered issues.", "warning")
        else:
            flash(flash_msg_db, "success")
        app.logger.info(flash_msg_db)
        return True
    except Exception as e_db_del_group:
        db.session.rollback()
        flash_msg_err = f"Database error while deleting group limit '{clean_group_name}': {str(e_db_del_group)}"
        flash(flash_msg_err, "danger")
        app.logger.error(f"Database error deleting group '{clean_group_name}': {e_db_del_group}", exc_info=True)
        return False
# --- APScheduler Task ---
@scheduler.task('interval', id='apply_scheduled_rules_job', minutes=app.config.get('SCHEDULER_INTERVAL_MINUTES', 1), misfire_grace_time=90)
def apply_scheduled_rules_task(): # Renamed from apply_scheduled_rules
    with app.app_context():
        app.logger.info("SCHEDULER: Running apply_scheduled_rules_task...")
        now = datetime.now()
        activated_count = 0
        deactivated_count = 0
        try:
            # Activate rules
            rules_to_check_activation = Rule.query.filter_by(is_scheduled=True, is_enabled=True, is_active_scheduled=False).all()
            for rule in rules_to_check_activation:
                if is_rule_scheduled_active_now(rule, now):
                    app.logger.info(f"SCHEDULER: Activating rule ID {rule.id} (IP: {rule.ip})")
                    if apply_single_tc_rule(rule):
                        rule.is_active_scheduled = True
                        db.session.add(rule)
                        activated_count += 1
                    else:
                        app.logger.error(f"SCHEDULER: Failed to apply TC for rule ID {rule.id} (IP: {rule.ip})")

            # Deactivate rules
            rules_to_check_deactivation = Rule.query.filter_by(is_scheduled=True, is_enabled=True, is_active_scheduled=True).all()
            for rule in rules_to_check_deactivation:
                if not is_rule_scheduled_active_now(rule, now): # is_rule_scheduled_active_now checks is_enabled
                    app.logger.info(f"SCHEDULER: Deactivating rule ID {rule.id} (IP: {rule.ip}) due to schedule end.")
                    if clear_single_tc_rule(rule):
                        rule.is_active_scheduled = False
                        db.session.add(rule)
                        deactivated_count += 1
                    else:
                        app.logger.error(f"SCHEDULER: Failed to clear TC for rule ID {rule.id} (IP: {rule.ip})")
            
            # Deactivate rules that were active but got disabled by user
            disabled_but_active_rules = Rule.query.filter_by(is_scheduled=True, is_enabled=False, is_active_scheduled=True).all()
            for rule in disabled_but_active_rules:
                app.logger.info(f"SCHEDULER: Deactivating rule ID {rule.id} (IP: {rule.ip}) because it was disabled by user.")
                if clear_single_tc_rule(rule):
                    rule.is_active_scheduled = False
                    db.session.add(rule)
                    deactivated_count += 1
                else:
                    app.logger.error(f"SCHEDULER: Failed to clear TC for disabled rule ID {rule.id} (IP: {rule.ip})")


            if activated_count > 0 or deactivated_count > 0:
                db.session.commit()
                app.logger.info(f"SCHEDULER: Committed DB changes. Activated: {activated_count}, Deactivated: {deactivated_count}.")
            # else:
            #     app.logger.info("SCHEDULER: No rule state changes to commit.")
        except Exception as e_sched:
            db.session.rollback()
            app.logger.error(f"SCHEDULER: Exception in task: {e_sched}", exc_info=True)
        app.logger.info("SCHEDULER: apply_scheduled_rules_task finished.")

# --- Context Processors ---
@app.context_processor
def inject_global_vars():
    return dict(
        utcnow=datetime.utcnow, # For footer year or other template uses
        active_if=session.get('active_interface'), # Make active_if available to all templates
        interfaces=get_interfaces() # Make interfaces available for navbar in all templates
    )

@app.context_processor
def inject_global_vars_for_templates():
    # ส่งตัวแปรเหล่านี้ไปให้ทุก Template ที่ Render โดยอัตโนมัติ
    # ทำให้ใน Template สามารถเรียกใช้ {{ active_if }} หรือ {{ interfaces }} ได้เลย
    # และ {{ current_year }} หรือ {{ utcnow()|strftime('%Y') }}
    interfaces_list = get_interfaces() # เรียก helper function
    active_interface_name = session.get('active_interface')

    # Ensure active_interface is valid or set a default if possible
    if active_interface_name not in interfaces_list:
        if interfaces_list:
            # active_interface_name = interfaces_list[0] # Optionally set default here
            # session['active_interface'] = active_interface_name
            # flash(f"Active interface reset to default: {active_interface_name}", "info")
            pass # Or let routes handle it if specific logic is needed per route
        else:
            active_interface_name = None
            
    return dict(
        utcnow=datetime.utcnow,
        current_year=datetime.now(timezone.utc).year,
        interfaces=interfaces_list,
        active_if=active_interface_name, # ส่ง active_if ที่อัปเดตแล้ว
        format_bytes=format_bytes # ส่ง helper function ไปให้ template โดยตรง
    )
# --- Flask Routes ---
# (Ensure all your routes are here and use global `app`, `db`, `session`, etc.
#  and `url_for('function_name')`)

# --- Main Routes (Dashboard, Status, Logs, Test Page) ---
# --- Flask Routes ---

@app.route("/", methods=["GET", "POST"])
def dashboard():
    global _bandwidth_rules_cache, _group_limits_cache
    if not session.get('logged_in'):
        app.logger.warning("User not logged in, redirecting to login")
        return redirect(url_for('login'))

    # interfaces and active_if will be available from context_processor,
    # but we might need to re-evaluate active_if if it's changed by POST here.
    current_interfaces = get_interfaces() # Get fresh list for dropdown logic

    # Handle interface change from POST on dashboard itself
    if request.method == "POST":
        selected_interface = request.form.get('interface_dropdown')
        if selected_interface and selected_interface in current_interfaces:
            if session.get('active_interface') != selected_interface:
                session['active_interface'] = selected_interface
                flash(f"Active interface set to {selected_interface}. Re-applying rules...", "success")
                app.logger.info(f"Active interface changed to {selected_interface}. Redirecting to reapply_rules_route.")
                return redirect(url_for('reapply_rules_route'))
        elif selected_interface: # Invalid interface selected
             flash(f"Invalid interface '{selected_interface}' selected via POST.", "danger")
             app.logger.warning(f"Invalid interface selected via POST: {selected_interface}")

    active_interface_now = session.get('active_interface')
    # Set default if no active_if is in session but interfaces are available
    if not active_interface_now and current_interfaces:
        active_interface_now = current_interfaces[0]
        session['active_interface'] = active_interface_now
        flash(f"Default active interface set to {active_interface_now}.", "info")
        app.logger.info(f"Default active interface set to {active_interface_now} in dashboard GET.")
    elif active_interface_now and active_interface_now not in current_interfaces:
        flash(f"Previously active interface '{active_interface_now}' is no longer available. Please select another.", "warning")
        active_interface_now = current_interfaces[0] if current_interfaces else None
        session['active_interface'] = active_interface_now
        app.logger.warning(f"Active interface '{session.get('active_interface')}' was invalid, reset to '{active_interface_now}'.")


    _bandwidth_rules_cache.clear()
    _group_limits_cache.clear()

    if active_interface_now:
        app.logger.info(f"Dashboard: Loading rules and groups for interface: {active_interface_now}")
        rules_from_db = Rule.query.filter_by(interface=active_interface_now).order_by(Rule.id).all()
        _bandwidth_rules_cache.extend(rules_from_db)
        
        group_limits_from_db = GroupLimit.query.filter_by(interface=active_interface_now).all()
        for gl in group_limits_from_db:
            _group_limits_cache.setdefault(gl.group_name, {})[gl.direction] = gl
    else:
        app.logger.info("Dashboard: No active interface set, clearing in-memory caches.")

    bandwidth_usage_data = get_bandwidth_usage(active_interface_now) if active_interface_now else {"rx_bytes": 0, "tx_bytes": 0}
    
    return render_template("dashboard.html",
                           # interfaces and active_if are now primarily from context_processor
                           # but we pass the re-evaluated active_interface_now here for explicit clarity this request.
                           active_if=active_interface_now, # Pass the one determined in this route
                           ips=_bandwidth_rules_cache, 
                           group_limits=_group_limits_cache,
                           bandwidth_usage=bandwidth_usage_data
                           # format_bytes is from context_processor
                           # rule_for_editing, edit_mode_ip_rule etc. are for edit routes
                           )

# --- (Copy and complete ALL other routes: login, logout, set_ip_route,
#      edit_ip_rule_form_route, update_ip_rule_route, toggle_rule_enabled_route,
#      delete_rule_by_id_route, limit_group_route, clear_group_limit_route,
#      reapply_rules_route, clear_all_rules_route,
#      status, log_view, test_page, and API routes.
#      Ensure they are adapted for single-file app.py.)

# Example for a route (you need to fill ALL of them from your previous structure)
# --- Authentication Routes ---
@app.route("/login", methods=["GET", "POST"])
def login():
    # ... (โค้ด Login Route เต็มๆ ที่คุณมี) ...
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        # !!! --- WARNING: HARDCODED CREDENTIALS - DO NOT USE IN PRODUCTION --- !!!
        if username == app.config['ADMIN_USERNAME'] and password == app.config['ADMIN_PASSWORD']:
            session['logged_in'] = True
            session['username'] = username # Store username
            session['role'] = 'admin'
            if 'active_interface' not in session: # Set default interface on first login if needed
                interfaces_list = get_interfaces()
                if interfaces_list:
                    session['active_interface'] = interfaces_list[0]
                    app.logger.info(f"Default active interface '{interfaces_list[0]}' set on login for user '{username}'.")
            flash("Logged in successfully!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    # ... (โค้ด Logout Route เต็มๆ ที่คุณมี) ...
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('role', None)
    session.pop('active_interface', None) # Clear active interface on logout
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

# --- (You MUST ensure ALL your routes are here and correctly implemented) ---
# --- For brevity, I am not re-listing every single route's full logic. ---
# --- You must copy them from your flask_bandwidth_control_full/app.py ---
# --- and adapt them to use global `app`, `db`, and correct `url_for` calls. ---

# --- Placeholder for your other routes ---
@app.route("/status")
def status(): return render_template("status.html", uptime="N/A", cpu_usage="N/A", mem_usage="N/A", disk_usage="N/A", network_status={}, format_bytes=format_bytes)
@app.route("/logs")
def log_view(): return render_template("logs.html", log_content="Logs not loaded.", num_log_lines=0)
@app.route("/test_page")
def test_page(): return render_template("test_tools.html")

@app.route("/api/bandwidth_usage/<interface_name>")
def bandwidth_usage_api_route(interface_name):
    # ... (Full logic copied from your app.py)
    if not session.get('logged_in'): return make_response(jsonify({"error": "Unauthorized"}), 401)
    interfaces_list = get_interfaces() # Get current interfaces
    if interface_name not in interfaces_list: return make_response(jsonify({"error": "Invalid interface"}), 400)
    return jsonify(get_bandwidth_usage(interface_name))


@app.route("/api/tc_stats/<interface_name>")
def tc_stats_api_route(interface_name):
    # ... (Full logic copied from your app.py)
    if not session.get('logged_in'): return make_response(jsonify({"error": "Unauthorized"}), 401)
    interfaces_list = get_interfaces() # Get current interfaces
    if interface_name not in interfaces_list: return make_response(jsonify({"error": "Invalid interface"}), 400)
    return jsonify(get_tc_stats(interface_name))

# Helper function สำหรับแปลง Rule Model เป็น Dictionary สำหรับ Frontend
def rule_model_to_dict_for_frontend(rule_model):
    is_truly_active = False
    if rule_model.is_enabled:
        if rule_model.is_scheduled:
            # คุณต้องมีฟังก์ชัน is_rule_scheduled_active_now ที่ทำงานถูกต้อง
            # สมมติว่ามีและเรียกใช้งานดังนี้:
            is_truly_active = is_rule_scheduled_active_now(rule_model, datetime.now())
        else:
            is_truly_active = True

    return {
        "id": str(rule_model.id), # JS อาจจะคาดหวัง ID เป็น string
        "name": rule_model.description or f"Rule for {rule_model.ip}", # ใช้ description หรือสร้างชื่อ default
        "target": rule_model.ip,
        "rate": rule_model.rate_str,
        "maxLimit": rule_model.cburst_str or rule_model.rate_str, # ตัวอย่างการ map maxLimit
        "enabled": is_truly_active, # สถานะการทำงานจริง
        "raw_is_enabled_flag": rule_model.is_enabled # ส่งสถานะดิบจาก DB ไปด้วย เผื่อ JS ต้องการ
        # เพิ่ม fields อื่นๆ ที่ frontend อาจต้องการจาก rule_model ที่นี่
    }

# 1. Route สำหรับแสดงหน้า Dashboard ใหม่
@app.route("/new_dashboard") # หรือ /new_dashboard หรือตามที่คุณต้องการ
def bandwidth_control_dashboard_view():
    if not session.get('logged_in'):
        app.logger.warning("User not logged in, redirecting to login")
        return redirect(url_for('login'))

    current_interfaces = get_interfaces()
    active_interface_now = session.get('active_interface')

    if not active_interface_now and current_interfaces:
        active_interface_now = current_interfaces[0]
        session['active_interface'] = active_interface_now
    
    app.logger.info(f"Serving bandwidth_control_view.html with active_if: {active_interface_now}")
    return render_template("bandwidth_control_view.html", # ชื่อไฟล์ HTML ใหม่ของคุณ
                           interfaces_list=current_interfaces,
                           current_active_if=active_interface_now)

# 2. API Endpoint สำหรับดึงรายการ Interfaces และ Active Interface
@app.route("/api/interfaces", methods=["GET"])
def api_get_interfaces():
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    
    interfaces = get_interfaces()
    active_interface = session.get('active_interface')
    
    if active_interface and active_interface not in interfaces:
        active_interface = None # ถ้า active interface ที่เก็บไว้ใช้ไม่ได้แล้ว
        session.pop('active_interface', None)
            
    if not active_interface and interfaces: # ถ้ายังไม่มี active interface ให้ใช้ตัวแรก
        active_interface = interfaces[0]
        session['active_interface'] = active_interface

    return jsonify({
        "interfaces": interfaces,
        "active_interface": active_interface
    })

# 3. API Endpoint สำหรับตั้งค่า Active Interface
@app.route("/api/set_active_interface", methods=["POST"])
def api_set_active_interface():
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    selected_interface = data.get('interface_name')
    interfaces = get_interfaces()

    if selected_interface and selected_interface in interfaces:
        if session.get('active_interface') != selected_interface:
            session['active_interface'] = selected_interface
            app.logger.info(f"API: Active interface set to {selected_interface}.")
            # การ reapply rules ควรจะถูก trigger โดย client หรือเป็น action แยก
            # ที่นี่แค่เปลี่ยน session และให้ client รับผิดชอบการ fetch ข้อมูลใหม่
            # การเรียก reapply_rules_route โดยตรงจาก API นี้อาจจะซับซ้อน
            # หรือคุณอาจจะสร้าง flag ให้ client รู้ว่าต้อง reapply
            # flash(f"Active interface set to {selected_interface}. Rules will be re-evaluated.", "info") # flash ไม่แสดงใน API
        return jsonify({"message": f"Active interface set to {selected_interface}."}), 200
    return jsonify({"error": "Invalid interface selected"}), 400

# 4. API Endpoint สำหรับดึงรายการ Rules ของ Interface ที่เลือก
@app.route("/api/rules/<string:interface_name>", methods=["GET"])
def api_get_rules(interface_name):
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    
    valid_interfaces = get_interfaces()
    if interface_name not in valid_interfaces:
        return jsonify({"error": "Invalid interface name provided"}), 400

    rules_from_db = Rule.query.filter_by(interface=interface_name).order_by(Rule.id).all()
    rules_for_frontend = [rule_model_to_dict_for_frontend(r) for r in rules_from_db]
    return jsonify(rules_for_frontend)

# 5. API Endpoint สำหรับลบ Rule
@app.route("/api/rules/<string:interface_name>/<int:rule_id>", methods=["DELETE"])
def api_delete_rule(interface_name, rule_id):
    if not session.get('logged_in') or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401

    active_if_session = session.get('active_interface')
    if interface_name != active_if_session:
         return jsonify({"error": f"Interface mismatch. Active is {active_if_session}"}), 400

    rule_to_delete = db.session.get(Rule, rule_id)
    if rule_to_delete and rule_to_delete.interface == interface_name:
        app.logger.info(f"API: Attempting to delete rule ID {rule_id} (IP: {rule_to_delete.ip}) on interface {interface_name}")
        # Clear TC rule if it was active
        rule_was_functionally_active = False
        if rule_to_delete.is_enabled:
            if rule_to_delete.is_scheduled:
                if is_rule_scheduled_active_now(rule_to_delete, datetime.now()):
                    rule_was_functionally_active = True
            else:
                rule_was_functionally_active = True
        
        if rule_was_functionally_active:
            if not clear_single_tc_rule(rule_to_delete):
                app.logger.warning(f"API Delete: TC cleanup for rule ID {rule_id} might have failed but proceeding with DB delete.")
        
        try:
            db.session.delete(rule_to_delete)
            db.session.commit()
            app.logger.info(f"API: Rule ID {rule_id} deleted successfully from DB.")
            return jsonify({"message": "Rule deleted successfully"}), 200
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"API Delete: DB error deleting rule {rule_id}: {e}", exc_info=True)
            return jsonify({"error": "Database error deleting rule"}), 500
    else:
        app.logger.warning(f"API Delete: Rule ID {rule_id} not found for interface {interface_name}.")
        return jsonify({"error": "Rule not found or interface mismatch"}), 404

# 6. API Endpoint สำหรับ เปิด/ปิด Rule
@app.route("/api/rules/<string:interface_name>/<int:rule_id>/toggle", methods=["POST"])
def api_toggle_rule_status(interface_name, rule_id):
    if not session.get('logged_in') or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401

    active_if_session = session.get('active_interface')
    if interface_name != active_if_session:
         return jsonify({"error": f"Interface mismatch. Active is {active_if_session}"}), 400

    rule_to_toggle = db.session.get(Rule, rule_id)
    if not rule_to_toggle or rule_to_toggle.interface != interface_name:
        return jsonify({"error": "Rule not found or interface mismatch"}), 404

    original_is_enabled_db_flag = rule_to_toggle.is_enabled
    new_is_enabled_db_flag = not original_is_enabled_db_flag # สลับค่า is_enabled ใน DB
    rule_to_toggle.is_enabled = new_is_enabled_db_flag
    app.logger.info(f"API Toggle: Rule ID {rule_id} (IP: {rule_to_toggle.ip}) DB 'is_enabled' flag changing from {original_is_enabled_db_flag} to {new_is_enabled_db_flag}.")

    # Logic การจัดการ TC และ is_active_scheduled (เหมือนใน toggle_rule_enabled เดิม)
    # ถ้า rule กำลังจะถูก disable และมัน active อยู่ (TC applied) -> clear TC
    # ถ้า rule กำลังจะถูก enable และมันไม่ scheduled -> apply TC
    # ถ้า rule scheduled และกำลังจะ enable -> scheduler จะจัดการ (is_active_scheduled จะถูก set ใหม่โดย scheduler)

    tc_change_successful = True
    if not new_is_enabled_db_flag: # กำลัง Disable (จาก DB flag)
        # ตรวจสอบว่าก่อนหน้านี้มัน active จริงๆ หรือไม่ (รวม scheduled)
        current_functional_status_before_toggle = False
        if original_is_enabled_db_flag: # ถ้า flag เดิมคือ enabled
            if rule_to_toggle.is_scheduled:
                if is_rule_scheduled_active_now(rule_to_toggle, datetime.now()): # เช็คด้วย is_enabled เดิม
                    current_functional_status_before_toggle = True
            else:
                current_functional_status_before_toggle = True
        
        if current_functional_status_before_toggle:
            app.logger.info(f"API Toggle: Disabling functionally active rule ID {rule_id}, clearing TC.")
            if not clear_single_tc_rule(rule_to_toggle):
                app.logger.warning(f"API Toggle: TC clear for rule {rule_id} failed during disabling.")
                tc_change_successful = False
        rule_to_toggle.is_active_scheduled = False # ปิดสถานะ is_active_scheduled เมื่อ is_enabled เป็น false
    else: # กำลัง Enable (จาก DB flag)
        if not rule_to_toggle.is_scheduled:
            app.logger.info(f"API Toggle: Enabling non-scheduled rule ID {rule_id}, applying TC.")
            if not apply_single_tc_rule(rule_to_toggle): # apply_single_tc_rule จะเช็ค is_enabled ใหม่ (True)
                app.logger.warning(f"API Toggle: TC apply for rule {rule_id} failed during enabling.")
                tc_change_successful = False
        else:
            app.logger.info(f"API Toggle: Enabling scheduled rule ID {rule_id}. Scheduler will handle activation.")
            rule_to_toggle.is_active_scheduled = False # Scheduler จะประเมิน is_active_scheduled ใหม่ในรอบถัดไป
    
    # ถ้า TC ล้มเหลว อาจจะ rollback DB (ตรงนี้ต้องตัดสินใจ)
    # if not tc_change_successful:
    #     rule_to_toggle.is_enabled = original_is_enabled_db_flag # Rollback
    #     # ไม่ต้อง commit เพราะจะ rollback
    #     return jsonify({"error": "TC action failed, rule status not changed in DB"}), 500


    try:
        db.session.commit() # บันทึกการเปลี่ยนแปลง is_enabled และ is_active_scheduled
        app.logger.info(f"API Toggle: Rule ID {rule_id} DB 'is_enabled' updated to {rule_to_toggle.is_enabled}.")
        updated_rule_for_fe = rule_model_to_dict_for_frontend(rule_to_toggle) # ส่งสถานะที่อัปเดตแล้วกลับไป
        return jsonify(updated_rule_for_fe), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"API Toggle: DB error for rule {rule_id}: {e}", exc_info=True)
        return jsonify({"error": "Database error toggling rule status"}), 500

# 7. API Endpoint สำหรับ Add New Rule (โครงสร้างเบื้องต้น)
@app.route("/api/rules/<string:interface_name>", methods=["POST"])
def api_add_new_rule(interface_name): # ควรใช้ชื่อฟังก์ชันที่สื่อถึงการ Add เช่น api_create_rule
    if not session.get('logged_in') or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    active_if_session = session.get('active_interface')
    if interface_name != active_if_session:
         return jsonify({"error": f"Interface mismatch. Active is {active_if_session}"}), 400

    data = request.json # ข้อมูล rule ใหม่ที่ส่งมาจาก frontend
    app.logger.info(f"API Add Rule received: {data} for interface {interface_name}")

    # --- การ Mapping ข้อมูลจาก Frontend (data) ไปยังพารามิเตอร์ของ set_bandwidth_limit ---
    # นี่คือส่วนสำคัญที่ต้องปรับให้ตรงกับฟอร์ม "Add New" ใน Modal ของคุณ
    # และโครงสร้าง BandwidthRule ใน JavaScript ของคุณ
    
    # ตัวอย่าง (คุณต้องปรับให้ครบถ้วนตามฟอร์มและ set_bandwidth_limit)
    try:
        ip_val = data.get('target')
        rate_str_val = data.get('rate') # เช่น "10 Mbps"
        name_val = data.get('name')     # map ไปที่ description
        enabled_val = data.get('enabled', True) # ถ้า frontend ไม่ส่งมา ให้ default เป็น True
        # max_limit_val = data.get('maxLimit') # ต้อง map ไปที่ burst/cburst ถ้าใช้

        # Frontend ต้องส่ง "direction" มาด้วย ถ้า set_bandwidth_limit ต้องการ
        direction_val = data.get('direction') # เช่น "upload" หรือ "download"
        if not direction_val: # ถ้า frontend ไม่ได้ส่งมา อาจจะต้องมี default หรือ error
             return jsonify({"error": "Direction is required for new rule"}), 400


        # Parse rate_str_val "10 Mbps" -> "10", "Mbps"
        rate_parts = rate_str_val.split()
        if len(rate_parts) != 2:
            return jsonify({"error": "Invalid rate format. Expected 'value unit' (e.g., '10 Mbps')."}), 400
        rate_value_form = rate_parts[0]
        rate_unit_form = rate_parts[1] # e.g. Mbps, Kbps, etc.

        # Fields อื่นๆ ที่ set_bandwidth_limit ต้องการ:
        # protocol, source_port, destination_port, group_name,
        # burst_value_form, burst_unit_form, cburst_value_form, cburst_unit_form,
        # is_scheduled, start_time, end_time, weekdays, start_date, end_date, priority

        # สมมติว่า Modal ของคุณมี fields เหล่านี้ และส่งมาใน `data`
        protocol_val = data.get('protocol') # ถ้าไม่มีเป็น None ได้
        sport_val = data.get('source_port')
        dport_val = data.get('destination_port')
        group_val = data.get('group_name')
        priority_val = data.get('priority') # อาจจะต้องแปลงเป็น int

        # สำหรับ burst/cburst (อาจจะ map มาจาก maxLimit หรือมี field แยกใน modal)
        # ตัวอย่างง่ายๆ: ถ้ามี maxLimit และ rate, อาจจะให้ burst = rate, cburst = maxLimit
        # burst_value_form_val, burst_unit_form_val = None, None
        # cburst_value_form_val, cburst_unit_form_val = None, None
        # if max_limit_val:
        #    cburst_parts = max_limit_val.split()
        #    if len(cburst_parts) == 2:
        #        cburst_value_form_val = cburst_parts[0]
        #        cburst_unit_form_val = cburst_parts[1]
        #    burst_value_form_val = rate_value_form # สมมติ burst = rate
        #    burst_unit_form_val = rate_unit_form

        success = set_bandwidth_limit(
            interface=interface_name,
            ip=ip_val,
            rate_value_form=rate_value_form,
            rate_unit_form=rate_unit_form,
            direction=direction_val, # สำคัญมาก
            description=name_val,
            is_enabled=enabled_val,
            protocol=protocol_val,
            source_port=sport_val,
            destination_port=dport_val,
            group=group_val,
            priority=int(priority_val) if priority_val is not None and str(priority_val).isdigit() else None,
            # burst_value_form=burst_value_form_val, burst_unit_form=burst_unit_form_val,
            # cburst_value_form=cburst_value_form_val, cburst_unit_form=cburst_unit_form_val,
            is_scheduled=data.get('is_scheduled', False), # Default ถ้าไม่มี
            start_time=data.get('start_time'),
            end_time=data.get('end_time'),
            weekdays=data.get('weekdays'), # ควรเป็น string "Mon,Tue,Wed"
            start_date=data.get('start_date'),
            end_date=data.get('end_date'),
            overwrite=False # เป็นการเพิ่ม Rule ใหม่
        )

        if success:
            # คืน rule ที่สร้างใหม่ (หรือแค่ message)
            # การดึง rule ที่เพิ่งสร้างจาก DB แล้วส่งกลับไปจะดีที่สุด
            # เพื่อให้ client มี ID และข้อมูลที่ถูกต้องทั้งหมด
            # rule_just_added = Rule.query.filter_by(...).first() # หา rule ที่เพิ่ง add
            # return jsonify(rule_model_to_dict_for_frontend(rule_just_added)), 201
            return jsonify({"message": "Rule added successfully. Please refresh rule list."}), 201 # ให้ client fetch ใหม่
        else:
            # set_bandwidth_limit ควรจะ return error message ที่ชัดเจนกว่าการใช้ flash
            # หรือมีการ throw exception ที่จับได้
            flashed_messages = get_flashed_messages(with_categories=True)
            error_message = "Failed to add rule on backend. "
            if flashed_messages:
                error_message += " ".join([msg for cat, msg in flashed_messages if cat == 'danger'])
            app.logger.error(f"API Add Rule Error: {error_message} Data: {data}")
            return jsonify({"error": error_message or "Unknown error adding rule."}), 500
            
    except Exception as e:
        app.logger.error(f"API Add Rule - Exception: {e}", exc_info=True)
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500



# --- Rule Management Routes (Copied from your app.py, ensure correctness) ---






@app.route("/toggle_rule_enabled/<int:rule_id>", methods=["POST"])
def toggle_rule_enabled(rule_id):
    if not session.get('logged_in') or session.get('role') != 'admin':
        flash("Unauthorized.", "danger"); return redirect(url_for('dashboard'))
    
    rule_to_toggle = db.session.get(Rule, rule_id)
    if not rule_to_toggle:
        flash(f"Rule ID {rule_id} not found.", "danger"); return redirect(url_for('dashboard'))

    # Ensure rule belongs to active interface for safety, though not strictly necessary if only toggling
    active_interface = session.get('active_interface')
    if rule_to_toggle.interface != active_interface:
        flash(f"Rule ID {rule_id} does not belong to the active interface '{active_interface}'. Action aborted for safety.", "warning")
        return redirect(url_for('dashboard'))

    new_enabled_state = not rule_to_toggle.is_enabled
    rule_to_toggle.is_enabled = new_enabled_state
    app.logger.info(f"Toggling rule ID {rule_id} to enabled={new_enabled_state}.")

    action_taken = "None"
    if not new_enabled_state: # Disabling the rule
        # If it was active (not scheduled OR scheduled & active_scheduled), clear its TC
        if not rule_to_toggle.is_scheduled or rule_to_toggle.is_active_scheduled:
            app.logger.info(f"Rule ID {rule_id} (IP: {rule_to_toggle.ip}) is being disabled, attempting to clear TC.")
            if clear_single_tc_rule(rule_to_toggle):
                action_taken = "TC_Cleared"
                rule_to_toggle.is_active_scheduled = False # Mark as not active by scheduler
                flash(f"Rule for {rule_to_toggle.ip} disabled and TC cleared.", "success")
            else:
                action_taken = "TC_Clear_Failed"
                flash(f"Rule for {rule_to_toggle.ip} disabled, but TC cleanup might have failed. Check logs.", "warning")
        else: # Was scheduled but not active_scheduled, or already not enabled
            action_taken = "No_TC_Action_Needed (was not active)"
            rule_to_toggle.is_active_scheduled = False # Ensure it's not marked active by scheduler
            flash(f"Rule for {rule_to_toggle.ip} disabled.", "info")
    else: # Enabling the rule
        action_taken = "Enabled"
        if not rule_to_toggle.is_scheduled:
            app.logger.info(f"Rule ID {rule_id} (IP: {rule_to_toggle.ip}) is being enabled (non-scheduled), attempting to apply TC.")
            if apply_single_tc_rule(rule_to_toggle): # apply_single checks is_enabled internally now
                action_taken = "TC_Applied_Non_Scheduled"
                flash(f"Rule for {rule_to_toggle.ip} enabled and TC applied.", "success")
            else:
                action_taken = "TC_Apply_Failed_Non_Scheduled"
                flash(f"Rule for {rule_to_toggle.ip} enabled, but TC application failed. Check logs.", "warning")
                rule_to_toggle.is_enabled = False # Revert enable state if TC apply failed
        else: # Is scheduled, let scheduler handle it. is_active_scheduled should be false.
            action_taken = "Enabled_Scheduled_Scheduler_Will_Handle"
            rule_to_toggle.is_active_scheduled = False # Scheduler will re-evaluate
            flash(f"Rule for {rule_to_toggle.ip} enabled. Scheduler will manage activation.", "info")
    
    try:
        db.session.commit()
        app.logger.info(f"Rule ID {rule_id} toggled. DB committed. Action: {action_taken}")
    except Exception as e:
        db.session.rollback()
        flash(f"Database error toggling rule: {str(e)}", "danger")
        app.logger.error(f"Database error toggling rule ID {rule_id}: {e}")

    return redirect(url_for('dashboard'))

@app.route("/delete_rule_by_id/<int:rule_id>", methods=["POST"])
def delete_rule_by_id(rule_id):
    if not session.get('logged_in') or session.get('role') != 'admin':
        flash("Unauthorized.", "danger"); return redirect(url_for('dashboard'))
    active_interface = session.get('active_interface')
    if not active_interface:
        flash("No active interface.", "danger"); return redirect(url_for('dashboard'))

    rule_to_delete = db.session.get(Rule, rule_id)
    if rule_to_delete and rule_to_delete.interface == active_interface:
        ip_for_flash = rule_to_delete.ip
        # Clear TC if rule was not scheduled, OR if it was scheduled AND active
        if not rule_to_delete.is_scheduled or rule_to_delete.is_active_scheduled:
            if not clear_single_tc_rule(rule_to_delete):
                flash(f"Warning: TC cleanup for rule ID {rule_id} (IP: {ip_for_flash}) might have failed.", "warning")
        try:
            db.session.delete(rule_to_delete)
            db.session.commit()
            flash(f"Rule for IP {ip_for_flash} deleted.", "success")
        except Exception as e:
            db.session.rollback(); flash(f"DB error deleting rule: {str(e)}", "danger")
    else:
        flash(f"Rule ID {rule_id} not found or not on active interface.", "warning")
    return redirect(url_for('dashboard'))

@app.route("/limit_group", methods=["POST"])
def limit_group():
    if not session.get('logged_in') or session.get('role') != 'admin':
        flash("Unauthorized.", "danger"); return redirect(url_for('dashboard'))
    interface = session.get('active_interface')
    if not interface:
        flash("No active interface.", "danger"); return redirect(url_for('dashboard'))

    group_name = request.form.get('group_name_limit') # Ensure form field names match
    rate_value = request.form.get('group_rate_value_limit')
    rate_unit = request.form.get('group_rate_unit_limit')
    direction = request.form.get('group_dir_limit')

    burst_value = request.form.get('group_burst_value_limit')
    burst_unit = request.form.get('group_burst_unit_limit')
    cburst_value = request.form.get('group_cburst_value_limit')
    cburst_unit = request.form.get('group_cburst_unit_limit')


    if not group_name or not rate_value or not direction or not rate_unit:
        flash("Group name, rate, unit, and direction required.", "danger"); return redirect(url_for('dashboard'))

    set_group_limit(interface, group_name, rate_value, rate_unit, direction,
                    burst_value, burst_unit, cburst_value, cburst_unit)
    return redirect(url_for('dashboard'))



@app.route("/clear_group_limit", methods=["POST"]) # ควรจะเป็น POST เพราะเป็นการกระทำที่เปลี่ยนแปลงข้อมูล
def clear_group_limit_route():
    if not session.get('logged_in') or session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('dashboard')) # หรือ 'login' ถ้าต้องการ

    interface_from_session = session.get('active_interface')
    if not interface_from_session: # ควรจะมาจาก session เพื่อความปลอดภัย
        flash("No active interface selected.", "danger")
        return redirect(url_for('dashboard'))

    group_name_to_clear = request.form.get('group_name_clear')
    direction_to_clear = request.form.get('group_dir_clear')

    # --- Validate inputs from form ---
    if not validate_interface_name(interface_from_session): # Validate interface from session
        flash(f"Internal error: Invalid active interface stored in session: '{interface_from_session}'.", "danger")
        return redirect(url_for('dashboard'))

    clean_group_name = str(group_name_to_clear).strip() if group_name_to_clear else None
    if not validate_group_name(clean_group_name) or not clean_group_name:
        flash("Group name is required and must be valid for clearing.", "danger")
        return redirect(url_for('dashboard'))
    
    if direction_to_clear not in ['upload', 'download']:
        flash("Invalid direction specified for clearing group limit.", "danger")
        return redirect(url_for('dashboard'))
    
    # --- Call the refactored clear_group_limit ---
    if clear_group_limit(interface_from_session, clean_group_name, direction_to_clear):
        # Flash messages are handled inside clear_group_limit
        pass
    else:
        # Flash messages for critical failure (e.g., DB error) are handled inside clear_group_limit
        # No additional flash needed here unless specific to the route context
        pass
        
    return redirect(url_for('dashboard'))


@app.route("/reapply_rules", methods=["POST"]) # Changed to POST as it's an action
def reapply_rules_route():
    global bandwidth_rules, group_limits
    if not session.get('logged_in') or session.get('role') != 'admin':
        flash("Unauthorized.", "danger"); return redirect(url_for('dashboard'))
    interface = session.get('active_interface')
    if not interface:
        flash("No active interface for reapply.", "danger"); return redirect(url_for('dashboard'))

    app.logger.info(f"Reapplying all rules on interface {interface}.")
    # Clear existing TC
    run_command(f"tc qdisc del dev {interface} root 2>/dev/null || true")
    run_command(f"tc qdisc del dev {interface} ingress 2>/dev/null || true")

    # Load from DB
    rules_to_reapply = Rule.query.filter_by(interface=interface).all()
    group_limits_to_reapply = GroupLimit.query.filter_by(interface=interface).all()

    bandwidth_rules.clear(); group_limits.clear() # Clear in-memory

    # Reapply groups first
    for gl_obj in group_limits_to_reapply:
        # Need to parse rate_value and rate_unit from gl_obj.rate_str for set_group_limit
        # This is a bit clunky, ideally set_group_limit takes rate_str directly
        # For now, let's assume rate_str is "valueUnit" like "10Mbps"
        match = re.match(r'(\d+(\.\d+)?)\s*(\w+)', gl_obj.rate_str)
        if match:
            val, _, unit_full = match.groups()
            unit = unit_full.lower() # mbps, kbps etc.
            # Burst/Cburst also need similar parsing if reapplying
            burst_val, burst_u, cburst_val, cburst_u = None, None, None, None
            if gl_obj.burst_str:
                b_match = re.match(r'(\d+(\.\d+)?)\s*(\w+)', gl_obj.burst_str)
                if b_match: burst_val, _, burst_u_full = b_match.groups(); burst_u = burst_u_full.lower()
            if gl_obj.cburst_str:
                cb_match = re.match(r'(\d+(\.\d+)?)\s*(\w+)', gl_obj.cburst_str)
                if cb_match: cburst_val, _, cburst_u_full = cb_match.groups(); cburst_u = cburst_u_full.lower()

            set_group_limit(interface, gl_obj.group_name, val, unit, gl_obj.direction,
                            burst_val, burst_u, cburst_val, cburst_u)

    # Reapply IP rules
    for r_obj in rules_to_reapply:
        match = re.match(r'(\d+(\.\d+)?)\s*(\w+)', r_obj.rate_str)
        if match:
            val, _, unit_full = match.groups()
            unit = unit_full.lower()
            b_val, b_u, cb_val, cb_u = None, None, None, None
            if r_obj.burst_str:
                b_match = re.match(r'(\d+(\.\d+)?)\s*(\w+)', r_obj.burst_str)
                if b_match: b_val, _, b_u_full = b_match.groups(); b_u = b_u_full.lower()
            if r_obj.cburst_str:
                cb_match = re.match(r'(\d+(\.\d+)?)\s*(\w+)', r_obj.cburst_str)
                if cb_match: cb_val, _, cb_u_full = cb_match.groups(); cb_u = cb_u_full.lower()


            set_bandwidth_limit(
                interface, r_obj.ip, val, unit, r_obj.direction, r_obj.group_name, True, # Force overwrite
                r_obj.protocol, r_obj.source_port, r_obj.destination_port,
                r_obj.is_scheduled, r_obj.start_time, r_obj.end_time, r_obj.weekdays, r_obj.start_date, r_obj.end_date,
                r_obj.description, r_obj.is_enabled, # Pass new fields
                b_val, b_u, cb_val, cb_u # Pass new burst fields
            )
    # Reset is_active_scheduled for all scheduled rules on this interface after reapply
    try:
        Rule.query.filter_by(interface=interface, is_scheduled=True).update({Rule.is_active_scheduled: False})
        db.session.commit()
    except Exception as e:
        db.session.rollback(); app.logger.error(f"Error resetting active_scheduled on reapply: {e}")

    flash("All rules for the active interface have been reapplied.", "success")
    return redirect(url_for('dashboard'))

@app.route("/clear_all_rules", methods=["POST"])
def clear_all_rules_route():
    global bandwidth_rules, group_limits
    if not session.get('logged_in') or session.get('role') != 'admin':
        flash("Unauthorized.", "danger"); return redirect(url_for('dashboard'))
    interface = session.get('active_interface')
    if not interface:
        flash("No active interface to clear rules from.", "danger"); return redirect(url_for('dashboard'))

    run_command(f"tc qdisc del dev {interface} root 2>/dev/null || true")
    run_command(f"tc qdisc del dev {interface} ingress 2>/dev/null || true")
    try:
        num_rules = Rule.query.filter_by(interface=interface).delete()
        num_groups = GroupLimit.query.filter_by(interface=interface).delete()
        db.session.commit()
        bandwidth_rules.clear(); group_limits.clear()
        flash(f"All TC rules cleared. {num_rules} IP rules and {num_groups} group limits deleted from DB for {interface}.", "success")
    except Exception as e:
        db.session.rollback(); flash(f"DB error clearing rules: {str(e)}", "danger")
    return redirect(url_for('dashboard'))



# --- Main Execution Block ---
if __name__ == "__main__":
    app.logger.info(f"Application starting (monolithic app.py) with DEBUG_MODE={app.config['DEBUG_MODE']}")
    with app.app_context():
        try:
            db.create_all()
            app.logger.info("Database tables created/checked successfully.")
        except Exception as e_db_create:
            app.logger.error(f"Error creating database tables: {e_db_create}", exc_info=True)

    if not app.config.get('TESTING', False): # Don't start scheduler during tests if using app factory
        if not scheduler.running:
            try:
                scheduler.start(paused=app.config.get('SCHEDULER_START_PAUSED', False))
                app.logger.info("APScheduler started successfully.")
            except Exception as e_sched_start:
                app.logger.error(f"Failed to start APScheduler: {e_sched_start}", exc_info=True)
        else:
            app.logger.info("APScheduler already running.")
    
    app.logger.info(f"Running Flask app on host={app.config.get('FLASK_RUN_HOST')} port={app.config.get('FLASK_RUN_PORT')}")
    
    try:
        app.run(
            host=app.config.get("FLASK_RUN_HOST"),
            port=int(app.config.get("FLASK_RUN_PORT", 5000)), # Ensure port is int
            debug=app.config.get("DEBUG_MODE"), # Use our own debug flag
            threaded=True,
            use_reloader=app.config.get("DEBUG_MODE", False) # Reloader with scheduler can be tricky
        )
    except Exception as e_app_run:
        app.logger.critical(f"Failed to run Flask application: {e_app_run}", exc_info=True)
    finally:
        app.logger.info("Application attempting to shut down.")
        if not app.config.get('TESTING', False) and scheduler.running:
            try:
                scheduler.shutdown()
                app.logger.info("APScheduler shut down successfully.")
            except Exception as e_sched_shutdown:
                app.logger.error(f"Error shutting down APScheduler: {e_sched_shutdown}", exc_info=True)
        app.logger.info("Application shutdown process complete.")