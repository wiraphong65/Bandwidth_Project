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
def run_command(command):
    app.logger.debug(f"Executing command: {command}")
    try:
        process = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', timeout=15)
        output_str = (process.stdout + process.stderr).strip()
        if output_str: app.logger.debug(f"Command output: {output_str}")
        return output_str
    except subprocess.CalledProcessError as e:
        error_msg = (e.stdout + e.stderr).strip() if e.stdout or e.stderr else "No output"
        app.logger.error(f"Command failed: {command} - Exit: {e.returncode} - Output: {error_msg}")
        return None
    except FileNotFoundError:
        app.logger.error(f"Command not found: {command.split(' ')[0]}. Is it installed and in PATH?")
        return None
    except subprocess.TimeoutExpired:
        app.logger.error(f"Command timed out: {command}")
        return None
    except Exception as e_run_cmd:
        app.logger.exception(f"Exception executing command: {command}")
        return None

def get_interfaces():
    app.logger.debug("Getting network interfaces")
    output = run_command("ip -o link show") # Linux specific
    interfaces = []
    if output:
        for line in output.splitlines():
            match = re.match(r'^\d+:\s+([\w.-]+):', line)
            if match:
                iface = match.group(1)
                if iface != 'lo' and not iface.startswith(('docker', 'veth', 'br-', 'virbr', 'kube-', 'cni', 'flannel', 'vxlan', 'geneve', 'bond', 'dummy', 'ifb')):
                    interfaces.append(iface)
    app.logger.debug(f"Found interfaces: {interfaces}")
    return interfaces

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
    # ... (Full implementation from flask_bandwidth_control_full/app.py, ensuring run_command is used)
    # This function needs to be robustly implemented with correct regex for your tc output.
    # The version in the uploaded file was a good start.
    if not interface: return {}
    app.logger.debug(f"Fetching TC stats for interface: {interface}")
    tc_stats = {}
    class_output = run_command(f"tc -s class show dev {interface}")
    if class_output:
        # Regex for 'class htb <id> ... bytes <bytes> ... pkts <pkts>' (order of bytes/pkts might vary)
        # Or 'class htb <id> ... Sent <bytes> bytes <pkts> pkts'
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
                try: tc_stats[class_id] = {'pkts': int(pkts_val), 'bytes': int(bytes_val)}
                except ValueError: app.logger.warning(f"Could not parse stats for class {class_id}")

    filter_output = run_command(f"tc -s filter show dev {interface} ingress")
    if filter_output:
        # Looking for 'flowid :<handle_id> ... pkts <pkts> bytes <bytes>'
        # Or 'police ... pkts <pkts> bytes <bytes> ... flowid :<handle_id>'
        filter_pattern = re.compile(
            r"filter\s+parent\s+ffff:.*?protocol\s+\S+.*?pref\s+\d+.*?"
            r"(?:handle\s+(?P<handle_hex>0x[0-9a-fA-F]+)\s+)?.*?"
            r"(?:flowid\s+:(?P<flowid_minor>\d+)|police.*?flowid\s+:(?P<flowid_minor_alt>\d+)).*?"
            r"pkts\s+(?P<packets>\d+)\s+bytes\s+(?P<bytes_val>\d+)", # Corrected group name
            re.DOTALL
        )
        for match in filter_pattern.finditer(filter_output):
            data = match.groupdict()
            filter_id_key = None
            pkts_val = data.get('packets')
            bytes_val_parsed = data.get('bytes_val') # Corrected group name
            
            flowid_minor_val = data.get('flowid_minor') or data.get('flowid_minor_alt')
            
            if flowid_minor_val: filter_id_key = f":{flowid_minor_val}"
            elif data.get('handle_hex'): filter_id_key = data.get('handle_hex')
            
            if filter_id_key and pkts_val and bytes_val_parsed:
                try: tc_stats[filter_id_key] = {'pkts': int(pkts_val), 'bytes': int(bytes_val_parsed)}
                except ValueError: app.logger.warning(f"Could not parse stats for filter {filter_id_key}")
    return tc_stats


def parse_tc_qdisc_show(interface):
    # ... (Full implementation from flask_bandwidth_control_full/app.py)
    qdiscs = {}
    output = run_command(f"tc qdisc show dev {interface}")
    if output:
        qdisc_regex = re.compile(r'qdisc\s+([a-zA-Z0-9_-]+)\s+([0-9a-fA-F]+:(?:[0-9a-fA-F]*)?)\s+.*?dev\s+([\w.-]+)\s*(?:parent\s+([0-9a-fA-F]+:(?:[0-9a-fA-F]*)?))?.*?')
        for line in output.splitlines():
            match = qdisc_regex.match(line)
            if match and match.group(3) == interface:
                qdiscs[match.group(2)] = {'type': match.group(1), 'parent': match.group(4) or 'root'}
    return qdiscs

def parse_tc_class_show(interface):
    # ... (Full implementation from flask_bandwidth_control_full/app.py)
    classes = {}
    output = run_command(f"tc class show dev {interface}")
    if output:
        class_regex = re.compile(
            r"class\s+(?P<type>\w+)\s+(?P<classid>\w+:\w+)\s+parent\s+(?P<parent>\w+:\w*)"
            r"(?:\s+prio\s+(?P<prio>\d+))?\s+rate\s+(?P<rate>[\w./]+(?:bit|bps|Bps))" # Simplified rate
            r"(?:\s+ceil\s+(?P<ceil>[\w./]+(?:bit|bps|Bps)))?"
            r"(?:\s+burst\s+(?P<burst>[\w./]+(?:b|bit|Bps)))?"
            r"(?:\s+cburst\s+(?P<cburst>[\w./]+(?:b|bit|Bps)))?", re.IGNORECASE
        )
        for line in output.splitlines():
            match = class_regex.search(line)
            if match:
                data = match.groupdict()
                classes[data['classid']] = {
                    'parent': data['parent'], 'prio': int(data['prio']) if data['prio'] else 0,
                    'rate_str': data['rate'], 'ceil_str': data.get('ceil') or data['rate'],
                    'burst_str': data.get('burst'), 'cburst_str': data.get('cburst')
                }
    return classes

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
def apply_single_tc_rule(rule_obj):
    if not rule_obj or not rule_obj.interface:
        app.logger.error("apply_single_tc_rule called with invalid rule object or interface.")
        return False
    
    if not rule_obj.is_enabled: # NEW: Check if rule is enabled
        app.logger.info(f"Rule ID {rule_obj.id} is disabled. Skipping TC application.")
        return True # Considered success as no action needed

    interface = rule_obj.interface
    ip = rule_obj.ip
    # Use parsed rate for TC command from a helper or re-parse here
    rate_val_str, tc_unit, _ = parse_rate_to_tc_format(rule_obj.rate_str)
    if not rate_val_str:
        app.logger.error(f"Cannot apply TC rule for DB ID {rule_obj.id}: Invalid rate_str '{rule_obj.rate_str}'.")
        return False
    tc_rate_str_cmd_rule = f"{rate_val_str}{tc_unit}"

    # Burst and Cburst for upload
    burst_cmd_part = ""
    if rule_obj.direction == "upload":
        if rule_obj.burst_str:
            burst_val_str, burst_tc_unit, _ = parse_rate_to_tc_format(rule_obj.burst_str)
            if burst_val_str: burst_cmd_part += f" burst {burst_val_str}{burst_tc_unit}"
        if rule_obj.cburst_str:
            cburst_val_str, cburst_tc_unit, _ = parse_rate_to_tc_format(rule_obj.cburst_str)
            if cburst_val_str: burst_cmd_part += f" cburst {cburst_val_str}{cburst_tc_unit}"


    direction = rule_obj.direction
    group = rule_obj.group_name
    protocol = rule_obj.protocol
    source_port = rule_obj.source_port
    destination_port = rule_obj.destination_port
    tc_identifier = rule_obj.upload_classid
    parent_handle_stored = rule_obj.upload_parent_handle

    if not tc_identifier:
        app.logger.error(f"Cannot apply TC rule for DB ID {rule_obj.id}: Missing TC identifier (upload_classid).")
        return False

    app.logger.info(f"Applying TC for rule ID {rule_obj.id}: IP={ip}, Dir={direction}, Rate(TC)={tc_rate_str_cmd_rule}, BurstCmd='{burst_cmd_part}', Filter='{protocol or 'Any'}:{source_port or '-'}:{destination_port or '-'}'. TC ID: {tc_identifier}")

    current_classes = parse_tc_class_show(interface)
    current_filters = parse_tc_filter_show(interface, direction) # This might need refinement for upload filter checks
    commands_to_execute = []

    if direction == "upload":
        commands_to_execute.append(f"tc qdisc add dev {interface} root handle 1: htb default 10 2>/dev/null || true")
    else: # download
        commands_to_execute.append(f"tc qdisc add dev {interface} ingress 2>/dev/null || true")

    parent_handle = parent_handle_stored
    if direction == "upload" and group:
        group_limit_db = GroupLimit.query.filter_by(interface=interface, group_name=group, direction="upload").first()
        if group_limit_db and group_limit_db.upload_classid:
            parent_handle = group_limit_db.upload_classid
            grp_rate_val_str, grp_tc_unit, _ = parse_rate_to_tc_format(group_limit_db.rate_str)
            grp_burst_cmd_part = ""
            if group_limit_db.burst_str:
                grp_burst_val_str, grp_burst_tc_unit, _ = parse_rate_to_tc_format(group_limit_db.burst_str)
                if grp_burst_val_str: grp_burst_cmd_part += f" burst {grp_burst_val_str}{grp_burst_tc_unit}"
            if group_limit_db.cburst_str:
                grp_cburst_val_str, grp_cburst_tc_unit, _ = parse_rate_to_tc_format(group_limit_db.cburst_str)
                if grp_cburst_val_str: grp_burst_cmd_part += f" cburst {grp_cburst_val_str}{grp_cburst_tc_unit}"

            group_tc_rate_str_cmd = f"{grp_rate_val_str}{grp_tc_unit}"
            if existing_group_class_tc := current_classes.get(group_limit_db.upload_classid):
                if existing_group_class_tc['parent'] == "1:":
                    commands_to_execute.append(f"tc class change dev {interface} parent 1: classid {group_limit_db.upload_classid} htb rate {group_tc_rate_str_cmd} ceil {group_tc_rate_str_cmd}{grp_burst_cmd_part} 2>/dev/null || true")
                # else: problem, parent mismatch, set_group_limit should handle this conflict. Here we assume it's correct or will be.
            else:
                commands_to_execute.append(f"tc class add dev {interface} parent 1: classid {group_limit_db.upload_classid} htb rate {group_tc_rate_str_cmd} ceil {group_tc_rate_str_cmd}{grp_burst_cmd_part} 2>/dev/null || true")
        else:
            parent_handle = "1:" # Fallback
    elif not parent_handle:
        parent_handle = "1:" if direction == "upload" else "ffff:"


    filter_prio = 1
    filter_protocol_cmd = protocol.lower() if protocol else "ip"
    match_details_parts = []
    # Basic IPv4/IPv6 check for match string (can be more robust)
    if ":" in ip: # crude IPv6 check
        match_details_parts.append(f"ip6 {'src' if direction == 'upload' else 'dst'} {ip}/128")
        if filter_protocol_cmd == "ip": filter_protocol_cmd = "ipv6" # Ensure protocol for filter command
    else:
        match_details_parts.append(f"ip {'src' if direction == 'upload' else 'dst'} {ip}/32")

    if protocol and protocol.lower() != "ip" and protocol.lower() != "ipv6": match_details_parts.append(f"protocol {protocol.lower()}") # Avoid redundant protocol if already ip/ipv6
    if protocol and protocol.lower() in ['tcp', 'udp']:
        if source_port: match_details_parts.append(f"{protocol.lower()} sport {source_port}") # tc uses sport/dport
        if destination_port: match_details_parts.append(f"{protocol.lower()} dport {destination_port}")
    u32_match_string = " ".join(match_details_parts)

    if direction == "upload":
        classid = tc_identifier
        if existing_ip_class_tc := current_classes.get(classid):
            if existing_ip_class_tc['parent'] == parent_handle:
                commands_to_execute.append(f"tc class change dev {interface} parent {parent_handle} classid {classid} htb rate {tc_rate_str_cmd_rule} ceil {tc_rate_str_cmd_rule}{burst_cmd_part} 2>/dev/null || true")
        else: # Add if not existing or parent mismatch (rely on set_bandwidth_limit to create unique classid)
            commands_to_execute.append(f"tc class add dev {interface} parent {parent_handle} classid {classid} htb rate {tc_rate_str_cmd_rule} ceil {tc_rate_str_cmd_rule}{burst_cmd_part} 2>/dev/null || true")

        intended_filter_key = f"{parent_handle}|{filter_prio}|{filter_protocol_cmd}|{u32_match_string}"
        existing_filter_tc = current_filters.get(intended_filter_key) # current_filters key format needs to align
        if existing_filter_tc and existing_filter_tc.get('flowid') == classid:
            pass # Filter exists and is correct
        else:
            if existing_filter_tc: # Exists but wrong flowid or other mismatch
                commands_to_execute.append(f"tc filter del dev {interface} parent {parent_handle} protocol {filter_protocol_cmd} prio {filter_prio} u32 match {u32_match_string} 2>/dev/null || true")
            commands_to_execute.append(f"tc filter add dev {interface} parent {parent_handle} protocol {filter_protocol_cmd} prio {filter_prio} u32 match {u32_match_string} flowid {classid}")

    elif direction == "download":
        filter_parent = "ffff:"
        filter_handle_str = tc_identifier
        try:
            filter_handle_num = int(filter_handle_str.lstrip(':'))
        except (ValueError, AttributeError):
            return False # Invalid handle

        _, _, rate_bps_for_burst = parse_rate_to_tc_format(rule_obj.rate_str)
        burst_bytes = max(int(rate_bps_for_burst * 0.1 / 8), 1600) # Example burst calc

        intended_filter_key = f"{filter_parent}|{filter_prio}|{filter_protocol_cmd}|{u32_match_string}"
        existing_filter_tc = current_filters.get(intended_filter_key)
        add_or_replace_cmd = "add" # Default to add

        if existing_filter_tc:
            # Try to determine if existing filter matches the handle we intend to use/reuse
            ef_handle_num = None
            if existing_filter_tc.get('handle_hex'):
                try: ef_handle_num = int(existing_filter_tc['handle_hex'], 16)
                except: pass
            elif existing_filter_tc.get('flowid','').startswith(':'): # flowid stores :handle for police
                try: ef_handle_num = int(existing_filter_tc['flowid'].lstrip(':'))
                except: pass

            if ef_handle_num is not None and ef_handle_num == filter_handle_num:
                add_or_replace_cmd = "replace"
            else: # Mismatch or existing doesn't have a clear handle, delete old and add new
                commands_to_execute.append(f"tc filter del dev {interface} parent {filter_parent} protocol {filter_protocol_cmd} prio {filter_prio} u32 match {u32_match_string} 2>/dev/null || true")

        base_filter_cmd = f"tc filter {add_or_replace_cmd} dev {interface} parent {filter_parent} protocol {filter_protocol_cmd} prio {filter_prio}"
        # For 'replace', if by handle, match criteria is not always needed if handle is unique for parent+prio+protocol
        # However, tc u32 replace often needs match. Let's be explicit.
        # The 'handle' keyword in tc filter add/replace is for assigning a specific handle, not for matching an existing one to replace.
        # The 'flowid' in police action can also take the ':<handle_num>' form.
        commands_to_execute.append(f"{base_filter_cmd} u32 match {u32_match_string} police rate {tc_rate_str_cmd_rule} burst {burst_bytes}b action drop flowid :{filter_handle_num} handle {filter_handle_num}")


    tc_execution_success = True
    for cmd in commands_to_execute:
        if run_command(cmd) is None and "del" not in cmd.lower() and "change" not in cmd.lower() and "|| true" not in cmd: # Be more lenient on del/change failures if they are to ensure state
            # A more robust check would be to verify state after, not just command success
            app.logger.error(f"TC command failed critically during apply_single_tc_rule for ID {rule_obj.id}: {cmd}")
            tc_execution_success = False
            # break # Stop on critical failure
    return tc_execution_success

def clear_single_tc_rule(rule_obj):
    if not rule_obj or not rule_obj.interface: return False
    interface = rule_obj.interface
    ip = rule_obj.ip
    direction = rule_obj.direction
    tc_identifier = rule_obj.upload_classid
    parent_handle_stored = rule_obj.upload_parent_handle

    if not tc_identifier: return True # Nothing to clear based on DB

    commands_to_execute = []
    if direction == "upload":
        classid_to_del = tc_identifier
        parent_to_use = parent_handle_stored or "1:"
        protocol = rule_obj.protocol
        source_port = rule_obj.source_port
        destination_port = rule_obj.destination_port
        filter_prio = 1
        filter_protocol_cmd = protocol.lower() if protocol else "ip"

        match_details_parts = []
        if ":" in ip:
            match_details_parts.append(f"ip6 src {ip}/128")
            if filter_protocol_cmd == "ip": filter_protocol_cmd = "ipv6"
        else:
            match_details_parts.append(f"ip src {ip}/32")

        if protocol and protocol.lower() not in ["ip", "ipv6"]: match_details_parts.append(f"protocol {protocol.lower()}")
        if protocol and protocol.lower() in ['tcp', 'udp']:
            if source_port: match_details_parts.append(f"{protocol.lower()} sport {source_port}")
            if destination_port: match_details_parts.append(f"{protocol.lower()} dport {destination_port}")
        u32_match_string = " ".join(match_details_parts)

        commands_to_execute.append(f"tc filter del dev {interface} parent {parent_to_use} protocol {filter_protocol_cmd} prio {filter_prio} u32 match {u32_match_string} 2>/dev/null || true")
        commands_to_execute.append(f"tc class del dev {interface} classid {classid_to_del} 2>/dev/null || true")

    elif direction == "download":
        filter_parent = "ffff:"
        filter_handle_str = tc_identifier
        try:
            handle_id_num = int(filter_handle_str.lstrip(':'))
            # To delete a police filter, matching on handle isn't enough if other params differ.
            # Deleting by full match is safer if possible, or by handle if it was uniquely assigned.
            # The 'handle <num>' in tc filter del refers to the internal kernel handle, not the :<flowid_minor> one directly.
            # However, if 'handle <num>' was used at creation with 'flowid :<num>', we can try deleting with 'handle <num>'.
            # A more robust way is to delete by specific match details if they are known and unique.
            # For simplicity, if 'handle <num>' was assigned, we try to remove using it.
            # This part is tricky without exact knowledge of how tc filter del matches existing filters by handle vs other properties.
            # The simplest tc filter del ... handle <handle_id_num> might not always work if it's a u32 filter not created with that exact handle as primary ID.
            # Deleting with parent ffff: prio protocol and match (if available and used for this rule) is more specific for u32.
            # Since we stored tc_identifier as ':<handle_num>', let's assume we want to delete using this.
            commands_to_execute.append(f"tc filter del dev {interface} parent {filter_parent} protocol ip prio 1 flower ip_proto ip dst {ip} action police flowid :{handle_id_num} 2>/dev/null || true") # Example for flower, u32 is different
            commands_to_execute.append(f"tc filter del dev {interface} parent {filter_parent} handle 800::{handle_id_num} 2>/dev/null || true") # trying to delete by a common tc handle format for ingress if that was used.
            # The most reliable way to delete the ingress u32 filter is by its exact match criteria if `handle` wasn't the primary identifier in creation.
            # Given tc_identifier is just ':handle_num', the original add command must have used '... handle <handle_num> flowid :<handle_num>'
            # So deleting by '... handle <handle_num>' (actual hex handle) might be better if we knew it.
            # Or delete by matching all params of the u32 filter.
            # The clear_single_tc_rule from apply_single_tc_rule for download should be used here.
            protocol = rule_obj.protocol
            source_port = rule_obj.source_port # Not typically used for download IP dst rule
            destination_port = rule_obj.destination_port
            filter_prio = 1
            filter_protocol_cmd = protocol.lower() if protocol else "ip"
            if ":" in ip: # crude IPv6 check
                match_details_parts_del = [f"ip6 dst {ip}/128"]
                if filter_protocol_cmd == "ip": filter_protocol_cmd = "ipv6"
            else:
                match_details_parts_del = [f"ip dst {ip}/32"]
            if protocol and protocol.lower() not in ['ip', 'ipv6']: match_details_parts_del.append(f"protocol {protocol.lower()}")
            if protocol and protocol.lower() in ['tcp', 'udp'] and destination_port : # dport for download
                 match_details_parts_del.append(f"{protocol.lower()} dport {destination_port}")
            u32_match_string_del = " ".join(match_details_parts_del)

            commands_to_execute.append(f"tc filter del dev {interface} parent {filter_parent} protocol {filter_protocol_cmd} prio {filter_prio} u32 match {u32_match_string_del} 2>/dev/null || true")

        except (ValueError, AttributeError): return False

    tc_execution_success = True
    for cmd in commands_to_execute:
        if run_command(cmd) is None and "|| true" not in cmd: # If command fails and not already lenient
            tc_execution_success = False
    return tc_execution_success



def set_bandwidth_limit(interface, ip, rate_value_form, rate_unit_form, direction, group=None, overwrite=False,
                        protocol=None, source_port=None, destination_port=None,
                        is_scheduled=False, start_time=None, end_time=None, weekdays=None, start_date=None, end_date=None,
                        description=None, is_enabled=True, # NEW fields
                        burst_value_form=None, burst_unit_form=None, # NEW burst fields
                        cburst_value_form=None, cburst_unit_form=None): # NEW cburst fields
    app.logger.info(f"set_bandwidth_limit called: ip={ip}, rate={rate_value_form}{rate_unit_form}, dir={direction}, sched={is_scheduled}, enabled={is_enabled}, desc={description}, burst={burst_value_form}{burst_unit_form}")

    tc_rate_str_cmd, rate_in_bps, rate_str_for_db = parse_rate_input(rate_value_form, rate_unit_form)
    if tc_rate_str_cmd is None:
        flash(f"Invalid rate value or unit: {rate_value_form}{rate_unit_form}. Must be a positive number and unit (bps, kbps, mbps, gbps).", "danger")
        return False

    # Parse burst and cburst if provided (for upload)
    burst_str_for_db, cburst_str_for_db = None, None
    if direction == "upload":
        if burst_value_form and burst_unit_form:
            _, _, burst_str_for_db = parse_rate_input(burst_value_form, burst_unit_form)
            if not burst_str_for_db:
                flash(f"Invalid burst rate/unit: {burst_value_form}{burst_unit_form}", "danger"); return False
        if cburst_value_form and cburst_unit_form:
            _, _, cburst_str_for_db = parse_rate_input(cburst_value_form, cburst_unit_form)
            if not cburst_str_for_db:
                flash(f"Invalid ceiling burst rate/unit: {cburst_value_form}{cburst_unit_form}", "danger"); return False

    if direction not in ['upload', 'download']: flash("Invalid direction.", "danger"); return False
    # Simplified validation for protocol/ports (assuming already done in route)
    if is_scheduled:
        if not start_time or not end_time: is_scheduled = False # Revert to non-scheduled if core time info missing
        # Add more format checks for time/date if needed, or rely on form validation

    # Check for existing rule based on more complete filter criteria if you want truly unique rules
    # For now, using existing logic: interface, ip, direction
    # If you want to allow multiple rules for the same IP but different ports/protocols, the unique constraint in DB and this query needs adjustment.
    # Current unique constraint includes protocol, source_port, destination_port. So this query should too.
    existing_rule_db = Rule.query.filter_by(
        interface=interface, ip=ip, direction=direction,
        protocol=protocol if protocol else None, # Ensure None is used if empty string
        source_port=source_port if source_port else None,
        destination_port=destination_port if destination_port else None
    ).first()


    if existing_rule_db and overwrite:
        app.logger.info(f"Overwrite requested for existing rule ID {existing_rule_db.id}.")
        # If old rule was active (not scheduled, or scheduled and active_scheduled), clear its TC
        if not existing_rule_db.is_scheduled or existing_rule_db.is_active_scheduled:
            if not clear_single_tc_rule(existing_rule_db):
                flash(f"Warning: Failed to clear old TC for rule {existing_rule_db.id} during overwrite. Manual check advised.", "warning")
        db.session.delete(existing_rule_db)
        # db.session.commit() # Commit deletion before adding new to avoid unique constraint issue if key parts are same
        # Better: commit after new rule is added, or handle unique constraint error
    elif existing_rule_db and not overwrite:
        flash(f"Rule for IP {ip} ({direction}) with these filter criteria already exists. Use overwrite or delete existing.", "danger")
        return False

    # Generate TC Identifiers (Class ID for upload, Filter Handle for download)
    # This logic needs to ensure uniqueness if multiple rules for same IP but different filters are allowed.
    # For simplicity, if overwrite is true, try to reuse. Otherwise, generate new.
    intended_ip_classid_to_store = None
    intended_parent_handle_to_store = None

    if direction == "upload":
        potential_parent_handle = "1:"
        if group:
            gl = GroupLimit.query.filter_by(interface=interface, group_name=group, direction="upload").first()
            if gl and gl.upload_classid: potential_parent_handle = gl.upload_classid

        if existing_rule_db and overwrite and existing_rule_db.upload_classid:
            intended_ip_classid_to_store = existing_rule_db.upload_classid
        else:
            unique_seed = f"{interface}-{ip}-{direction}-{protocol}-{source_port}-{destination_port}-{potential_parent_handle}-{os.urandom(4).hex()}"
            ip_unique_minor_id = (abs(hash(unique_seed)) % 64900) + 100 # Range 100-65000
            parent_major_id_str = potential_parent_handle.split(':')[0]
            intended_ip_classid_to_store = f"{parent_major_id_str}:{ip_unique_minor_id}"
        intended_parent_handle_to_store = potential_parent_handle
    else: # download
        if existing_rule_db and overwrite and existing_rule_db.upload_classid and existing_rule_db.upload_classid.startswith(':'):
            intended_ip_classid_to_store = existing_rule_db.upload_classid # Reuse :handle
        else:
            filter_handle_seed = f"dl-{interface}-{ip}-{direction}-{protocol}-{source_port}-{destination_port}-{os.urandom(4).hex()}"
            intended_filter_handle_num = abs(hash(filter_handle_seed)) % 65500 + 1 # Range 1-65500
            intended_ip_classid_to_store = f":{intended_filter_handle_num}"
        intended_parent_handle_to_store = "ffff:"


    # Create new Rule object for DB (even if only TC identifiers changed for an existing logical rule)
    # If 'existing_rule_db' was deleted, we are adding a new one.
    # If 'existing_rule_db' was not found, we are adding a new one.
    # If 'existing_rule_db' was found and NOT overwritten, we returned False.
    
    # If overwrite happened, existing_rule_db was marked for deletion.
    # We must create a new rule instance because primary key cannot be updated.
    
    new_rule = Rule(
        interface=interface, ip=ip, rate_str=rate_str_for_db, direction=direction, group_name=group,
        protocol=protocol, source_port=source_port, destination_port=destination_port,
        description=description, is_enabled=is_enabled, # NEW
        burst_str=burst_str_for_db if direction == "upload" else None, # NEW
        cburst_str=cburst_str_for_db if direction == "upload" else None, # NEW
        is_scheduled=is_scheduled, start_time=start_time, end_time=end_time,
        weekdays=weekdays, start_date=start_date, end_date=end_date,
        is_active_scheduled=False, # Scheduler will set this to True if rule is active. If not scheduled & enabled, apply_single will handle.
        upload_classid=intended_ip_classid_to_store,
        upload_parent_handle=intended_parent_handle_to_store
    )

    tc_apply_success = True
    if is_enabled and not is_scheduled: # Apply immediately if enabled and not scheduled
        app.logger.info(f"Rule (ID tentative, IP {ip}) is enabled and not scheduled. Applying TC immediately.")
        if not apply_single_tc_rule(new_rule): # Pass the new_rule object
            flash(f"Failed to apply TC rule for {ip} ({direction}) immediately. Rule saved to DB but not active.", "danger")
            tc_apply_success = False
            new_rule.is_active_scheduled = False # Ensure it's not marked active
            # new_rule.is_enabled = False # Optionally disable it if TC fails? Or let admin fix.
    elif not is_enabled:
        app.logger.info(f"Rule (ID tentative, IP {ip}) is disabled. Not applying TC.")
        new_rule.is_active_scheduled = False # Disabled rules are not active by scheduler
    # If scheduled and enabled, scheduler will handle it. is_active_scheduled is False initially.

    try:
        db.session.add(new_rule)
        db.session.commit()
        app.logger.info(f"Rule for IP {ip} saved to DB with ID {new_rule.id}. Enabled: {is_enabled}, Scheduled: {is_scheduled}, TC Applied Now: {tc_apply_success if is_enabled and not is_scheduled else 'Deferred/Skipped'}")
        if is_enabled:
            if is_scheduled:
                flash(f"Scheduled rule for {ip} ({rate_str_for_db} {direction}) saved. Scheduler will manage activation.", "success")
            elif tc_apply_success:
                flash(f"Rule for {ip} ({rate_str_for_db} {direction}) applied and saved.", "success")
            # else: error already flashed by apply_single_tc_rule or immediate TC block
        else: # Rule is disabled
             flash(f"Rule for {ip} ({rate_str_for_db} {direction}) saved as DISABLED.", "info")
        return True
    except Exception as e:
        db.session.rollback()
        # Check for unique constraint violation
        if "UNIQUE constraint failed" in str(e):
             flash(f"Error: A rule with the same Interface, IP, Direction, and Filter Criteria already exists. DB Error: {str(e)}", "danger")
        else:
             flash(f"Database error saving rule for {ip}: {str(e)}", "danger")
        app.logger.error(f"Database error for IP {ip}: {e}")
        return False
# --- (Copy and complete set_group_limit and clear_group_limit similarly) ---
def set_group_limit(interface, group_name, rate_value_form, rate_unit_form, direction,
                    burst_value_form=None, burst_unit_form=None, # NEW
                    cburst_value_form=None, cburst_unit_form=None): # NEW

    tc_rate_str_cmd, rate_in_bps, rate_str_for_db = parse_rate_input(rate_value_form, rate_unit_form)
    if tc_rate_str_cmd is None:
        flash(f"Invalid group rate: {rate_value_form}{rate_unit_form}.", "danger"); return False

    burst_str_for_db, cburst_str_for_db = None, None
    burst_cmd_part = "" # For TC command
    if direction == "upload":
        if burst_value_form and burst_unit_form:
            parsed_burst_val_str, parsed_burst_tc_unit, burst_str_for_db = parse_rate_input(burst_value_form, burst_unit_form)
            if not burst_str_for_db: flash(f"Invalid group burst rate/unit.", "danger"); return False
            if parsed_burst_val_str: burst_cmd_part += f" burst {parsed_burst_val_str}{parsed_burst_tc_unit}"
        if cburst_value_form and cburst_unit_form:
            parsed_cburst_val_str, parsed_cburst_tc_unit, cburst_str_for_db = parse_rate_input(cburst_value_form, cburst_unit_form)
            if not cburst_str_for_db: flash(f"Invalid group ceil burst rate/unit.", "danger"); return False
            if parsed_cburst_val_str: burst_cmd_part += f" cburst {parsed_cburst_val_str}{parsed_cburst_tc_unit}"


    existing_group_limit_db = GroupLimit.query.filter_by(interface=interface, group_name=group_name, direction=direction).first()
    intended_group_classid = None

    if direction == "upload":
        if existing_group_limit_db and existing_group_limit_db.upload_classid:
            intended_group_classid = existing_group_limit_db.upload_classid
        else:
            unique_seed = f"group-{interface}-{group_name}-{direction}-{os.urandom(4).hex()}"
            group_unique_minor_id = (abs(hash(unique_seed)) % 80) + 20 # Range 20-99
            intended_group_classid = f"1:{group_unique_minor_id}"

        commands_to_execute = [f"tc qdisc add dev {interface} root handle 1: htb default 10 2>/dev/null || true"]
        current_classes = parse_tc_class_show(interface)
        existing_tc_class = current_classes.get(intended_group_classid)

        if existing_tc_class:
            if existing_tc_class['parent'] == "1:":
                commands_to_execute.append(f"tc class change dev {interface} parent 1: classid {intended_group_classid} htb rate {tc_rate_str_cmd} ceil {tc_rate_str_cmd}{burst_cmd_part} 2>/dev/null || true")
            else: # Conflict
                flash(f"Error: TC class {intended_group_classid} exists with wrong parent {existing_tc_class['parent']}. Manual TC cleanup needed.", "danger"); return False
        else:
            commands_to_execute.append(f"tc class add dev {interface} parent 1: classid {intended_group_classid} htb rate {tc_rate_str_cmd} ceil {tc_rate_str_cmd}{burst_cmd_part} 2>/dev/null || true")

        tc_success = True
        for cmd in commands_to_execute:
            if run_command(cmd) is None and "|| true" not in cmd: tc_success = False; break
        if not tc_success: flash(f"Failed to apply TC for group {group_name}.", "danger"); return False
    else: # Download group - DB only
        intended_group_classid = None # No TC class for download group
        app.logger.info(f"Download group limit '{group_name}' is DB only.")

    try:
        if existing_group_limit_db:
            existing_group_limit_db.rate_str = rate_str_for_db
            existing_group_limit_db.upload_classid = intended_group_classid
            existing_group_limit_db.burst_str = burst_str_for_db if direction == "upload" else None
            existing_group_limit_db.cburst_str = cburst_str_for_db if direction == "upload" else None
        else:
            new_group = GroupLimit(interface=interface, group_name=group_name, rate_str=rate_str_for_db, direction=direction,
                                   upload_classid=intended_group_classid,
                                   burst_str=burst_str_for_db if direction == "upload" else None,
                                   cburst_str=cburst_str_for_db if direction == "upload" else None)
            db.session.add(new_group)
        db.session.commit()
        flash(f"Group limit for {group_name} ({direction}) saved.", "success")
        return True
    except Exception as e:
        db.session.rollback()
        flash(f"Database error for group {group_name}: {str(e)}", "danger"); return False
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
def clear_group_limit(interface, group_name, direction):
    app.logger.info(f"Clearing group limit: {group_name}/{direction} on {interface}")
    group_limit_db = GroupLimit.query.filter_by(interface=interface, group_name=group_name, direction=direction).first()
    if not group_limit_db:
        flash(f"Group limit {group_name}/{direction} not found.", "warning"); return True

    if direction == "upload" and group_limit_db.upload_classid:
        cmd = f"tc class del dev {interface} classid {group_limit_db.upload_classid} 2>/dev/null || true"
        if run_command(cmd) is None and "|| true" not in cmd: # If it matters that it failed
             # This indicates run_command had an actual error, not just tc returning non-zero for "already deleted"
             app.logger.warning(f"TC class del command ({cmd}) for group {group_name} might have failed (returned None from run_command).")
             flash(f"Warning: TC cleanup for group {group_name} might have failed. Check logs.", "warning")
    elif direction == "download":
        app.logger.info(f"Download group '{group_name}' cleared from DB (no direct TC entity).")

    try:
        db.session.delete(group_limit_db)
        db.session.commit()
        flash(f"Group limit {group_name}/{direction} cleared.", "success")
        return True
    except Exception as e:
        db.session.rollback()
        flash(f"DB error clearing group {group_name}: {str(e)}", "danger"); return False

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

@app.route("/clear_group_limit", methods=["POST"])
def clear_group_limit_route():
    if not session.get('logged_in') or session.get('role') != 'admin':
        flash("Unauthorized.", "danger"); return redirect(url_for('dashboard'))
    interface = session.get('active_interface')
    if not interface:
        flash("No active interface.", "danger"); return redirect(url_for('dashboard'))

    group_name = request.form.get('group_name_clear')
    direction = request.form.get('group_dir_clear')
    if not group_name or not direction:
        flash("Group name and direction required.", "danger"); return redirect(url_for('dashboard'))
    clear_group_limit(interface, group_name, direction)
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