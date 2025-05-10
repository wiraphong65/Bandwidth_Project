import os
import sys
import secrets
import subprocess
import re
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response, get_flashed_messages
from flask_sqlalchemy import SQLAlchemy
from logging.handlers import RotatingFileHandler
import time # Keep time for now, even if not explicitly used in all new features
from datetime import datetime, time as dtime, date as ddate # Import datetime, time, date for scheduling logic
from sqlalchemy import or_, and_ # Import SQLAlchemy operators for complex queries

# --- APScheduler Imports ---
from flask_apscheduler import APScheduler


# --- Flask App Initialization and Configuration ---
app = Flask(__name__)
# !! IMPORTANT !! Change this secret key to a strong, random value in production!
# Consider moving this and other configs to an external file or environment variables.
app.secret_key = secrets.token_hex(16)

# --- Database Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

app.config['LOG_FILE'] = 'app.log' # set log file

# --- Logging Setup ---
try:
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    log_file_path = os.path.join(log_dir, app.config['LOG_FILE'])

    log_handler = RotatingFileHandler(log_file_path, maxBytes=1024 * 1024 * 5, backupCount=5)
    log_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    log_handler.setFormatter(formatter)
    app.logger.addHandler(log_handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    app.logger.addHandler(stream_handler)

    app.logger.setLevel(logging.INFO)
    app.logger.info("Logging configured.")

except Exception as e:
    print(f"ERROR: Failed to set up logging: {e}", file=sys.stderr)
    print("Logging to console only.", file=sys.stderr)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    app.logger = logging.getLogger(__name__)
    app.logger.warning("Failed to set up file logging. Logging to console.")


# --- APScheduler Configuration ---
class Config:
    SCHEDULER_API_ENABLED = False
    SCHEDULER_TIMEZONE = 'Asia/Bangkok' # ตั้ง Timezone ให้ถูกต้อง

app.config.from_object(Config())
scheduler = APScheduler() # สร้าง Scheduler Instance

# --- Database Models ---

class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    interface = db.Column(db.String(50), nullable=False)
    ip = db.Column(db.String(45), nullable=False) # Increased size for IPv6
    rate_str = db.Column(db.String(20), nullable=False)
    direction = db.Column(db.String(10), nullable=False)
    group_name = db.Column(db.String(50), nullable=True)

    protocol = db.Column(db.String(10), nullable=True)
    source_port = db.Column(db.String(10), nullable=True)
    destination_port = db.Column(db.String(10), nullable=True)

    # --- NEW: Description and Enable/Disable fields ---
    description = db.Column(db.String(255), nullable=True)
    is_enabled = db.Column(db.Boolean, default=True, nullable=False)
    # --- END NEW ---

    # --- NEW: Burst and Cburst fields for Upload ---
    burst_str = db.Column(db.String(20), nullable=True) # e.g., "1600b", "20kbit"
    cburst_str = db.Column(db.String(20), nullable=True)
    # --- END NEW ---

    is_scheduled = db.Column(db.Boolean, default=False)
    start_time = db.Column(db.String(5), nullable=True) # HH:MM
    end_time = db.Column(db.String(5), nullable=True) # HH:MM
    weekdays = db.Column(db.String(30), nullable=True) # Comma-separated "Mon,Tue"
    start_date = db.Column(db.String(10), nullable=True) # YYYY-MM-DD
    end_date = db.Column(db.String(10), nullable=True) # YYYY-MM-DD
    is_active_scheduled = db.Column(db.Boolean, default=False)

    upload_classid = db.Column(db.String(20), nullable=True)
    upload_parent_handle = db.Column(db.String(20), nullable=True)

    __table_args__ = (db.UniqueConstraint('interface', 'ip', 'direction', 'protocol', 'source_port', 'destination_port', name='_ip_iface_dir_filter_uc'),) # Adjusted unique constraint if filters are part of uniqueness

    def __repr__(self):
        return (f"Rule(id={self.id}, iface='{self.interface}', ip='{self.ip}', rate='{self.rate_str}', dir='{self.direction}', "
                f"proto='{self.protocol}', sport='{self.source_port}', dport='{self.destination_port}', group='{self.group_name}', "
                f"desc='{self.description}', enabled={self.is_enabled}, burst='{self.burst_str}', cburst='{self.cburst_str}', "
                f"scheduled={self.is_scheduled}, time='{self.start_time}-{self.end_time}', days='{self.weekdays}', "
                f"date='{self.start_date}-{self.end_date}', active_sched={self.is_active_scheduled}, "
                f"tc_id='{self.upload_classid}', parent='{self.upload_parent_handle}')")

class GroupLimit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    interface = db.Column(db.String(50), nullable=False)
    group_name = db.Column(db.String(50), nullable=False)
    direction = db.Column(db.String(10), nullable=False)
    rate_str = db.Column(db.String(20), nullable=False)

    # --- NEW: Burst and Cburst fields for Upload ---
    burst_str = db.Column(db.String(20), nullable=True)
    cburst_str = db.Column(db.String(20), nullable=True)
    # --- END NEW ---

    upload_classid = db.Column(db.String(20), nullable=True)
    __table_args__ = (db.UniqueConstraint('interface', 'group_name', 'direction', name='_group_direction_uc'),)

    def __repr__(self):
        return (f"GroupLimit(id={self.id}, iface='{self.interface}', group='{self.group_name}', dir='{self.direction}', "
                f"rate='{self.rate_str}', burst='{self.burst_str}', cburst='{self.cburst_str}', classid='{self.upload_classid}')")

# --- In-memory Data Stores ---
bandwidth_rules = [] # Will hold Rule objects for the active interface
group_limits = {}    # Will hold GroupLimit objects for the active interface

# --- Helper Functions ---
def run_command(command):
    app.logger.debug(f"Executing command: {command}")
    try:
        process = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', timeout=15)
        output_str = (process.stdout + process.stderr).strip()
        if output_str:
            app.logger.debug(f"Command output: {output_str}")
        return output_str
    except subprocess.CalledProcessError as e:
        error_msg = (e.stdout + e.stderr).strip() if e.stdout or e.stderr else "No output"
        app.logger.error(f"Command failed: {command} - Exit Code: {e.returncode} - Output: {error_msg}")
        return None # Indicate failure
    except FileNotFoundError:
        app.logger.error(f"Command not found: {command.split(' ')[0]}. Is it installed and in PATH?")
        return None
    except subprocess.TimeoutExpired:
        app.logger.error(f"Command timed out: {command}")
        return None
    except Exception as e:
        app.logger.exception(f"Exception occurred while executing command: {command}")
        return None

def get_interfaces():
    app.logger.debug("Getting network interfaces")
    output = run_command("ip -o link show")
    interfaces = []
    if output:
        lines = output.splitlines()
        for line in lines:
            match = re.match(r'^\d+:\s+([\w.-]+):', line) # Allow . and - in interface names
            if match:
                iface = match.group(1)
                if iface != 'lo' and not iface.startswith(('docker', 'veth', 'br-', 'virbr', 'kube-', 'cni', 'flannel', 'vxlan', 'geneve')):
                    interfaces.append(iface)
    app.logger.debug(f"Found interfaces: {interfaces}")
    return interfaces

def is_float(value):
    if value is None: return False
    try:
        float(value)
        return True
    except (ValueError, TypeError):
        return False

def get_bandwidth_usage(interface):
    if not interface or not os.path.exists(f"/sys/class/net/{interface}/statistics/"):
        app.logger.warning(f"Attempted to get bandwidth usage for invalid or non-existent interface: {interface}")
        return {"rx_bytes": 0, "tx_bytes": 0}
    rx_path = f"/sys/class/net/{interface}/statistics/rx_bytes"
    tx_path = f"/sys/class/net/{interface}/statistics/tx_bytes"
    rx_bytes, tx_bytes = 0, 0
    try:
        if os.path.exists(rx_path):
            with open(rx_path, 'r') as f: rx_bytes = int(f.read().strip())
        else: app.logger.warning(f"Sysfs file not found: {rx_path}")
        if os.path.exists(tx_path):
            with open(tx_path, 'r') as f: tx_bytes = int(f.read().strip())
        else: app.logger.warning(f"Sysfs file not found: {tx_path}")
        return {"rx_bytes": rx_bytes, "tx_bytes": tx_bytes}
    except Exception as e:
        app.logger.error(f"Error fetching bandwidth usage for {interface} from sysfs: {e}")
        return {"rx_bytes": 0, "tx_bytes": 0}

def format_bytes(byte_count):
    if byte_count is None or not isinstance(byte_count, (int, float)): return "N/A"
    byte_count = int(byte_count)
    if byte_count < 0: return f"{byte_count} B"
    elif byte_count < 1024: return f"{byte_count} B"
    elif byte_count < 1024**2: return f"{byte_count / 1024:.2f} KB"
    elif byte_count < 1024**3: return f"{byte_count / (1024**2):.2f} MB"
    elif byte_count < 1024**4: return f"{byte_count / (1024**3):.2f} GB"
    elif byte_count < 1024**5: return f"{byte_count / (1024**4):.2f} TB"
    else: return f"{byte_count / (1024**5):.2f} PB"

def get_tc_stats(interface):
    if not interface:
        app.logger.warning("Attempted to get TC stats for None interface.")
        return {}
    app.logger.debug(f"Fetching TC stats for interface: {interface} using 'tc -s'")
    tc_stats = {}
    class_output = run_command(f"tc -s class show dev {interface}")
    if class_output:
        class_regex = re.compile(r'class\s+htb\s+(\w+:\w+)\s+.*?pkts\s+(\d+)\s+bytes\s+(\d+)')
        for line in class_output.splitlines():
            match = class_regex.search(line)
            if match:
                tc_stats[match.group(1)] = {'pkts': int(match.group(2)), 'bytes': int(match.group(3))}
    filter_output = run_command(f"tc -s filter show dev {interface} ingress")
    if filter_output:
        filter_regex = re.compile(r'filter\s+parent\s+ffff:\s+protocol\s+ip\s+pref\s+\d+\s+(?:handle\s+(0x[0-9a-f]+)\s+)?.*? (?:flowid\s*:\s*(\d+))?.*?pkts\s+(\d+)\s+bytes\s+(\d+)')
        for line in filter_output.splitlines():
            match = filter_regex.search(line)
            if match:
                handle_hex, handle_minor, pkts_str, bytes_str = match.group(1), match.group(2), match.group(3), match.group(4)
                filter_id = f":{handle_minor}" if handle_minor else handle_hex
                if filter_id:
                    tc_stats[filter_id] = {'pkts': int(pkts_str), 'bytes': int(bytes_str)}
    app.logger.debug(f"Finished fetching TC stats for {interface}. Found {len(tc_stats)} entries.")
    return tc_stats

def parse_tc_qdisc_show(interface):
    qdiscs = {}
    output = run_command(f"tc qdisc show dev {interface}")
    if output:
        qdisc_regex = re.compile(r'qdisc\s+(\w+)\s+(\w+:\w*)\s+dev\s+\w+\s+(?:parent\s+(\w+:\w+)\s+)?.*?') # handle can be e.g. ffff:
        for line in output.splitlines():
            match = qdisc_regex.search(line)
            if match:
                qdiscs[match.group(2)] = {'type': match.group(1), 'parent': match.group(3)}
    return qdiscs

def parse_tc_class_show(interface):
    classes = {}
    output = run_command(f"tc class show dev {interface}")
    if output:
        class_regex = re.compile(r'class\s+htb\s+(\w+:\w+)\s+parent\s+(\w+:\w*)\s*(?:prio\s+\d+\s+)?rate\s+([\w.]+bit)(?:\s+ceil\s+([\w.]+bit))?.*?')
        for line in output.splitlines():
            match = class_regex.search(line)
            if match:
                classes[match.group(1)] = {'parent': match.group(2), 'rate_str': match.group(3), 'ceil_str': match.group(4) or match.group(3)}
    return classes

def parse_tc_filter_show(interface, direction):
    filters = {}
    direction_arg = "ingress" if direction == "download" else "" # For upload, filters are usually under specific classes, not root qdisc.
                                                                  # However, a general 'tc filter show dev <iface>' might be too broad.
                                                                  # This function primarily aims for u32 filters.
    output = run_command(f"tc filter show dev {interface} {direction_arg}")
    if output:
        filter_regex = re.compile(
            r'filter\s+parent\s+(\w+:\w*)\s+protocol\s+(\w+)\s+pref\s+(\d+)\s+'
            r'u32.*?match\s+(.+?)\s+'
            r'(?:flowid\s+(\w+:\w*|\s*:\d+))?' # Optional flowid (major:minor or :minor)
            r'.*?(?:\(handle\s+(0x[0-9a-f]+)\))?' # Optional handle
        )
        for line in output.splitlines():
            match = filter_regex.search(line)
            if match:
                parent, protocol, prio_str, match_details_raw, flowid, handle_hex = match.groups()
                filter_key = f"{parent}|{prio_str}|{protocol}|{match_details_raw.strip()}"
                filters[filter_key] = {
                    'parent': parent, 'prio': int(prio_str), 'protocol': protocol,
                    'match_details': match_details_raw.strip(), 'flowid': flowid, 'handle_hex': handle_hex
                }
    return filters

def parse_rate_to_tc_format(rate_str_in):
    """ Parses rate string (e.g., "10Mbps", "512Kbps") and returns value_str, unit_suffix for tc, and rate_in_bps. """
    if not rate_str_in: return None, None, 0
    match = re.match(r'^(\d+(\.\d+)?)\s*([bKMGT]?bps|[bKMGT]?bit)?$', rate_str_in, re.IGNORECASE)
    if not match: return None, None, 0

    value_str = match.group(1)
    value = float(value_str)
    unit = match.group(3)
    rate_bps = value
    tc_unit_suffix = "bit" # tc commands use Kbit, Mbit, Gbit, or just bit

    if unit:
        unit = unit.lower()
        if 'mbps' in unit or 'mbit' in unit:
            rate_bps *= 1000000
            tc_unit_suffix = "Mbit"
        elif 'kbps' in unit or 'kbit' in unit:
            rate_bps *= 1000
            tc_unit_suffix = "Kbit"
        elif 'gbps' in unit or 'gbit' in unit:
            rate_bps *= 1000000000
            tc_unit_suffix = "Gbit"
        # if just 'bps' or 'bit', rate_bps is already correct, tc_unit_suffix is "bit"
    else: # No unit, assume Mbps as a default from previous logic, but for tc better to be explicit
        app.logger.warning(f"Rate unit not specified for '{rate_str_in}', assuming bps for calculation, but tc command will use 'bit' if value is small or explicit if large.")
        # Let tc command construction decide on Mbit/Kbit based on value if no unit, or just pass number and 'bit'
        # For now, let's make it explicit if large, or just 'bit'
        if value >= 1000000:
            tc_unit_suffix = "Mbit"
            value_str = str(value / 1000000)
        elif value >= 1000:
            tc_unit_suffix = "Kbit"
            value_str = str(value / 1000)
        # else value_str is fine, tc_unit_suffix = "bit"

    return f"{float(value_str):.2f}".rstrip('0').rstrip('.'), tc_unit_suffix, int(rate_bps)


def is_rule_scheduled_active_now(rule_obj, current_datetime):
    if not rule_obj.is_scheduled or not rule_obj.is_enabled: # Check if rule is enabled
        return False
    now_time = current_datetime.time()
    now_weekday = current_datetime.strftime('%a')
    now_date = current_datetime.date()
    is_time_match = False
    if rule_obj.start_time and rule_obj.end_time:
        try:
            start_dt_time = dtime.fromisoformat(rule_obj.start_time)
            end_dt_time = dtime.fromisoformat(rule_obj.end_time)
            if start_dt_time < end_dt_time:
                if start_dt_time <= now_time < end_dt_time: is_time_match = True
            else: # Wraps midnight
                if now_time >= start_dt_time or now_time < end_dt_time: is_time_match = True
        except ValueError: is_time_match = False
    else: is_time_match = False # Should not happen if is_scheduled is True and validated

    is_weekday_match = True
    if rule_obj.weekdays:
        if now_weekday not in [d.strip() for d in rule_obj.weekdays.split(',')]:
            is_weekday_match = False
    is_date_match = True
    if rule_obj.start_date:
        try:
            if now_date < ddate.fromisoformat(rule_obj.start_date): is_date_match = False
        except ValueError: is_date_match = False
    if rule_obj.end_date:
        try:
            if now_date > ddate.fromisoformat(rule_obj.end_date): is_date_match = False
        except ValueError: is_date_match = False
    return is_time_match and is_weekday_match and is_date_match

# --- Helper Functions for Scheduler to Apply/Clear Single Rule TC ---

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


# --- Background Task Function for Scheduling ---
def apply_scheduled_rules():
    with app.app_context():
        app.logger.info("Running scheduled rules task...")
        now = datetime.now()
        # Activate rules that should be active and are enabled
        rules_to_activate = Rule.query.filter_by(is_scheduled=True, is_active_scheduled=False, is_enabled=True).all()
        activated_count = 0
        for rule in rules_to_activate:
            if is_rule_scheduled_active_now(rule, now): # is_rule_scheduled_active_now already checks is_enabled
                if apply_single_tc_rule(rule):
                    rule.is_active_scheduled = True
                    activated_count += 1
                else: app.logger.error(f"Failed to apply TC for scheduled rule ID {rule.id}.")
        # Deactivate rules that should no longer be active or are disabled
        rules_to_deactivate = Rule.query.filter_by(is_scheduled=True, is_active_scheduled=True).all() # Get all active scheduled
        deactivated_count = 0
        for rule in rules_to_deactivate:
            # Deactivate if schedule ended OR if rule got disabled
            if not rule.is_enabled or not is_rule_scheduled_active_now(rule, now):
                if clear_single_tc_rule(rule):
                    rule.is_active_scheduled = False
                    deactivated_count += 1
                else: app.logger.error(f"Failed to clear TC for scheduled rule ID {rule.id}.")

        if activated_count > 0 or deactivated_count > 0:
            try:
                db.session.commit()
            except Exception as db_error:
                db.session.rollback()
                app.logger.error(f"Scheduled rules task: Database commit failed: {db_error}")
        app.logger.info(f"Scheduled rules: {activated_count} activated, {deactivated_count} deactivated.")

# --- Configure and Start APScheduler ---
scheduler.init_app(app)
scheduler.add_job(id='apply_scheduled_rules_job', func=apply_scheduled_rules, trigger='interval', minutes=1)

# --- Helper: Rate String Parsing (used in set_bandwidth_limit, set_group_limit) ---
def parse_rate_input(rate_value_in, rate_unit_in):
    """ Validates rate_value, rate_unit and returns tc_rate_str_cmd, rate_in_bps, original_rate_str_for_db """
    if not is_float(rate_value_in):
        return None, 0, None # Indicate error

    rate_value = float(rate_value_in)
    if rate_value <= 0:
        return None, 0, None # Indicate error

    original_rate_str_for_db = f"{rate_value_in}{rate_unit_in.title() if rate_unit_in else 'Bps'}" # Store with original value and unit

    rate_in_bps = rate_value
    tc_rate_str_cmd_val = rate_value_in # Use original string for value part of TC command initially
    tc_rate_unit_suffix = "bit" # Default for TC command if small

    if rate_unit_in:
        unit = rate_unit_in.lower()
        if unit == 'mbps':
            rate_in_bps = rate_value * 1000000
            tc_rate_unit_suffix = "Mbit"
        elif unit == 'kbps':
            rate_in_bps = rate_value * 1000
            tc_rate_unit_suffix = "Kbit"
        elif unit == 'gbps': # Added Gbps
            rate_in_bps = rate_value * 1000000000
            tc_rate_unit_suffix = "Gbit"
        elif unit == 'bps':
            pass # rate_in_bps is already correct
        else: # Invalid unit
            return None, 0, None
    else: # No unit provided, assume BPS for rate_in_bps, let TC command be just number+bit
        app.logger.warning(f"Rate unit not specified for value {rate_value_in}, assuming BPS for internal calc, 'bit' for TC unless large.")
        # For TC, if no unit, it's bits/sec. We can make it Kbit/Mbit for readability if large.
        if rate_value >= 1000000:
            tc_rate_str_cmd_val = f"{rate_value/1000000:.2f}".rstrip('0').rstrip('.')
            tc_rate_unit_suffix = "Mbit"
        elif rate_value >= 1000:
            tc_rate_str_cmd_val = f"{rate_value/1000:.2f}".rstrip('0').rstrip('.')
            tc_rate_unit_suffix = "Kbit"
        # else tc_rate_str_cmd_val and tc_rate_unit_suffix are fine

    return f"{tc_rate_str_cmd_val}{tc_rate_unit_suffix}", int(rate_in_bps), original_rate_str_for_db


# --- Main Business Logic Functions ---
# Function to set bandwidth limit for an IP
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

# Function to set bandwidth limit for a group
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


# --- Flask Routes ---
# Global variable declarations (moved to top of functions where used if local scope is better)
# For simplicity in this combined file, they are here.
# Consider Flask's 'g' object or other state management for larger apps.
# bandwidth_rules = [] (defined earlier)
# group_limits = {} (defined earlier)

@app.route("/", methods=["GET", "POST"])
def dashboard():
    global bandwidth_rules, group_limits # Use global for these in-memory caches

    if not session.get('logged_in'):
        return redirect(url_for('login'))

    interfaces = get_interfaces()
    if not interfaces and not session.get('active_interface'): # Only flash if no interfaces at all AND no active_if set
        flash("No network interfaces found. Bandwidth control may not be possible.", "warning")

    current_active_if = session.get('active_interface')
    if not current_active_if and interfaces:
        session['active_interface'] = interfaces[0]
        current_active_if = interfaces[0] # Update for current request
        flash(f"Default active interface set to {current_active_if}.", "info")
    elif current_active_if and current_active_if not in interfaces: # Previously active interface disappeared
        flash(f"Previously active interface {current_active_if} is no longer available. Please select a new one.", "warning")
        session['active_interface'] = interfaces[0] if interfaces else None
        current_active_if = session.get('active_interface')


    active_interface = session.get('active_interface')

    if request.method == "POST":
        # Handle interface selection
        selected_interface = request.form.get('interface_dropdown')
        if selected_interface and selected_interface in interfaces:
            if active_interface != selected_interface:
                session['active_interface'] = selected_interface
                flash(f"Active interface set to {selected_interface}. Re-applying rules...", "success")
                # IMPORTANT: When interface changes, existing TC rules on the OLD interface are NOT automatically cleared by this.
                # Reapply will clear TC on NEW interface and apply its rules.
                return redirect(url_for('reapply_rules_route')) # This will clear TC on new iface & load its rules
            else:
                flash(f"Interface is already {selected_interface}.", "info")
        elif selected_interface: # Invalid selection
             flash(f"Invalid interface '{selected_interface}' selected.", "danger")
        # No redirect here if not changing interface, allow other POST actions on dashboard if any in future
        # For now, any POST not changing interface will just reload dashboard via GET logic below

    # Load rules from DB for the active_interface (for GET or after POST without interface change)
    bandwidth_rules.clear()
    group_limits.clear()
    if active_interface:
        app.logger.info(f"Loading rules for interface: {active_interface}")
        rules_from_db = Rule.query.filter_by(interface=active_interface).order_by(Rule.id).all()
        bandwidth_rules.extend(rules_from_db)
        group_limits_from_db = GroupLimit.query.filter_by(interface=active_interface).all()
        for gl in group_limits_from_db:
            group_limits.setdefault(gl.group_name, {})[gl.direction] = gl
    
    bandwidth_usage = get_bandwidth_usage(active_interface) if active_interface else {"rx_bytes": 0, "tx_bytes": 0}

    return render_template("dashboard.html",
                           interfaces=interfaces,
                           active_if=active_interface,
                           ips=bandwidth_rules, # Now contains full Rule objects
                           group_limits=group_limits,
                           bandwidth_usage=bandwidth_usage,
                           format_bytes=format_bytes)

@app.route("/set_ip", methods=["POST"])
def set_ip():
    if not session.get('logged_in') or session.get('role') != 'admin':
        flash("Unauthorized.", "danger"); return redirect(url_for('dashboard'))
    interface = session.get('active_interface')
    if not interface:
        flash("No active interface.", "danger"); return redirect(url_for('dashboard'))

    ip = request.form.get('ip')
    rate_value = request.form.get('rate_value')
    rate_unit = request.form.get('rate_unit') # e.g., mbps, kbps
    direction = request.form.get('direction')
    group = request.form.get('group_name') if request.form.get('group_name') else None # Ensure None if empty
    overwrite = 'overwrite_rule' in request.form

    protocol = request.form.get('protocol') if request.form.get('protocol') else None
    source_port = request.form.get('source_port') if request.form.get('source_port') else None
    destination_port = request.form.get('destination_port') if request.form.get('destination_port') else None
    
    description = request.form.get('description') if request.form.get('description') else None # NEW
    is_enabled = 'is_enabled' in request.form # NEW

    # NEW: Burst and Cburst for upload
    burst_value = request.form.get('burst_value') if request.form.get('burst_value') else None
    burst_unit = request.form.get('burst_unit') if request.form.get('burst_unit') else None
    cburst_value = request.form.get('cburst_value') if request.form.get('cburst_value') else None
    cburst_unit = request.form.get('cburst_unit') if request.form.get('cburst_unit') else None


    is_scheduled = 'enable_scheduling' in request.form
    start_time, end_time, weekdays, start_date, end_date = None, None, None, None, None
    if is_scheduled:
        start_time = request.form.get('start_time')
        end_time = request.form.get('end_time')
        weekdays_list = request.form.getlist('weekdays')
        weekdays = ",".join(weekdays_list) if weekdays_list else None
        start_date = request.form.get('start_date') if request.form.get('start_date') else None
        end_date = request.form.get('end_date') if request.form.get('end_date') else None
        if not start_time or not end_time : # Basic check
            flash("Start and End time required for scheduling.", "warning")
            is_scheduled = False # Disable scheduling if essential info missing

    # Basic IP Validation (can be more robust for IPv6)
    if not ip or not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^(?:[A-F0-9]{0,4}:){2,7}[A-F0-9]{0,4}$", ip, re.IGNORECASE): # Basic IPv4/IPv6
        flash("Invalid IP address format.", "danger"); return redirect(url_for('dashboard'))

    set_bandwidth_limit(interface, ip, rate_value, rate_unit, direction, group, overwrite,
                        protocol, source_port, destination_port,
                        is_scheduled, start_time, end_time, weekdays, start_date, end_date,
                        description, is_enabled, # NEW
                        burst_value, burst_unit, # NEW
                        cburst_value, cburst_unit) # NEW
    return redirect(url_for('dashboard'))

# --- NEW Route to toggle Rule Enable/Disable ---
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

# Management Routes
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

# Authentication Routes
@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get('logged_in'): return redirect(url_for('dashboard'))
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        # !!! --- WARNING: HARDCODED CREDENTIALS - DO NOT USE IN PRODUCTION --- !!!
        # Replace with a secure authentication mechanism (e.g., hashed passwords from DB)
        if username == "admin" and password == "password123": # Changed for slight variation
            session['logged_in'] = True
            session['role'] = 'admin'
            # Set default active interface if not set
            if 'active_interface' not in session:
                interfaces = get_interfaces()
                if interfaces: session['active_interface'] = interfaces[0]
            flash("Logged in successfully!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials.", "danger")
    return render_template("login.html") # You need to create this HTML file

@app.route("/logout")
def logout():
    session.pop('logged_in', None)
    session.pop('role', None)
    # session.pop('active_interface', None) # Keep active interface selection? Or clear? Let's clear.
    session.pop('active_interface', None)
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

# Status and Monitoring Routes
@app.route("/status")
def status():
    if not session.get('logged_in') or session.get('role') != 'admin':
        flash("Unauthorized.", "danger"); return redirect(url_for('dashboard'))
    
    # Consider using psutil here for more robust system info fetching
    uptime_str = run_command("uptime -p") or "N/A"
    cpu_usage_str = run_command("top -bn1 | grep '^%Cpu(s):' | awk '{print $2+$4}'") # Example
    if cpu_usage_str: cpu_usage_str = cpu_usage_str.strip() + "%"
    else: cpu_usage_str = "N/A"
    
    mem_info_str = run_command("free -m | awk '/^Mem:/{printf \"%.2f%% (%dMB/%dMB)\", $3/$2*100, $3, $2}'") or "N/A"
    disk_info_str = run_command("df -h / | awk 'NR==2{print $5 \" (\" $3 \"/\" $2 \")\"}'") or "N/A"

    interfaces = get_interfaces()
    active_interface = session.get('active_interface')
    network_status = {}
    for iface in interfaces:
        usage = get_bandwidth_usage(iface)
        network_status[iface] = usage

    return render_template("status.html", uptime=uptime_str, cpu_usage=cpu_usage_str,
                           mem_usage=mem_info_str, disk_usage=disk_info_str,
                           network_status=network_status, format_bytes=format_bytes,
                           interfaces=interfaces, active_if=active_interface) # Need status.html

@app.route("/logs")
def log_view():
    if not session.get('logged_in') or session.get('role') != 'admin':
        flash("Unauthorized.", "danger"); return redirect(url_for('dashboard'))
    log_lines_to_show = 300
    log_file_path = os.path.join('logs', app.config['LOG_FILE'])
    log_content = f"Log file not found: {log_file_path}"
    num_log_lines = 0
    if os.path.exists(log_file_path):
        log_output = run_command(f"tail -n {log_lines_to_show} {log_file_path}")
        if log_output is not None:
            log_content = log_output
            num_log_lines = log_content.count('\n') + (1 if log_content else 0)
        else:
            log_content = "Error reading log file."
    return render_template("logs.html", log_content=log_content, num_log_lines=num_log_lines,
                            interfaces=get_interfaces(), active_if=session.get('active_interface')) # Need logs.html

@app.route("/test_page") # Placeholder
def test_page():
    if not session.get('logged_in') or session.get('role') != 'admin':
        flash("Unauthorized.", "danger"); return redirect(url_for('dashboard'))
    return render_template("test_tools.html", interfaces=get_interfaces(), active_if=session.get('active_interface')) # Need test_tools.html

# API Routes
@app.route("/api/bandwidth_usage/<interface_name>") # Changed param name
def bandwidth_usage_api(interface_name):
    if not session.get('logged_in'): return make_response(jsonify({"error": "Unauthorized"}), 401)
    if interface_name not in get_interfaces(): return make_response(jsonify({"error": "Invalid interface"}), 400)
    return jsonify(get_bandwidth_usage(interface_name))

@app.route("/api/tc_stats/<interface_name>")
def tc_stats_api(interface_name):
    if not session.get('logged_in'): return make_response(jsonify({"error": "Unauthorized"}), 401)
    if interface_name not in get_interfaces(): return make_response(jsonify({"error": "Invalid interface"}), 400)
    return jsonify(get_tc_stats(interface_name))

# --- Main Execution Block ---
if __name__ == "__main__":
    app.logger.info("Application starting...")
    with app.app_context():
        db.create_all()
        app.logger.info("Database tables created (if they didn't exist).")

    # Start the scheduler if not already running (APScheduler checks this)
    if not scheduler.running:
        try:
            scheduler.start()
            app.logger.info("APScheduler started.")
        except Exception as e:
            app.logger.error(f"Failed to start APScheduler: {e}")
            # Decide if app should exit or continue without scheduler
    else:
        app.logger.info("APScheduler already running.")


    # --- Production Considerations (Reminder) ---
    # 1. Change app.secret_key (DONE, but ensure it's strong and ideally from env/config file)
    # 2. Use a production WSGI server (Gunicorn, uWSGI). Example: gunicorn -w 4 'app:app'
    # 3. Securely handle tc command permissions (sudoers.d or CAP_NET_ADMIN).
    # 4. Set debug=False.
    # 5. Externalize configurations (DB URI, secret key, admin credentials).
    # 6. Use a more robust DB than SQLite for high traffic.
    # 7. For APScheduler in production, use a persistent job store and a different executor if needed.

    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True) # debug=True for dev ONLY
    app.logger.info("Application stopped.")