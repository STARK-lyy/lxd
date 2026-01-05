# bot.py
import discord
from discord.ext import commands
import asyncio
import subprocess
import json
from datetime import datetime
import shlex
import logging
import shutil
import os
from typing import Optional, List, Dict, Any
import threading
import time
import sqlite3
import random

# Load environment variables
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
MAIN_ADMIN_ID = int(os.getenv('MAIN_ADMIN_ID', '1210291131301101618'))
VPS_USER_ROLE_ID = int(os.getenv('VPS_USER_ROLE_ID', '1210291131301101618'))
DEFAULT_STORAGE_POOL = os.getenv('DEFAULT_STORAGE_POOL', 'default')

# OS Options for VPS Creation
OS_OPTIONS = [
    {"label": "Ubuntu 20.04 LTS", "value": "ubuntu:20.04"},
    {"label": "Ubuntu 22.04 LTS", "value": "ubuntu:22.04"},
    {"label": "Ubuntu 24.04 LTS", "value": "ubuntu:24.04"},
    {"label": "Debian 10 (Buster)", "value": "images:debian/10"},
    {"label": "Debian 11 (Bullseye)", "value": "images:debian/11"},
    {"label": "Debian 12 (Bookworm)", "value": "images:debian/12"},
    {"label": "Debian 13 (Trixie)", "value": "images:debian/13"},
]

# Configure logging to file and console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('unixnodes_vps_bot')

# Check if lxc command is available
if not shutil.which("lxc"):
    logger.error("LXC command not found. Please ensure LXC is installed.")
    raise SystemExit("LXC command not found. Please ensure LXC is installed.")

# Database setup
def get_db():
    conn = sqlite3.connect('vps.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS admins (
        user_id TEXT PRIMARY KEY
    )''')
    cur.execute('INSERT OR IGNORE INTO admins (user_id) VALUES (?)', (str(MAIN_ADMIN_ID),))
    
    cur.execute('''CREATE TABLE IF NOT EXISTS vps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        container_name TEXT UNIQUE NOT NULL,
        ram TEXT NOT NULL,
        cpu TEXT NOT NULL,
        storage TEXT NOT NULL,
        config TEXT NOT NULL,
        os_version TEXT DEFAULT 'ubuntu:22.04',
        status TEXT DEFAULT 'stopped',
        suspended INTEGER DEFAULT 0,
        whitelisted INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        shared_with TEXT DEFAULT '[]',
        suspension_history TEXT DEFAULT '[]'
    )''')
    
    # Create port_forwarding table
    cur.execute('''CREATE TABLE IF NOT EXISTS port_forwarding (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        container_name TEXT NOT NULL,
        internal_port INTEGER NOT NULL,
        external_port INTEGER NOT NULL,
        protocol TEXT DEFAULT 'tcp',
        status TEXT DEFAULT 'active',
        created_at TEXT NOT NULL,
        expires_at TEXT,
        description TEXT,
        FOREIGN KEY (user_id) REFERENCES vps (user_id),
        UNIQUE(container_name, external_port)
    )''')
    
    # Create port_allocations table to track available ports
    cur.execute('''CREATE TABLE IF NOT EXISTS port_allocations (
        port INTEGER PRIMARY KEY,
        allocated INTEGER DEFAULT 0,
        allocated_to TEXT,
        allocated_at TEXT,
        container_name TEXT
    )''')
    
    # Create user_port_quota table
    cur.execute('''CREATE TABLE IF NOT EXISTS user_port_quota (
        user_id TEXT PRIMARY KEY,
        max_ports INTEGER DEFAULT 0,
        used_ports INTEGER DEFAULT 0,
        last_updated TEXT
    )''')
    
    # Migration for os_version column
    cur.execute('PRAGMA table_info(vps)')
    info = cur.fetchall()
    columns = [col[1] for col in info]
    if 'os_version' not in columns:
        cur.execute("ALTER TABLE vps ADD COLUMN os_version TEXT DEFAULT 'ubuntu:22.04'")
    
    cur.execute('''CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )''')
    
    settings_init = [
        ('cpu_threshold', '90'),
        ('ram_threshold', '90'),
        ('min_port', '30000'),
        ('max_port', '40000'),
        ('default_port_quota', '5'),
    ]
    for key, value in settings_init:
        cur.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (key, value))
    
    # Initialize port allocations if empty
    cur.execute('SELECT COUNT(*) as count FROM port_allocations')
    if cur.fetchone()['count'] == 0:
        min_port = int(get_setting('min_port', 30000))
        max_port = int(get_setting('max_port', 40000))
        for port in range(min_port, max_port + 1):
            cur.execute('INSERT OR IGNORE INTO port_allocations (port, allocated) VALUES (?, 0)', (port,))
    
    conn.commit()
    conn.close()

def get_setting(key: str, default: Any = None):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT value FROM settings WHERE key = ?', (key,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else default

def set_setting(key: str, value: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
    conn.commit()
    conn.close()

def get_vps_data() -> Dict[str, List[Dict[str, Any]]]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM vps')
    rows = cur.fetchall()
    conn.close()
    data = {}
    for row in rows:
        user_id = row['user_id']
        if user_id not in data:
            data[user_id] = []
        vps = dict(row)
        vps['shared_with'] = json.loads(vps['shared_with'])
        vps['suspension_history'] = json.loads(vps['suspension_history'])
        vps['suspended'] = bool(vps['suspended'])
        vps['whitelisted'] = bool(vps['whitelisted'])
        vps['os_version'] = vps.get('os_version', 'ubuntu:22.04')
        data[user_id].append(vps)
    return data

def get_admins() -> List[str]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT user_id FROM admins')
    rows = cur.fetchall()
    conn.close()
    return [row['user_id'] for row in rows]

def save_vps_data():
    conn = get_db()
    cur = conn.cursor()
    for user_id, vps_list in vps_data.items():
        for vps in vps_list:
            shared_json = json.dumps(vps['shared_with'])
            history_json = json.dumps(vps['suspension_history'])
            suspended_int = 1 if vps['suspended'] else 0
            whitelisted_int = 1 if vps.get('whitelisted', False) else 0
            os_ver = vps.get('os_version', 'ubuntu:22.04')
            if 'id' not in vps or vps['id'] is None:
                cur.execute('''INSERT INTO vps (user_id, container_name, ram, cpu, storage, config, os_version, status, suspended, whitelisted, created_at, shared_with, suspension_history)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                            (user_id, vps['container_name'], vps['ram'], vps['cpu'], vps['storage'], vps['config'],
                             os_ver, vps['status'], suspended_int, whitelisted_int,
                             vps['created_at'], shared_json, history_json))
                vps['id'] = cur.lastrowid
            else:
                cur.execute('''UPDATE vps SET user_id = ?, ram = ?, cpu = ?, storage = ?, config = ?, os_version = ?, status = ?, suspended = ?, whitelisted = ?, shared_with = ?, suspension_history = ?
                               WHERE id = ?''',
                            (user_id, vps['ram'], vps['cpu'], vps['storage'], vps['config'],
                             os_ver, vps['status'], suspended_int, whitelisted_int, shared_json, history_json, vps['id']))
    conn.commit()
    conn.close()

def save_admin_data():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM admins')
    for admin_id in admin_data['admins']:
        cur.execute('INSERT INTO admins (user_id) VALUES (?)', (admin_id,))
    conn.commit()
    conn.close()

# Initialize database
init_db()

# Load data at startup
vps_data = get_vps_data()
admin_data = {'admins': get_admins()}

# Global settings from DB
CPU_THRESHOLD = int(get_setting('cpu_threshold', 90))
RAM_THRESHOLD = int(get_setting('ram_threshold', 90))

# Bot setup
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)

# Resource monitoring settings
resource_monitor_active = True

# Helper function to truncate text to a specific length
def truncate_text(text, max_length=1024):
    if not text:
        return text
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."

# Embed creation functions with black theme and UnixNodes branding
def create_embed(title, description="", color=0x1a1a1a):
    embed = discord.Embed(
        title=truncate_text(f"⭐ UnixNodes - {title}", 256),
        description=truncate_text(description, 4096),
        color=color
    )
    embed.set_thumbnail(url="https://i.imgur.com/xSsIERx.png")
    embed.set_footer(text=f"UnixNodes VPS Manager • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                     icon_url="https://i.imgur.com/xSsIERx.png")
    return embed

def add_field(embed, name, value, inline=False):
    embed.add_field(
        name=truncate_text(f"▸ {name}", 256),
        value=truncate_text(value, 1024),
        inline=inline
    )
    return embed

def create_success_embed(title, description=""):
    return create_embed(title, description, color=0x00ff88)

def create_error_embed(title, description=""):
    return create_embed(title, description, color=0xff3366)

def create_info_embed(title, description=""):
    return create_embed(title, description, color=0x00ccff)

def create_warning_embed(title, description=""):
    return create_embed(title, description, color=0xffaa00)

# Admin checks
def is_admin():
    async def predicate(ctx):
        user_id = str(ctx.author.id)
        if user_id == str(MAIN_ADMIN_ID) or user_id in admin_data.get("admins", []):
            return True
        raise commands.CheckFailure("You need admin permissions to use this command. Contact UnixNodes support.")
    return commands.check(predicate)

def is_main_admin():
    async def predicate(ctx):
        if str(ctx.author.id) == str(MAIN_ADMIN_ID):
            return True
        raise commands.CheckFailure("Only the main admin can use this command.")
    return commands.check(predicate)

# Port Forwarding Functions
def get_user_port_quota(user_id: str) -> Dict[str, int]:
    """Get user's port quota"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT max_ports, used_ports FROM user_port_quota WHERE user_id = ?', (user_id,))
    row = cur.fetchone()
    conn.close()
    
    if row:
        return {'max_ports': row['max_ports'], 'used_ports': row['used_ports']}
    else:
        # Return default quota
        default_quota = int(get_setting('default_port_quota', 5))
        return {'max_ports': default_quota, 'used_ports': 0}

def set_user_port_quota(user_id: str, max_ports: int):
    """Set user's port quota"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''INSERT OR REPLACE INTO user_port_quota 
                   (user_id, max_ports, used_ports, last_updated) 
                   VALUES (?, ?, COALESCE((SELECT used_ports FROM user_port_quota WHERE user_id = ?), 0), ?)''',
                (user_id, max_ports, user_id, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_available_port() -> Optional[int]:
    """Get an available port from the pool"""
    conn = get_db()
    cur = conn.cursor()
    
    # Get port range from settings
    min_port = int(get_setting('min_port', 30000))
    max_port = int(get_setting('max_port', 40000))
    
    # Find an unallocated port
    cur.execute('''SELECT port FROM port_allocations 
                   WHERE port BETWEEN ? AND ? AND allocated = 0 
                   ORDER BY RANDOM() LIMIT 1''', 
                (min_port, max_port))
    row = cur.fetchone()
    
    if row:
        port = row['port']
        # Mark as allocated
        cur.execute('UPDATE port_allocations SET allocated = 1 WHERE port = ?', (port,))
        conn.commit()
        conn.close()
        return port
    else:
        # Try to find any unallocated port
        cur.execute('SELECT port FROM port_allocations WHERE allocated = 0 ORDER BY RANDOM() LIMIT 1')
        row = cur.fetchone()
        conn.close()
        return row['port'] if row else None

def release_port(port: int):
    """Release a port back to the pool"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('UPDATE port_allocations SET allocated = 0, allocated_to = NULL, allocated_at = NULL, container_name = NULL WHERE port = ?', (port,))
    conn.commit()
    conn.close()

def add_port_forwarding(user_id: str, container_name: str, internal_port: int, external_port: int, protocol: str = 'tcp', description: str = ""):
    """Add a port forwarding rule"""
    conn = get_db()
    cur = conn.cursor()
    
    # Check if external port is already allocated
    cur.execute('SELECT allocated FROM port_allocations WHERE port = ?', (external_port,))
    row = cur.fetchone()
    if row and row['allocated'] == 1:
        conn.close()
        return False, "Port already allocated"
    
    # Mark port as allocated
    cur.execute('UPDATE port_allocations SET allocated = 1, allocated_to = ?, allocated_at = ?, container_name = ? WHERE port = ?',
                (user_id, datetime.now().isoformat(), container_name, external_port))
    
    # Add port forwarding record
    cur.execute('''INSERT INTO port_forwarding 
                   (user_id, container_name, internal_port, external_port, protocol, status, created_at, description) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (user_id, container_name, internal_port, external_port, protocol, 'active', datetime.now().isoformat(), description))
    
    # Update user's used ports count
    cur.execute('SELECT used_ports FROM user_port_quota WHERE user_id = ?', (user_id,))
    quota_row = cur.fetchone()
    if quota_row:
        new_used = quota_row['used_ports'] + 1
        cur.execute('UPDATE user_port_quota SET used_ports = ?, last_updated = ? WHERE user_id = ?',
                    (new_used, datetime.now().isoformat(), user_id))
    else:
        # Create quota entry if it doesn't exist
        default_quota = int(get_setting('default_port_quota', 5))
        cur.execute('INSERT INTO user_port_quota (user_id, max_ports, used_ports, last_updated) VALUES (?, ?, 1, ?)',
                    (user_id, default_quota, datetime.now().isoformat()))
    
    conn.commit()
    conn.close()
    
    # Actually set up the port forwarding with iptables
    try:
        setup_iptables_forwarding(container_name, internal_port, external_port, protocol)
        return True, "Port forwarding added successfully"
    except Exception as e:
        # Rollback database changes if iptables fails
        remove_port_forwarding(external_port)
        return False, f"Failed to set up iptables: {str(e)}"

def remove_port_forwarding(external_port: int):
    """Remove a port forwarding rule"""
    conn = get_db()
    cur = conn.cursor()
    
    # Get forwarding info before deleting
    cur.execute('SELECT user_id, container_name, internal_port, protocol FROM port_forwarding WHERE external_port = ?', (external_port,))
    row = cur.fetchone()
    
    if row:
        user_id = row['user_id']
        
        # Remove iptables rules
        try:
            remove_iptables_forwarding(row['container_name'], row['internal_port'], external_port, row['protocol'])
        except Exception as e:
            logger.error(f"Failed to remove iptables rules for port {external_port}: {e}")
        
        # Delete port forwarding record
        cur.execute('DELETE FROM port_forwarding WHERE external_port = ?', (external_port,))
        
        # Release the port
        release_port(external_port)
        
        # Update user's used ports count
        cur.execute('SELECT used_ports FROM user_port_quota WHERE user_id = ?', (user_id,))
        quota_row = cur.fetchone()
        if quota_row and quota_row['used_ports'] > 0:
            new_used = quota_row['used_ports'] - 1
            cur.execute('UPDATE user_port_quota SET used_ports = ?, last_updated = ? WHERE user_id = ?',
                        (new_used, datetime.now().isoformat(), user_id))
        
        conn.commit()
        conn.close()
        return True, "Port forwarding removed successfully"
    
    conn.close()
    return False, "Port forwarding not found"

def get_user_port_forwardings(user_id: str):
    """Get all port forwardings for a user"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''SELECT * FROM port_forwarding 
                   WHERE user_id = ? AND status = 'active' 
                   ORDER BY created_at DESC''', (user_id,))
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_vps_port_forwardings(container_name: str):
    """Get all port forwardings for a VPS"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''SELECT * FROM port_forwarding 
                   WHERE container_name = ? AND status = 'active' 
                   ORDER BY internal_port''', (container_name,))
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_container_ip(container_name: str) -> Optional[str]:
    """Get the IP address of a container"""
    try:
        proc = subprocess.run(['lxc', 'list', container_name, '--format', 'json'], 
                             capture_output=True, text=True)
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            if data and len(data) > 0:
                # Try to get IPv4 address
                for network in data[0]['state']['network'].values():
                    for addr in network.get('addresses', []):
                        if addr['family'] == 'inet' and addr['scope'] == 'global':
                            return addr['address']
        return None
    except Exception as e:
        logger.error(f"Error getting IP for {container_name}: {e}")
        return None

def setup_iptables_forwarding(container_name: str, internal_port: int, external_port: int, protocol: str = 'tcp'):
    """Set up iptables rules for port forwarding"""
    container_ip = get_container_ip(container_name)
    if not container_ip:
        raise Exception(f"Could not get IP address for container {container_name}")
    
    # Flush existing rules for this external port
    subprocess.run(['iptables', '-t', 'nat', '-D', 'PREROUTING', '-p', protocol, 
                    '--dport', str(external_port), '-j', 'DNAT', 
                    '--to-destination', f'{container_ip}:{internal_port}'], 
                   stderr=subprocess.DEVNULL)
    
    # Add new rule
    subprocess.run(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', protocol, 
                    '--dport', str(external_port), '-j', 'DNAT', 
                    '--to-destination', f'{container_ip}:{internal_port}'], 
                   check=True)
    
    # Allow traffic in FORWARD chain
    subprocess.run(['iptables', '-A', 'FORWARD', '-p', protocol, 
                    '-d', container_ip, '--dport', str(internal_port), '-j', 'ACCEPT'], 
                   check=True)
    
    logger.info(f"Set up port forwarding: {external_port} -> {container_ip}:{internal_port} ({protocol})")

def remove_iptables_forwarding(container_name: str, internal_port: int, external_port: int, protocol: str = 'tcp'):
    """Remove iptables rules for port forwarding"""
    container_ip = get_container_ip(container_name)
    if not container_ip:
        logger.warning(f"Could not get IP for {container_name} to remove iptables rules")
        return
    
    # Remove PREROUTING rule
    subprocess.run(['iptables', '-t', 'nat', '-D', 'PREROUTING', '-p', protocol, 
                    '--dport', str(external_port), '-j', 'DNAT', 
                    '--to-destination', f'{container_ip}:{internal_port}'], 
                   stderr=subprocess.DEVNULL)
    
    # Remove FORWARD rule
    subprocess.run(['iptables', '-D', 'FORWARD', '-p', protocol, 
                    '-d', container_ip, '--dport', str(internal_port), '-j', 'ACCEPT'], 
                   stderr=subprocess.DEVNULL)
    
    logger.info(f"Removed port forwarding: {external_port} -> {container_ip}:{internal_port}")

# Clean LXC command execution with improved timeout handling
async def execute_lxc(command, timeout=120):
    try:
        cmd = shlex.split(command)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise asyncio.TimeoutError(f"Command timed out after {timeout} seconds")
        if proc.returncode != 0:
            error = stderr.decode().strip() if stderr else "Command failed with no error output"
            raise Exception(error)
        return stdout.decode().strip() if stdout else True
    except asyncio.TimeoutError as te:
        logger.error(f"LXC command timed out: {command} - {str(te)}")
        raise
    except Exception as e:
        logger.error(f"LXC Error: {command} - {str(e)}")
        raise

# Function to apply advanced permissions to a container
async def apply_advanced_permissions(container_name):
    try:
        await execute_lxc(f"lxc config set {container_name} security.nesting true")
        await execute_lxc(f"lxc config set {container_name} security.privileged true")
        await execute_lxc(f"lxc config device add {container_name} fuse unix-char path=/dev/fuse")
        await execute_lxc(f"lxc config set {container_name} linux.kernel_modules overlay,loop")
        logger.info(f"Applied advanced permissions to {container_name}")
    except Exception as e:
        logger.error(f"Failed to apply advanced permissions to {container_name}: {e}")
        logger.warning(f"Continuing without full permissions for {container_name}. Check logs for details.")

# Get or create VPS user role
async def get_or_create_vps_role(guild):
    global VPS_USER_ROLE_ID
    if VPS_USER_ROLE_ID:
        role = guild.get_role(VPS_USER_ROLE_ID)
        if role:
            return role
    role = discord.utils.get(guild.roles, name="UnixNodes VPS User")
    if role:
        VPS_USER_ROLE_ID = role.id
        return role
    try:
        role = await guild.create_role(
            name="UnixNodes VPS User",
            color=discord.Color.dark_purple(),
            reason="UnixNodes VPS User role for bot management",
            permissions=discord.Permissions.none()
        )
        VPS_USER_ROLE_ID = role.id
        logger.info(f"Created UnixNodes VPS User role: {role.name} (ID: {role.id})")
        return role
    except Exception as e:
        logger.error(f"Failed to create UnixNodes VPS User role: {e}")
        return None

# Host resource monitoring functions
def get_cpu_usage():
    try:
        if shutil.which("mpstat"):
            result = subprocess.run(['mpstat', '1', '1'], capture_output=True, text=True)
            output = result.stdout
            for line in output.split('\n'):
                if 'all' in line and '%' in line:
                    parts = line.split()
                    idle = float(parts[-1])
                    return 100.0 - idle
        else:
            result = subprocess.run(['top', '-bn1'], capture_output=True, text=True)
            output = result.stdout
            for line in output.split('\n'):
                if '%Cpu(s):' in line:
                    parts = line.split()
                    us = float(parts[1])
                    sy = float(parts[3])
                    ni = float(parts[5])
                    id_ = float(parts[7])
                    wa = float(parts[9])
                    hi = float(parts[11])
                    si = float(parts[13])
                    st = float(parts[15])
                    usage = us + sy + ni + wa + hi + si + st
                    return usage
        return 0.0
    except Exception as e:
        logger.error(f"Error getting CPU usage: {e}")
        return 0.0

def get_ram_usage():
    try:
        result = subprocess.run(['free', '-m'], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        if len(lines) > 1:
            mem = lines[1].split()
            total = int(mem[1])
            used = int(mem[2])
            return (used / total * 100) if total > 0 else 0.0
        return 0.0
    except Exception as e:
        logger.error(f"Error getting RAM usage: {e}")
        return 0.0

def resource_monitor():
    global resource_monitor_active
    while resource_monitor_active:
        try:
            cpu_usage = get_cpu_usage()
            ram_usage = get_ram_usage()
            logger.info(f"Current CPU usage: {cpu_usage:.1f}%, RAM usage: {ram_usage:.1f}%")
            if cpu_usage > CPU_THRESHOLD or ram_usage > RAM_THRESHOLD:
                logger.warning(f"Resource usage exceeded thresholds (CPU: {CPU_THRESHOLD}%, RAM: {RAM_THRESHOLD}%). Stopping all VPS.")
                try:
                    subprocess.run(['lxc', 'stop', '--all', '--force'], check=True)
                    logger.info("All VPS stopped due to high resource usage")
                    for user_id, vps_list in list(vps_data.items()):
                        for vps in vps_list:
                            if vps.get('status') == 'running':
                                vps['status'] = 'stopped'
                    save_vps_data()
                except Exception as e:
                    logger.error(f"Error stopping all VPS: {e}")
            time.sleep(60)
        except Exception as e:
            logger.error(f"Error in resource monitor: {e}")
            time.sleep(60)

# Start resource monitoring in a separate thread
monitor_thread = threading.Thread(target=resource_monitor, daemon=True)
monitor_thread.start()

# Helper functions for container stats with improved error handling
async def get_container_status(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "info", container_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode()
        for line in output.splitlines():
            if line.startswith("Status: "):
                return line.split(": ", 1)[1].strip().lower()
        return "unknown"
    except Exception:
        return "unknown"

async def get_container_cpu(container_name):
    usage = await get_container_cpu_pct(container_name)
    return f"{usage:.1f}%"

async def get_container_cpu_pct(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "top", "-bn1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode()
        for line in output.splitlines():
            if '%Cpu(s):' in line:
                parts = line.split()
                us = float(parts[1])
                sy = float(parts[3])
                ni = float(parts[5])
                id_ = float(parts[7])
                wa = float(parts[9])
                hi = float(parts[11])
                si = float(parts[13])
                st = float(parts[15])
                usage = us + sy + ni + wa + hi + si + st
                return usage
        return 0.0
    except Exception as e:
        logger.error(f"Error getting CPU for {container_name}: {e}")
        return 0.0

async def get_container_memory(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "free", "-m",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        lines = stdout.decode().splitlines()
        if len(lines) > 1:
            parts = lines[1].split()
            total = int(parts[1])
            used = int(parts[2])
            usage_pct = (used / total * 100) if total > 0 else 0
            return f"{used}/{total} MB ({usage_pct:.1f}%)"
        return "Unknown"
    except Exception:
        return "Unknown"

async def get_container_ram_pct(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "free", "-m",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        lines = stdout.decode().splitlines()
        if len(lines) > 1:
            parts = lines[1].split()
            total = int(parts[1])
            used = int(parts[2])
            usage_pct = (used / total * 100) if total > 0 else 0
            return usage_pct
        return 0.0
    except Exception as e:
        logger.error(f"Error getting RAM for {container_name}: {e}")
        return 0.0

async def get_container_disk(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "df", "-h", "/",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        lines = stdout.decode().splitlines()
        for line in lines:
            if '/dev/' in line and ' /' in line:
                parts = line.split()
                if len(parts) >= 5:
                    used = parts[2]
                    size = parts[1]
                    perc = parts[4]
                    return f"{used}/{size} ({perc})"
        return "Unknown"
    except Exception:
        return "Unknown"

async def get_container_uptime(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "uptime",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        return stdout.decode().strip() if stdout else "Unknown"
    except Exception:
        return "Unknown"

def get_uptime():
    try:
        result = subprocess.run(['uptime'], capture_output=True, text=True)
        return result.stdout.strip()
    except Exception:
        return "Unknown"

# Bot events
@bot.event
async def on_ready():
    logger.info(f'{bot.user} has connected to Discord!')
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="UnixNodes VPS Manager"))
    logger.info("UnixNodes Bot is ready!")

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(embed=create_error_embed("Missing Argument", "Please check command usage with `!help`."))
    elif isinstance(error, commands.BadArgument):
        await ctx.send(embed=create_error_embed("Invalid Argument", "Please check your input and try again."))
    elif isinstance(error, commands.CheckFailure):
        error_msg = str(error) if str(error) else "You need admin permissions for this command. Contact UnixNodes support."
        await ctx.send(embed=create_error_embed("Access Denied", error_msg))
    elif isinstance(error, discord.NotFound):
        await ctx.send(embed=create_error_embed("Error", "The requested resource was not found. Please try again."))
    else:
        logger.error(f"Command error: {error}")
        await ctx.send(embed=create_error_embed("System Error", "An unexpected error occurred. UnixNodes support has been notified."))

# Bot commands
@bot.command(name='ping')
async def ping(ctx):
    latency = round(bot.latency * 1000)
    embed = create_success_embed("Pong!", f"UnixNodes Bot latency: {latency}ms")
    await ctx.send(embed=embed)

@bot.command(name='uptime')
async def uptime(ctx):
    up = get_uptime()
    embed = create_info_embed("Host Uptime", up)
    await ctx.send(embed=embed)

@bot.command(name='thresholds')
@is_admin()
async def thresholds(ctx):
    embed = create_info_embed("Resource Thresholds", f"**CPU:** {CPU_THRESHOLD}%\n**RAM:** {RAM_THRESHOLD}%")
    await ctx.send(embed=embed)

@bot.command(name='set-threshold')
@is_admin()
async def set_threshold(ctx, cpu: int, ram: int):
    global CPU_THRESHOLD, RAM_THRESHOLD
    if cpu < 0 or ram < 0:
        await ctx.send(embed=create_error_embed("Invalid Thresholds", "Thresholds must be non-negative."))
        return
    CPU_THRESHOLD = cpu
    RAM_THRESHOLD = ram
    set_setting('cpu_threshold', str(cpu))
    set_setting('ram_threshold', str(ram))
    embed = create_success_embed("Thresholds Updated", f"**CPU:** {cpu}%\n**RAM:** {ram}%")
    await ctx.send(embed=embed)

@bot.command(name='set-status')
@is_admin()
async def set_status(ctx, activity_type: str, *, name: str):
    types = {
        'playing': discord.ActivityType.playing,
        'watching': discord.ActivityType.watching,
        'listening': discord.ActivityType.listening,
        'streaming': discord.ActivityType.streaming,
    }
    if activity_type.lower() not in types:
        await ctx.send(embed=create_error_embed("Invalid Type", "Valid types: playing, watching, listening, streaming"))
        return
    await bot.change_presence(activity=discord.Activity(type=types[activity_type.lower()], name=name))
    embed = create_success_embed("Status Updated", f"Set to {activity_type}: {name}")
    await ctx.send(embed=embed)

@bot.command(name='myvps')
async def my_vps(ctx):
    user_id = str(ctx.author.id)
    vps_list = vps_data.get(user_id, [])
    if not vps_list:
        embed = create_error_embed("No VPS Found", "You don't have any UnixNodes VPS. Contact an admin to create one.")
        add_field(embed, "Quick Actions", "• `!manage` - Manage VPS\n• Contact UnixNodes admin for VPS creation", False)
        await ctx.send(embed=embed)
        return
    embed = create_info_embed("My UnixNodes VPS", "")
    text = []
    for i, vps in enumerate(vps_list):
        status = vps.get('status', 'unknown').upper()
        if vps.get('suspended', False):
            status += " (SUSPENDED)"
        if vps.get('whitelisted', False):
            status += " (WHITELISTED)"
        config = vps.get('config', 'Custom')
        text.append(f"**VPS {i+1}:** `{vps['container_name']}` - {status} - {config}")
    add_field(embed, "Your VPS", "\n".join(text), False)
    add_field(embed, "Actions", "Use `!manage` to start/stop/reinstall", False)
    await ctx.send(embed=embed)

@bot.command(name='lxc-list')
@is_admin()
async def lxc_list(ctx):
    try:
        result = await execute_lxc("lxc list")
        embed = create_info_embed("UnixNodes LXC Containers List", result)
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(embed=create_error_embed("Error", str(e)))

class OSSelectView(discord.ui.View):
    def __init__(self, ram: int, cpu: int, disk: int, user: discord.Member, ctx):
        super().__init__(timeout=300)
        self.ram = ram
        self.cpu = cpu
        self.disk = disk
        self.user = user
        self.ctx = ctx
        self.select = discord.ui.Select(
            placeholder="Select an OS for the VPS",
            options=[discord.SelectOption(label=o["label"], value=o["value"]) for o in OS_OPTIONS]
        )
        self.select.callback = self.select_os
        self.add_item(self.select)

    async def select_os(self, interaction: discord.Interaction):
        if str(interaction.user.id) != str(self.ctx.author.id):
            await interaction.response.send_message(embed=create_error_embed("Access Denied", "Only the command author can select."), ephemeral=True)
            return
        os_version = self.select.values[0]
        self.select.disabled = True
        creating_embed = create_info_embed("Creating VPS", f"Deploying {os_version} VPS for {self.user.mention}...")
        await interaction.response.edit_message(embed=creating_embed, view=self)
        user_id = str(self.user.id)
        if user_id not in vps_data:
            vps_data[user_id] = []
        vps_count = len(vps_data[user_id]) + 1
        container_name = f"unixnodes-vps-{user_id}-{vps_count}"
        ram_mb = self.ram * 1024
        try:
            await execute_lxc(f"lxc init {os_version} {container_name} -s {DEFAULT_STORAGE_POOL}")
            await execute_lxc(f"lxc config set {container_name} limits.memory {ram_mb}MB")
            await execute_lxc(f"lxc config set {container_name} limits.cpu {self.cpu}")
            await execute_lxc(f"lxc config device set {container_name} root size={self.disk}GB")
            await apply_advanced_permissions(container_name)
            await execute_lxc(f"lxc start {container_name}")
            config_str = f"{self.ram}GB RAM / {self.cpu} CPU / {self.disk}GB Disk"
            vps_info = {
                "container_name": container_name,
                "ram": f"{self.ram}GB",
                "cpu": str(self.cpu),
                "storage": f"{self.disk}GB",
                "config": config_str,
                "os_version": os_version,
                "status": "running",
                "suspended": False,
                "whitelisted": False,
                "suspension_history": [],
                "created_at": datetime.now().isoformat(),
                "shared_with": [],
                "id": None
            }
            vps_data[user_id].append(vps_info)
            save_vps_data()
            if self.ctx.guild:
                vps_role = await get_or_create_vps_role(self.ctx.guild)
                if vps_role:
                    try:
                        await self.user.add_roles(vps_role, reason="UnixNodes VPS ownership granted")
                    except discord.Forbidden:
                        logger.warning(f"Failed to assign UnixNodes VPS role to {self.user.name}")
            success_embed = create_success_embed("UnixNodes VPS Created Successfully")
            add_field(success_embed, "Owner", self.user.mention, True)
            add_field(success_embed, "VPS ID", f"#{vps_count}", True)
            add_field(success_embed, "Container", f"`{container_name}`", True)
            add_field(success_embed, "Resources", f"**RAM:** {self.ram}GB\n**CPU:** {self.cpu} Cores\n**Storage:** {self.disk}GB", False)
            add_field(success_embed, "OS", os_version, True)
            add_field(success_embed, "Features", "Nesting, Privileged, FUSE, Kernel Modules (Docker Ready)", False)
            add_field(success_embed, "Disk Note", "Run `sudo resize2fs /` inside VPS if needed to expand filesystem.", False)
            await interaction.followup.send(embed=success_embed)
            dm_embed = create_success_embed("UnixNodes VPS Created!", f"Your VPS has been successfully deployed by an admin!")
            add_field(dm_embed, "VPS Details", f"**VPS ID:** #{vps_count}\n**Container Name:** `{container_name}`\n**Configuration:** {config_str}\n**Status:** Running\n**OS:** {os_version}\n**Created:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", False)
            add_field(dm_embed, "Management", "• Use `!manage` to start/stop/reinstall your UnixNodes VPS\n• Use `!manage` → SSH for terminal access\n• Contact UnixNodes admin for upgrades or issues", False)
            add_field(dm_embed, "Important Notes", "• Full root access via SSH\n• Docker-ready with nesting and privileged mode\n• Back up your data regularly", False)
            try:
                await self.user.send(embed=dm_embed)
            except discord.Forbidden:
                await self.ctx.send(embed=create_info_embed("Notification Failed", f"Couldn't send DM to {self.user.mention}. Please ensure DMs are enabled."))
        except Exception as e:
            error_embed = create_error_embed("Creation Failed", f"Error: {str(e)}")
            await interaction.followup.send(embed=error_embed)

@bot.command(name='create')
@is_admin()
async def create_vps(ctx, ram: int, cpu: int, disk: int, user: discord.Member):
    if ram <= 0 or cpu <= 0 or disk <= 0:
        await ctx.send(embed=create_error_embed("Invalid Specs", "RAM, CPU, and Disk must be positive integers."))
        return
    embed = create_info_embed("VPS Creation", f"Creating VPS for {user.mention} with {ram}GB RAM, {cpu} CPU cores, {disk}GB Disk.\nSelect OS below.")
    view = OSSelectView(ram, cpu, disk, user, ctx)
    await ctx.send(embed=embed, view=view)

class ManageView(discord.ui.View):
    def __init__(self, user_id, vps_list, is_shared=False, owner_id=None, is_admin=False, actual_index: Optional[int] = None):
        super().__init__(timeout=300)
        self.user_id = user_id
        self.vps_list = vps_list[:]
        self.selected_index = None
        self.is_shared = is_shared
        self.owner_id = owner_id or user_id
        self.is_admin = is_admin
        self.actual_index = actual_index
        self.indices = list(range(len(vps_list)))
        if self.is_shared and self.actual_index is None:
            raise ValueError("actual_index required for shared views")
        if len(vps_list) > 1:
            options = [
                discord.SelectOption(
                    label=f"UnixNodes VPS {i+1} ({v.get('config', 'Custom')})",
                    description=f"Status: {v.get('status', 'unknown')}",
                    value=str(i)
                ) for i, v in enumerate(vps_list)
            ]
            self.select = discord.ui.Select(placeholder="Select a UnixNodes VPS to manage", options=options)
            self.select.callback = self.select_vps
            self.add_item(self.select)
            self.initial_embed = create_embed("UnixNodes VPS Management", "Select a VPS from the dropdown menu below.", 0x1a1a1a)
            add_field(self.initial_embed, "Available VPS", "\n".join([f"**VPS {i+1}:** `{v['container_name']}` - Status: `{v.get('status', 'unknown').upper()}`" for i, v in enumerate(vps_list)]), False)
        else:
            self.selected_index = 0
            self.initial_embed = None
            self.add_action_buttons()

    async def get_initial_embed(self):
        if self.initial_embed is not None:
            return self.initial_embed
        self.initial_embed = await self.create_vps_embed(self.selected_index)
        return self.initial_embed

    async def create_vps_embed(self, index):
        vps = self.vps_list[index]
        status = vps.get('status', 'unknown')
        suspended = vps.get('suspended', False)
        whitelisted = vps.get('whitelisted', False)
        status_color = 0x00ff88 if status == 'running' and not suspended else 0xffaa00 if suspended else 0xff3366
        container_name = vps['container_name']
        lxc_status = await get_container_status(container_name)
        cpu_usage = await get_container_cpu(container_name)
        memory_usage = await get_container_memory(container_name)
        disk_usage = await get_container_disk(container_name)
        uptime = await get_container_uptime(container_name)
        status_text = f"{lxc_status.upper()}"
        if suspended:
            status_text += " (SUSPENDED)"
        if whitelisted:
            status_text += " (WHITELISTED)"
        owner_text = ""
        if self.is_admin and self.owner_id != self.user_id:
            try:
                owner_user = await bot.fetch_user(int(self.owner_id))
                owner_text = f"\n**Owner:** {owner_user.mention}"
            except:
                owner_text = f"\n**Owner ID:** {self.owner_id}"
        embed = create_embed(
            f"UnixNodes VPS Management - VPS {index + 1}",
            f"Managing container: `{container_name}`{owner_text}",
            status_color
        )
        resource_info = f"**Configuration:** {vps.get('config', 'Custom')}\n"
        resource_info += f"**Status:** `{status_text}`\n"
        resource_info += f"**RAM:** {vps['ram']}\n"
        resource_info += f"**CPU:** {vps['cpu']} Cores\n"
        resource_info += f"**Storage:** {vps['storage']}\n"
        resource_info += f"**OS:** {vps.get('os_version', 'ubuntu:22.04')}\n"
        resource_info += f"**Uptime:** {uptime}"
        add_field(embed, "📊 Allocated Resources", resource_info, False)
        if suspended:
            add_field(embed, "⚠️ Suspended", "This UnixNodes VPS is suspended. Contact an admin to unsuspend.", False)
        if whitelisted:
            add_field(embed, "✅ Whitelisted", "This VPS is exempt from auto-suspension.", False)
        live_stats = f"**CPU Usage:** {cpu_usage}\n**Memory:** {memory_usage}\n**Disk:** {disk_usage}"
        add_field(embed, "📈 Live Usage", live_stats, False)
        add_field(embed, "🎮 Controls", "Use the buttons below to manage your UnixNodes VPS", False)
        return embed

    def add_action_buttons(self):
        if not self.is_shared and not self.is_admin:
            reinstall_button = discord.ui.Button(label="🔄 Reinstall", style=discord.ButtonStyle.danger)
            reinstall_button.callback = lambda inter: self.action_callback(inter, 'reinstall')
            self.add_item(reinstall_button)
        start_button = discord.ui.Button(label="▶ Start", style=discord.ButtonStyle.success)
        start_button.callback = lambda inter: self.action_callback(inter, 'start')
        stop_button = discord.ui.Button(label="⏸ Stop", style=discord.ButtonStyle.secondary)
        stop_button.callback = lambda inter: self.action_callback(inter, 'stop')
        ssh_button = discord.ui.Button(label="🔑 SSH", style=discord.ButtonStyle.primary)
        ssh_button.callback = lambda inter: self.action_callback(inter, 'tmate')
        stats_button = discord.ui.Button(label="📊 Stats", style=discord.ButtonStyle.secondary)
        stats_button.callback = lambda inter: self.action_callback(inter, 'stats')
        self.add_item(start_button)
        self.add_item(stop_button)
        self.add_item(ssh_button)
        self.add_item(stats_button)

    async def select_vps(self, interaction: discord.Interaction):
        if str(interaction.user.id) != self.user_id and not self.is_admin:
            await interaction.response.send_message(embed=create_error_embed("Access Denied", "This is not your UnixNodes VPS!"), ephemeral=True)
            return
        self.selected_index = int(self.select.values[0])
        new_embed = await self.create_vps_embed(self.selected_index)
        self.clear_items()
        self.add_action_buttons()
        await interaction.response.edit_message(embed=new_embed, view=self)

    async def action_callback(self, interaction: discord.Interaction, action: str):
        if str(interaction.user.id) != self.user_id and not self.is_admin:
            await interaction.response.send_message(embed=create_error_embed("Access Denied", "This is not your UnixNodes VPS!"), ephemeral=True)
            return
        if self.selected_index is None:
            await interaction.response.send_message(embed=create_error_embed("No VPS Selected", "Please select a VPS first."), ephemeral=True)
            return
        actual_idx = self.actual_index if self.is_shared else self.indices[self.selected_index]
        target_vps = vps_data[self.owner_id][actual_idx]
        suspended = target_vps.get('suspended', False)
        if suspended and not self.is_admin and action != 'stats':
            await interaction.response.send_message(embed=create_error_embed("Access Denied", "This UnixNodes VPS is suspended. Contact an admin to unsuspend."), ephemeral=True)
            return
        container_name = target_vps["container_name"]
        if action == 'stats':
            status = await get_container_status(container_name)
            cpu_usage = await get_container_cpu(container_name)
            memory_usage = await get_container_memory(container_name)
            disk_usage = await get_container_disk(container_name)
            uptime = await get_container_uptime(container_name)
            stats_embed = create_info_embed("📈 UnixNodes Live Statistics", f"Real-time stats for `{container_name}`")
            add_field(stats_embed, "Status", f"`{status.upper()}`", True)
            add_field(stats_embed, "CPU", cpu_usage, True)
            add_field(stats_embed, "Memory", memory_usage, True)
            add_field(stats_embed, "Disk", disk_usage, True)
            add_field(stats_embed, "Uptime", uptime, True)
            await interaction.response.send_message(embed=stats_embed, ephemeral=True)
            return
        if action == 'reinstall':
            if self.is_shared or self.is_admin:
                await interaction.response.send_message(embed=create_error_embed("Access Denied", "Only the UnixNodes VPS owner can reinstall!"), ephemeral=True)
                return
            if suspended:
                await interaction.response.send_message(embed=create_error_embed("Cannot Reinstall", "Unsuspend the UnixNodes VPS first."), ephemeral=True)
                return
            os_version = target_vps.get('os_version', 'ubuntu:22.04')
            confirm_embed = create_warning_embed("UnixNodes Reinstall Warning",
                f"⚠️ **WARNING:** This will erase all data on VPS `{container_name}` and reinstall {os_version}.\n\n"
                f"This action cannot be undone. Continue?")
            class ConfirmView(discord.ui.View):
                def __init__(self, parent_view, container_name, owner_id, actual_idx):
                    super().__init__(timeout=60)
                    self.parent_view = parent_view
                    self.container_name = container_name
                    self.owner_id = owner_id
                    self.actual_idx = actual_idx

                @discord.ui.button(label="Confirm", style=discord.ButtonStyle.danger)
                async def confirm(self, inter: discord.Interaction, item: discord.ui.Button):
                    await inter.response.defer(ephemeral=True)
                    try:
                        await inter.followup.send(embed=create_info_embed("Deleting Container", f"Forcefully removing container `{self.container_name}`..."), ephemeral=True)
                        await execute_lxc(f"lxc delete {self.container_name} --force")
                        await inter.followup.send(embed=create_info_embed("Recreating Container", f"Creating new UnixNodes container `{self.container_name}`..."), ephemeral=True)
                        target_vps = vps_data[self.owner_id][self.actual_idx]
                        original_ram = target_vps["ram"]
                        original_cpu = target_vps["cpu"]
                        original_storage = target_vps["storage"]
                        ram_gb = int(original_ram.replace("GB", ""))
                        ram_mb = ram_gb * 1024
                        storage_gb = int(original_storage.replace("GB", ""))
                        os_version = target_vps.get('os_version', 'ubuntu:22.04')
                        await execute_lxc(f"lxc init {os_version} {self.container_name} -s {DEFAULT_STORAGE_POOL}")
                        await execute_lxc(f"lxc config set {self.container_name} limits.memory {ram_mb}MB")
                        await execute_lxc(f"lxc config set {self.container_name} limits.cpu {original_cpu}")
                        await execute_lxc(f"lxc config device set {self.container_name} root size={storage_gb}GB")
                        await apply_advanced_permissions(self.container_name)
                        await execute_lxc(f"lxc start {self.container_name}")
                        target_vps["status"] = "running"
                        target_vps["suspended"] = False
                        target_vps["created_at"] = datetime.now().isoformat()
                        config_str = f"{ram_gb}GB RAM / {original_cpu} CPU / {storage_gb}GB Disk"
                        target_vps["config"] = config_str
                        save_vps_data()
                        await inter.followup.send(embed=create_success_embed("Reinstall Complete", f"UnixNodes VPS `{self.container_name}` has been successfully reinstalled!"), ephemeral=True)
                        new_embed = await self.parent_view.create_vps_embed(self.parent_view.selected_index)
                        await inter.followup.send(embed=new_embed, view=self.parent_view, ephemeral=True)
                    except Exception as e:
                        await inter.followup.send(embed=create_error_embed("Reinstall Failed", f"Error: {str(e)}"), ephemeral=True)

                @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
                async def cancel(self, inter: discord.Interaction, item: discord.ui.Button):
                    new_embed = await self.parent_view.create_vps_embed(self.parent_view.selected_index)
                    await inter.response.edit_message(embed=new_embed, view=self.parent_view)
            await interaction.response.send_message(embed=confirm_embed, view=ConfirmView(self, container_name, self.owner_id, actual_idx), ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)
        suspended = target_vps.get('suspended', False)
        if suspended:
            target_vps['suspended'] = False
            save_vps_data()
        if action == 'start':
            try:
                await execute_lxc(f"lxc start {container_name}")
                target_vps["status"] = "running"
                save_vps_data()
                await interaction.followup.send(embed=create_success_embed("VPS Started", f"UnixNodes VPS `{container_name}` is now running!"), ephemeral=True)
            except Exception as e:
                await interaction.followup.send(embed=create_error_embed("Start Failed", str(e)), ephemeral=True)
        elif action == 'stop':
            try:
                await execute_lxc(f"lxc stop {container_name}", timeout=120)
                target_vps["status"] = "stopped"
                save_vps_data()
                await interaction.followup.send(embed=create_success_embed("VPS Stopped", f"UnixNodes VPS `{container_name}` has been stopped!"), ephemeral=True)
            except Exception as e:
                await interaction.followup.send(embed=create_error_embed("Stop Failed", str(e)), ephemeral=True)
        elif action == 'tmate':
            if suspended:
                await interaction.followup.send(embed=create_error_embed("Access Denied", "Cannot access suspended UnixNodes VPS."), ephemeral=True)
                return
            await interaction.followup.send(embed=create_info_embed("SSH Access", "Generating UnixNodes SSH connection..."), ephemeral=True)
            try:
                check_proc = await asyncio.create_subprocess_exec(
                    "lxc", "exec", container_name, "--", "which", "tmate",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await check_proc.communicate()
                if check_proc.returncode != 0:
                    await interaction.followup.send(embed=create_info_embed("Installing SSH", "Installing tmate..."), ephemeral=True)
                    await execute_lxc(f"lxc exec {container_name} -- apt-get update -y")
                    await execute_lxc(f"lxc exec {container_name} -- apt-get install tmate -y")
                    await interaction.followup.send(embed=create_success_embed("Installed", "UnixNodes SSH service installed!"), ephemeral=True)
                session_name = f"unixnodes-session-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                await execute_lxc(f"lxc exec {container_name} -- tmate -S /tmp/{session_name}.sock new-session -d")
                await asyncio.sleep(3)
                ssh_proc = await asyncio.create_subprocess_exec(
                    "lxc", "exec", container_name, "--", "tmate", "-S", f"/tmp/{session_name}.sock", "display", "-p", "#{tmate_ssh}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await ssh_proc.communicate()
                ssh_url = stdout.decode().strip() if stdout else None
                if ssh_url:
                    try:
                        ssh_embed = create_embed("🔑 UnixNodes SSH Access", f"SSH connection for VPS `{container_name}`:", 0x00ff88)
                        add_field(ssh_embed, "Command", f"```{ssh_url}```", False)
                        add_field(ssh_embed, "⚠️ Security", "This link is temporary. Do not share it.", False)
                        add_field(ssh_embed, "📝 Session", f"Session ID: {session_name}", False)
                        await interaction.user.send(embed=ssh_embed)
                        await interaction.followup.send(embed=create_success_embed("SSH Sent", f"Check your DMs for UnixNodes SSH link! Session: {session_name}"), ephemeral=True)
                    except discord.Forbidden:
                        await interaction.followup.send(embed=create_error_embed("DM Failed", "Enable DMs to receive UnixNodes SSH link!"), ephemeral=True)
                else:
                    error_msg = stderr.decode().strip() if stderr else "Unknown error"
                    await interaction.followup.send(embed=create_error_embed("SSH Failed", error_msg), ephemeral=True)
            except Exception as e:
                await interaction.followup.send(embed=create_error_embed("SSH Error", str(e)), ephemeral=True)
        new_embed = await self.create_vps_embed(self.selected_index)
        await interaction.message.edit(embed=new_embed, view=self)

@bot.command(name='manage')
async def manage_vps(ctx, user: discord.Member = None):
    if user:
        user_id_check = str(ctx.author.id)
        if user_id_check != str(MAIN_ADMIN_ID) and user_id_check not in admin_data.get("admins", []):
            await ctx.send(embed=create_error_embed("Access Denied", "Only UnixNodes admins can manage other users' VPS."))
            return
        user_id = str(user.id)
        vps_list = vps_data.get(user_id, [])
        if not vps_list:
            await ctx.send(embed=create_error_embed("No VPS Found", f"{user.mention} doesn't have any UnixNodes VPS."))
            return
        view = ManageView(str(ctx.author.id), vps_list, is_admin=True, owner_id=user_id)
        await ctx.send(embed=create_info_embed(f"Managing {user.name}'s UnixNodes VPS", f"Managing VPS for {user.mention}"), view=view)
    else:
        user_id = str(ctx.author.id)
        vps_list = vps_data.get(user_id, [])
        if not vps_list:
            embed = create_error_embed("No VPS Found", "You don't have any UnixNodes VPS. Contact an admin to create one.")
            add_field(embed, "Quick Actions", "• `!manage` - Manage VPS\n• Contact UnixNodes admin for VPS creation", False)
            await ctx.send(embed=embed)
            return
        view = ManageView(user_id, vps_list)
        embed = await view.get_initial_embed()
        await ctx.send(embed=embed, view=view)

@bot.command(name='list-all')
@is_admin()
async def list_all_vps(ctx):
    total_vps = 0
    total_users = len(vps_data)
    running_vps = 0
    stopped_vps = 0
    suspended_vps = 0
    whitelisted_vps = 0
    vps_info = []
    user_summary = []
    for user_id, vps_list in vps_data.items():
        try:
            user = await bot.fetch_user(int(user_id))
            user_vps_count = len(vps_list)
            user_running = sum(1 for vps in vps_list if vps.get('status') == 'running' and not vps.get('suspended', False))
            user_stopped = sum(1 for vps in vps_list if vps.get('status') == 'stopped')
            user_suspended = sum(1 for vps in vps_list if vps.get('suspended', False))
            user_whitelisted = sum(1 for vps in vps_list if vps.get('whitelisted', False))

            total_vps += user_vps_count
            running_vps += user_running
            stopped_vps += user_stopped
            suspended_vps += user_suspended
            whitelisted_vps += user_whitelisted

            user_summary.append(f"**{user.name}** ({user.mention}) - {user_vps_count} UnixNodes VPS ({user_running} running, {user_suspended} suspended, {user_whitelisted} whitelisted)")

            for i, vps in enumerate(vps_list):
                status_emoji = "🟢" if vps.get('status') == 'running' and not vps.get('suspended', False) else "🟡" if vps.get('suspended', False) else "🔴"
                status_text = vps.get('status', 'unknown').upper()
                if vps.get('suspended', False):
                    status_text += " (SUSPENDED)"
                if vps.get('whitelisted', False):
                    status_text += " (WHITELISTED)"
                vps_info.append(f"{status_emoji} **{user.name}** - VPS {i+1}: `{vps['container_name']}` - {vps.get('config', 'Custom')} - {status_text}")

        except discord.NotFound:
            vps_info.append(f"❓ Unknown User ({user_id}) - {len(vps_list)} UnixNodes VPS")
    embed = create_embed("All UnixNodes VPS Information", "Complete overview of all UnixNodes VPS deployments and user statistics", 0x1a1a1a)
    add_field(embed, "System Overview", f"**Total Users:** {total_users}\n**Total VPS:** {total_vps}\n**Running:** {running_vps}\n**Stopped:** {stopped_vps}\n**Suspended:** {suspended_vps}\n**Whitelisted:** {whitelisted_vps}", False)
    await ctx.send(embed=embed)
    if user_summary:
        embed = create_embed("UnixNodes User Summary", f"Summary of all users and their UnixNodes VPS", 0x1a1a1a)
        summary_text = "\n".join(user_summary)
        chunks = [summary_text[i:i+1024] for i in range(0, len(summary_text), 1024)]
        for idx, chunk in enumerate(chunks, 1):
            add_field(embed, f"Users (Part {idx})", chunk, False)
        await ctx.send(embed=embed)
    if vps_info:
        vps_text = "\n".join(vps_info)
        chunks = [vps_text[i:i+1024] for i in range(0, len(vps_text), 1024)]
        for idx, chunk in enumerate(chunks, 1):
            embed = create_embed(f"UnixNodes VPS Details (Part {idx})", "List of all UnixNodes VPS deployments", 0x1a1a1a)
            add_field(embed, "VPS List", chunk, False)
            await ctx.send(embed=embed)

@bot.command(name='manage-shared')
async def manage_shared_vps(ctx, owner: discord.Member, vps_number: int):
    owner_id = str(owner.id)
    user_id = str(ctx.author.id)
    if owner_id not in vps_data or vps_number < 1 or vps_number > len(vps_data[owner_id]):
        await ctx.send(embed=create_error_embed("Invalid VPS", "Invalid VPS number or owner doesn't have a UnixNodes VPS."))
        return
    vps = vps_data[owner_id][vps_number - 1]
    if user_id not in vps.get("shared_with", []):
        await ctx.send(embed=create_error_embed("Access Denied", "You do not have access to this UnixNodes VPS."))
        return
    view = ManageView(user_id, [vps], is_shared=True, owner_id=owner_id, actual_index=vps_number - 1)
    embed = await view.get_initial_embed()
    await ctx.send(embed=embed, view=view)

@bot.command(name='share-user')
async def share_user(ctx, shared_user: discord.Member, vps_number: int):
    user_id = str(ctx.author.id)
    shared_user_id = str(shared_user.id)
    if user_id not in vps_data or vps_number < 1 or vps_number > len(vps_data[user_id]):
        await ctx.send(embed=create_error_embed("Invalid VPS", "Invalid VPS number or you don't have a UnixNodes VPS."))
        return
    vps = vps_data[user_id][vps_number - 1]
    if "shared_with" not in vps:
        vps["shared_with"] = []
    if shared_user_id in vps["shared_with"]:
        await ctx.send(embed=create_error_embed("Already Shared", f"{shared_user.mention} already has access to this UnixNodes VPS!"))
        return
    vps["shared_with"].append(shared_user_id)
    save_vps_data()
    await ctx.send(embed=create_success_embed("VPS Shared", f"UnixNodes VPS #{vps_number} shared with {shared_user.mention}!"))
    try:
        await shared_user.send(embed=create_embed("UnixNodes VPS Access Granted", f"You have access to VPS #{vps_number} from {ctx.author.mention}. Use `!manage-shared {ctx.author.mention} {vps_number}`", 0x00ff88))
    except discord.Forbidden:
        await ctx.send(embed=create_info_embed("Notification Failed", f"Could not DM {shared_user.mention}"))

@bot.command(name='share-ruser')
async def revoke_share(ctx, shared_user: discord.Member, vps_number: int):
    user_id = str(ctx.author.id)
    shared_user_id = str(shared_user.id)
    if user_id not in vps_data or vps_number < 1 or vps_number > len(vps_data[user_id]):
        await ctx.send(embed=create_error_embed("Invalid VPS", "Invalid VPS number or you don't have a UnixNodes VPS."))
        return
    vps = vps_data[user_id][vps_number - 1]
    if "shared_with" not in vps:
        vps["shared_with"] = []
    if shared_user_id not in vps["shared_with"]:
        await ctx.send(embed=create_error_embed("Not Shared", f"{shared_user.mention} doesn't have access to this UnixNodes VPS!"))
        return
    vps["shared_with"].remove(shared_user_id)
    save_vps_data()
    await ctx.send(embed=create_success_embed("Access Revoked", f"Access to UnixNodes VPS #{vps_number} revoked from {shared_user.mention}!"))
    try:
        await shared_user.send(embed=create_embed("UnixNodes VPS Access Revoked", f"Your access to VPS #{vps_number} by {ctx.author.mention} has been revoked.", 0xff3366))
    except discord.Forbidden:
        await ctx.send(embed=create_info_embed("Notification Failed", f"Could not DM {shared_user.mention}"))

@bot.command(name='delete-vps')
@is_admin()
async def delete_vps(ctx, user: discord.Member, vps_number: int, *, reason: str = "No reason"):
    user_id = str(user.id)
    if user_id not in vps_data or vps_number < 1 or vps_number > len(vps_data[user_id]):
        await ctx.send(embed=create_error_embed("Invalid VPS", "Invalid VPS number or user doesn't have a UnixNodes VPS."))
        return
    vps = vps_data[user_id][vps_number - 1]
    container_name = vps["container_name"]
    await ctx.send(embed=create_info_embed("Deleting UnixNodes VPS", f"Removing VPS #{vps_number}..."))
    try:
        # Remove all port forwardings for this container first
        port_forwardings = get_vps_port_forwardings(container_name)
        for pf in port_forwardings:
            remove_port_forwarding(pf['external_port'])
        
        await execute_lxc(f"lxc delete {container_name} --force")
        del vps_data[user_id][vps_number - 1]
        if not vps_data[user_id]:
            del vps_data[user_id]
            if ctx.guild:
                vps_role = await get_or_create_vps_role(ctx.guild)
                if vps_role and vps_role in user.roles:
                    try:
                        await user.remove_roles(vps_role, reason="No UnixNodes VPS ownership")
                    except discord.Forbidden:
                        logger.warning(f"Failed to remove UnixNodes VPS role from {user.name}")
        save_vps_data()
        embed = create_success_embed("UnixNodes VPS Deleted Successfully")
        add_field(embed, "Owner", user.mention, True)
        add_field(embed, "VPS ID", f"#{vps_number}", True)
        add_field(embed, "Container", f"`{container_name}`", True)
        add_field(embed, "Reason", reason, False)
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(embed=create_error_embed("Deletion Failed", f"Error: {str(e)}"))

@bot.command(name='add-resources')
@is_admin()
async def add_resources(ctx, vps_id: str, ram: int = None, cpu: int = None, disk: int = None):
    if ram is None and cpu is None and disk is None:
        await ctx.send(embed=create_error_embed("Missing Parameters", "Please specify at least one resource to add (ram, cpu, or disk)"))
        return
    found_vps = None
    user_id = None
    vps_index = None
    for uid, vps_list in vps_data.items():
        for i, vps in enumerate(vps_list):
            if vps['container_name'] == vps_id:
                found_vps = vps
                user_id = uid
                vps_index = i
                break
        if found_vps:
            break
    if not found_vps:
        await ctx.send(embed=create_error_embed("VPS Not Found", f"No UnixNodes VPS found with ID: `{vps_id}`"))
        return
    was_running = found_vps.get('status') == 'running' and not found_vps.get('suspended', False)
    disk_changed = disk is not None
    if was_running:
        await ctx.send(embed=create_info_embed("Stopping VPS", f"Stopping UnixNodes VPS `{vps_id}` to apply resource changes..."))
        try:
            await execute_lxc(f"lxc stop {vps_id}")
            found_vps['status'] = 'stopped'
            save_vps_data()
        except Exception as e:
            await ctx.send(embed=create_error_embed("Stop Failed", f"Error stopping VPS: {str(e)}"))
            return
    changes = []
    try:
        current_ram_gb = int(found_vps['ram'].replace('GB', ''))
        current_cpu = int(found_vps['cpu'])
        current_disk_gb = int(found_vps['storage'].replace('GB', ''))

        new_ram_gb = current_ram_gb
        new_cpu = current_cpu
        new_disk_gb = current_disk_gb

        if ram is not None and ram > 0:
            new_ram_gb += ram
            ram_mb = new_ram_gb * 1024
            await execute_lxc(f"lxc config set {vps_id} limits.memory {ram_mb}MB")
            changes.append(f"RAM: +{ram}GB (New total: {new_ram_gb}GB)")

        if cpu is not None and cpu > 0:
            new_cpu += cpu
            await execute_lxc(f"lxc config set {vps_id} limits.cpu {new_cpu}")
            changes.append(f"CPU: +{cpu} cores (New total: {new_cpu} cores)")

        if disk is not None and disk > 0:
            new_disk_gb += disk
            await execute_lxc(f"lxc config device set {vps_id} root size={new_disk_gb}GB")
            changes.append(f"Disk: +{disk}GB (New total: {new_disk_gb}GB)")

        found_vps['ram'] = f"{new_ram_gb}GB"
        found_vps['cpu'] = str(new_cpu)
        found_vps['storage'] = f"{new_disk_gb}GB"
        found_vps['config'] = f"{new_ram_gb}GB RAM / {new_cpu} CPU / {new_disk_gb}GB Disk"

        vps_data[user_id][vps_index] = found_vps
        save_vps_data()

        if was_running:
            await execute_lxc(f"lxc start {vps_id}")
            found_vps['status'] = 'running'
            save_vps_data()

        embed = create_success_embed("Resources Added", f"Successfully added resources to UnixNodes VPS `{vps_id}`")
        add_field(embed, "Changes Applied", "\n".join(changes), False)
        if disk_changed:
            add_field(embed, "Disk Note", "Run `sudo resize2fs /` inside the VPS to expand the filesystem.", False)
        await ctx.send(embed=embed)

    except Exception as e:
        await ctx.send(embed=create_error_embed("Resource Addition Failed", f"Error: {str(e)}"))

@bot.command(name='admin-add')
@is_main_admin()
async def admin_add(ctx, user: discord.Member):
    user_id = str(user.id)
    if user_id == str(MAIN_ADMIN_ID):
        await ctx.send(embed=create_error_embed("Already Admin", "This user is already the main UnixNodes admin!"))
        return
    if user_id in admin_data.get("admins", []):
        await ctx.send(embed=create_error_embed("Already Admin", f"{user.mention} is already a UnixNodes admin!"))
        return
    admin_data["admins"].append(user_id)
    save_admin_data()
    await ctx.send(embed=create_success_embed("Admin Added", f"{user.mention} is now a UnixNodes admin!"))
    try:
        await user.send(embed=create_embed("🎉 UnixNodes Admin Role Granted", f"You are now a UnixNodes admin by {ctx.author.mention}", 0x00ff88))
    except discord.Forbidden:
        await ctx.send(embed=create_info_embed("Notification Failed", f"Could not DM {user.mention}"))

@bot.command(name='admin-remove')
@is_main_admin()
async def admin_remove(ctx, user: discord.Member):
    user_id = str(user.id)
    if user_id == str(MAIN_ADMIN_ID):
        await ctx.send(embed=create_error_embed("Cannot Remove", "You cannot remove the main UnixNodes admin!"))
        return
    if user_id not in admin_data.get("admins", []):
        await ctx.send(embed=create_error_embed("Not Admin", f"{user.mention} is not a UnixNodes admin!"))
        return
    admin_data["admins"].remove(user_id)
    save_admin_data()
    await ctx.send(embed=create_success_embed("Admin Removed", f"{user.mention} is no longer a UnixNodes admin!"))
    try:
        await user.send(embed=create_embed("⚠️ UnixNodes Admin Role Revoked", f"Your admin role was removed by {ctx.author.mention}", 0xff3366))
    except discord.Forbidden:
        await ctx.send(embed=create_info_embed("Notification Failed", f"Could not DM {user.mention}"))

@bot.command(name='admin-list')
@is_main_admin()
async def admin_list(ctx):
    admins = admin_data.get("admins", [])
    main_admin = await bot.fetch_user(MAIN_ADMIN_ID)
    embed = create_embed("👑 UnixNodes Admin Team", "Current UnixNodes administrators:", 0x1a1a1a)
    add_field(embed, "🔰 Main Admin", f"{main_admin.mention} (ID: {MAIN_ADMIN_ID})", False)
    if admins:
        admin_list = []
        for admin_id in admins:
            try:
                admin_user = await bot.fetch_user(int(admin_id))
                admin_list.append(f"• {admin_user.mention} (ID: {admin_id})")
            except:
                admin_list.append(f"• Unknown User (ID: {admin_id})")
        admin_text = "\n".join(admin_list)
        add_field(embed, "🛡️ Admins", admin_text, False)
    else:
        add_field(embed, "🛡️ Admins", "No additional UnixNodes admins", False)
    await ctx.send(embed=embed)

@bot.command(name='userinfo')
@is_admin()
async def user_info(ctx, user: discord.Member):
    user_id = str(user.id)
    vps_list = vps_data.get(user_id, [])
    embed = create_embed(f"UnixNodes User Information - {user.name}", f"Detailed information for {user.mention}", 0x1a1a1a)
    add_field(embed, "👤 User Details", f"**Name:** {user.name}\n**ID:** {user.id}\n**Joined:** {user.joined_at.strftime('%Y-%m-%d %H:%M:%S') if user.joined_at else 'Unknown'}", False)
    if vps_list:
        vps_info = []
        total_ram = 0
        total_cpu = 0
        total_storage = 0
        running_count = 0
        suspended_count = 0
        whitelisted_count = 0
        for i, vps in enumerate(vps_list):
            status_emoji = "🟢" if vps.get('status') == 'running' and not vps.get('suspended', False) else "🟡" if vps.get('suspended', False) else "🔴"
            status_text = vps.get('status', 'unknown').upper()
            if vps.get('suspended', False):
                status_text += " (SUSPENDED)"
                suspended_count += 1
            else:
                running_count += 1 if vps.get('status') == 'running' else 0
            if vps.get('whitelisted', False):
                whitelisted_count += 1
            vps_info.append(f"{status_emoji} VPS {i+1}: `{vps['container_name']}` - {status_text}")
            ram_gb = int(vps['ram'].replace('GB', ''))
            storage_gb = int(vps['storage'].replace('GB', ''))
            total_ram += ram_gb
            total_cpu += int(vps['cpu'])
            total_storage += storage_gb
        vps_summary = f"**Total VPS:** {len(vps_list)}\n**Running:** {running_count}\n**Suspended:** {suspended_count}\n**Whitelisted:** {whitelisted_count}\n**Total RAM:** {total_ram}GB\n**Total CPU:** {total_cpu} cores\n**Total Storage:** {total_storage}GB"
        add_field(embed, "🖥️ UnixNodes VPS Information", vps_summary, False)

        vps_text = "\n".join(vps_info)
        chunks = [vps_text[i:i+1024] for i in range(0, len(vps_text), 1024)]
        for idx, chunk in enumerate(chunks, 1):
            add_field(embed, f"📋 VPS List (Part {idx})", chunk, False)
    else:
        add_field(embed, "🖥️ UnixNodes VPS Information", "**No VPS owned**", False)
    is_admin_user = user_id == str(MAIN_ADMIN_ID) or user_id in admin_data.get("admins", [])
    add_field(embed, "🛡️ UnixNodes Admin Status", f"**{'Yes' if is_admin_user else 'No'}**", False)
    await ctx.send(embed=embed)

@bot.command(name='serverstats')
@is_admin()
async def server_stats(ctx):
    total_users = len(vps_data)
    total_vps = sum(len(vps_list) for vps_list in vps_data.values())
    total_ram = 0
    total_cpu = 0
    total_storage = 0
    running_vps = 0
    suspended_vps = 0
    whitelisted_vps = 0
    for vps_list in vps_data.values():
        for vps in vps_list:
            ram_gb = int(vps['ram'].replace('GB', ''))
            storage_gb = int(vps['storage'].replace('GB', ''))
            total_ram += ram_gb
            total_cpu += int(vps['cpu'])
            total_storage += storage_gb
            if vps.get('status') == 'running':
                if vps.get('suspended', False):
                    suspended_vps += 1
                else:
                    running_vps += 1
            if vps.get('whitelisted', False):
                whitelisted_vps += 1
    embed = create_embed("📊 UnixNodes Server Statistics", "Current UnixNodes server overview", 0x1a1a1a)
    add_field(embed, "👥 Users", f"**Total Users:** {total_users}\n**Total Admins:** {len(admin_data.get('admins', [])) + 1}", False)
    add_field(embed, "🖥️ VPS", f"**Total VPS:** {total_vps}\n**Running:** {running_vps}\n**Suspended:** {suspended_vps}\n**Whitelisted:** {whitelisted_vps}\n**Stopped:** {total_vps - running_vps - suspended_vps}", False)
    add_field(embed, "📈 Resources", f"**Total RAM:** {total_ram}GB\n**Total CPU:** {total_cpu} cores\n**Total Storage:** {total_storage}GB", False)
    await ctx.send(embed=embed)

@bot.command(name='vpsinfo')
@is_admin()
async def vps_info(ctx, container_name: str = None):
    if not container_name:
        all_vps = []
        for user_id, vps_list in vps_data.items():
            try:
                user = await bot.fetch_user(int(user_id))
                for i, vps in enumerate(vps_list):
                    status_text = vps.get('status', 'unknown').upper()
                    if vps.get('suspended', False):
                        status_text += " (SUSPENDED)"
                    if vps.get('whitelisted', False):
                        status_text += " (WHITELISTED)"
                    all_vps.append(f"**{user.name}** - UnixNodes VPS {i+1}: `{vps['container_name']}` - {status_text}")
            except:
                pass
        vps_text = "\n".join(all_vps)
        chunks = [vps_text[i:i+1024] for i in range(0, len(vps_text), 1024)]
        for idx, chunk in enumerate(chunks, 1):
            embed = create_embed(f"🖥️ All UnixNodes VPS (Part {idx})", f"List of all UnixNodes VPS deployments", 0x1a1a1a)
            add_field(embed, "VPS List", chunk, False)
            await ctx.send(embed=embed)
    else:
        found_vps = None
        found_user = None
        for user_id, vps_list in vps_data.items():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    found_vps = vps
                    found_user = await bot.fetch_user(int(user_id))
                    break
            if found_vps:
                break
        if not found_vps:
            await ctx.send(embed=create_error_embed("VPS Not Found", f"No UnixNodes VPS found with container name: `{container_name}`"))
            return
        suspended_text = " (SUSPENDED)" if found_vps.get('suspended', False) else ""
        whitelisted_text = " (WHITELISTED)" if found_vps.get('whitelisted', False) else ""
        embed = create_embed(f"🖥️ UnixNodes VPS Information - {container_name}", f"Details for VPS owned by {found_user.mention}{suspended_text}{whitelisted_text}", 0x1a1a1a)
        add_field(embed, "👤 Owner", f"**Name:** {found_user.name}\n**ID:** {found_user.id}", False)
        add_field(embed, "📊 Specifications", f"**RAM:** {found_vps['ram']}\n**CPU:** {found_vps['cpu']} Cores\n**Storage:** {found_vps['storage']}", False)
        add_field(embed, "📈 Status", f"**Current:** {found_vps.get('status', 'unknown').upper()}{suspended_text}{whitelisted_text}\n**Suspended:** {found_vps.get('suspended', False)}\n**Whitelisted:** {found_vps.get('whitelisted', False)}\n**Created:** {found_vps.get('created_at', 'Unknown')}", False)
        if 'config' in found_vps:
            add_field(embed, "⚙️ Configuration", f"**Config:** {found_vps['config']}", False)
        if found_vps.get('shared_with'):
            shared_users = []
            for shared_id in found_vps['shared_with']:
                try:
                    shared_user = await bot.fetch_user(int(shared_id))
                    shared_users.append(f"• {shared_user.mention}")
                except:
                    shared_users.append(f"• Unknown User ({shared_id})")
            shared_text = "\n".join(shared_users)
            add_field(embed, "🔗 Shared With", shared_text, False)
        await ctx.send(embed=embed)

@bot.command(name='restart-vps')
@is_admin()
async def restart_vps(ctx, container_name: str):
    await ctx.send(embed=create_info_embed("Restarting VPS", f"Restarting UnixNodes VPS `{container_name}`..."))
    try:
        await execute_lxc(f"lxc restart {container_name}")
        for user_id, vps_list in vps_data.items():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    vps['status'] = 'running'
                    vps['suspended'] = False
                    save_vps_data()
                    break
        await ctx.send(embed=create_success_embed("VPS Restarted", f"UnixNodes VPS `{container_name}` has been restarted successfully!"))
    except Exception as e:
        await ctx.send(embed=create_error_embed("Restart Failed", f"Error: {str(e)}"))

@bot.command(name='exec')
@is_admin()
async def execute_command(ctx, container_name: str, *, command: str):
    await ctx.send(embed=create_info_embed("Executing Command", f"Running command in UnixNodes VPS `{container_name}`..."))
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "bash", "-c", command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        output = stdout.decode() if stdout else "No output"
        error = stderr.decode() if stderr else ""
        embed = create_embed(f"Command Output - {container_name}", f"Command: `{command}`", 0x1a1a1a)
        if output.strip():
            if len(output) > 1000:
                output = output[:1000] + "\n... (truncated)"
            add_field(embed, "📤 Output", f"```\n{output}\n```", False)
        if error.strip():
            if len(error) > 1000:
                error = error[:1000] + "\n... (truncated)"
            add_field(embed, "⚠️ Error", f"```\n{error}\n```", False)
        add_field(embed, "🔄 Exit Code", f"**{proc.returncode}**", False)
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(embed=create_error_embed("Execution Failed", f"Error: {str(e)}"))

@bot.command(name='stop-vps-all')
@is_admin()
async def stop_all_vps(ctx):
    embed = create_warning_embed("Stopping All UnixNodes VPS", "⚠️ **WARNING:** This will stop ALL running VPS on the UnixNodes server.\n\nThis action cannot be undone. Continue?")
    class ConfirmView(discord.ui.View):
        def __init__(self):
            super().__init__(timeout=60)

        @discord.ui.button(label="Stop All VPS", style=discord.ButtonStyle.danger)
        async def confirm(self, interaction: discord.Interaction, item: discord.ui.Button):
            await interaction.response.defer()
            try:
                proc = await asyncio.create_subprocess_exec(
                    "lxc", "stop", "--all", "--force",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()
                if proc.returncode == 0:
                    stopped_count = 0
                    for user_id, vps_list in vps_data.items():
                        for vps in vps_list:
                            if vps.get('status') == 'running':
                                vps['status'] = 'stopped'
                                vps['suspended'] = False
                                stopped_count += 1
                    save_vps_data()
                    embed = create_success_embed("All UnixNodes VPS Stopped", f"Successfully stopped {stopped_count} VPS using `lxc stop --all --force`")
                    output_text = stdout.decode() if stdout else 'No output'
                    add_field(embed, "Command Output", f"```\n{output_text}\n```", False)
                    await interaction.followup.send(embed=embed)
                else:
                    error_msg = stderr.decode() if stderr else "Unknown error"
                    embed = create_error_embed("Stop Failed", f"Failed to stop UnixNodes VPS: {error_msg}")
                    await interaction.followup.send(embed=embed)
            except Exception as e:
                embed = create_error_embed("Error", f"Error stopping VPS: {str(e)}")
                await interaction.followup.send(embed=embed)

        @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
        async def cancel(self, interaction: discord.Interaction, item: discord.ui.Button):
            await interaction.response.edit_message(embed=create_info_embed("Operation Cancelled", "The stop all UnixNodes VPS operation has been cancelled."))
    await ctx.send(embed=embed, view=ConfirmView())

@bot.command(name='cpu-monitor')
@is_admin()
async def resource_monitor_control(ctx, action: str = "status"):
    global resource_monitor_active
    if action.lower() == "status":
        status = "Active" if resource_monitor_active else "Inactive"
        embed = create_embed("UnixNodes Resource Monitor Status", f"UnixNodes resource monitoring is currently **{status}**", 0x00ccff if resource_monitor_active else 0xffaa00)
        add_field(embed, "Thresholds", f"{CPU_THRESHOLD}% CPU / {RAM_THRESHOLD}% RAM usage", True)
        add_field(embed, "Check Interval", f"60 seconds (host)", True)
        await ctx.send(embed=embed)
    elif action.lower() == "enable":
        resource_monitor_active = True
        await ctx.send(embed=create_success_embed("Resource Monitor Enabled", "UnixNodes resource monitoring has been enabled."))
    elif action.lower() == "disable":
        resource_monitor_active = False
        await ctx.send(embed=create_warning_embed("Resource Monitor Disabled", "UnixNodes resource monitoring has been disabled."))
    else:
        await ctx.send(embed=create_error_embed("Invalid Action", "Use: `!cpu-monitor <status|enable|disable>`"))

@bot.command(name='resize-vps')
@is_admin()
async def resize_vps(ctx, container_name: str, ram: int = None, cpu: int = None, disk: int = None):
    if ram is None and cpu is None and disk is None:
        await ctx.send(embed=create_error_embed("Missing Parameters", "Please specify at least one resource to resize (ram, cpu, or disk)"))
        return
    found_vps = None
    user_id = None
    vps_index = None
    for uid, vps_list in vps_data.items():
        for i, vps in enumerate(vps_list):
            if vps['container_name'] == container_name:
                found_vps = vps
                user_id = uid
                vps_index = i
                break
        if found_vps:
            break
    if not found_vps:
        await ctx.send(embed=create_error_embed("VPS Not Found", f"No UnixNodes VPS found with container name: `{container_name}`"))
        return
    was_running = found_vps.get('status') == 'running' and not found_vps.get('suspended', False)
    disk_changed = disk is not None
    if was_running:
        await ctx.send(embed=create_info_embed("Stopping VPS", f"Stopping UnixNodes VPS `{container_name}` to apply resource changes..."))
        try:
            await execute_lxc(f"lxc stop {container_name}")
            found_vps['status'] = 'stopped'
            save_vps_data()
        except Exception as e:
            await ctx.send(embed=create_error_embed("Stop Failed", f"Error stopping VPS: {str(e)}"))
            return
    changes = []
    try:
        new_ram = int(found_vps['ram'].replace('GB', ''))
        new_cpu = int(found_vps['cpu'])
        new_disk = int(found_vps['storage'].replace('GB', ''))

        if ram is not None and ram > 0:
            new_ram = ram
            ram_mb = ram * 1024
            await execute_lxc(f"lxc config set {container_name} limits.memory {ram_mb}MB")
            changes.append(f"RAM: {ram}GB")

        if cpu is not None and cpu > 0:
            new_cpu = cpu
            await execute_lxc(f"lxc config set {container_name} limits.cpu {cpu}")
            changes.append(f"CPU: {cpu} cores")

        if disk is not None and disk > 0:
            new_disk = disk
            await execute_lxc(f"lxc config device set {container_name} root size={disk}GB")
            changes.append(f"Disk: {disk}GB")

        found_vps['ram'] = f"{new_ram}GB"
        found_vps['cpu'] = str(new_cpu)
        found_vps['storage'] = f"{new_disk}GB"
        found_vps['config'] = f"{new_ram}GB RAM / {new_cpu} CPU / {new_disk}GB Disk"

        vps_data[user_id][vps_index] = found_vps
        save_vps_data()

        if was_running:
            await execute_lxc(f"lxc start {container_name}")
            found_vps['status'] = 'running'
            save_vps_data()

        embed = create_success_embed("VPS Resized", f"Successfully resized resources for UnixNodes VPS `{container_name}`")
        add_field(embed, "Changes Applied", "\n".join(changes), False)
        if disk_changed:
            add_field(embed, "Disk Note", "Run `sudo resize2fs /` inside the VPS to expand the filesystem.", False)
        await ctx.send(embed=embed)

    except Exception as e:
        await ctx.send(embed=create_error_embed("Resize Failed", f"Error: {str(e)}"))

@bot.command(name='clone-vps')
@is_admin()
async def clone_vps(ctx, container_name: str, new_name: str = None):
    if not new_name:
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        new_name = f"unixnodes-{container_name}-clone-{timestamp}"
    await ctx.send(embed=create_info_embed("Cloning VPS", f"Cloning UnixNodes VPS `{container_name}` to `{new_name}`..."))
    try:
        found_vps = None
        user_id = None

        for uid, vps_list in vps_data.items():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    found_vps = vps
                    user_id = uid
                    break
            if found_vps:
                break

        if not found_vps:
            await ctx.send(embed=create_error_embed("VPS Not Found", f"No UnixNodes VPS found with container name: `{container_name}`"))
            return

        await execute_lxc(f"lxc copy {container_name} {new_name}")
        await apply_advanced_permissions(new_name)
        await execute_lxc(f"lxc start {new_name}")

        if user_id not in vps_data:
            vps_data[user_id] = []

        new_vps = found_vps.copy()
        new_vps['container_name'] = new_name
        new_vps['status'] = 'running'
        new_vps['suspended'] = False
        new_vps['whitelisted'] = False
        new_vps['suspension_history'] = []
        new_vps['created_at'] = datetime.now().isoformat()
        new_vps['shared_with'] = []
        new_vps['id'] = None

        vps_data[user_id].append(new_vps)
        save_vps_data()

        embed = create_success_embed("VPS Cloned", f"Successfully cloned UnixNodes VPS `{container_name}` to `{new_name}`")
        add_field(embed, "New VPS Details", f"**RAM:** {new_vps['ram']}\n**CPU:** {new_vps['cpu']} Cores\n**Storage:** {new_vps['storage']}", False)
        add_field(embed, "Features", "Nesting, Privileged, FUSE, Kernel Modules (Docker Ready)", False)
        await ctx.send(embed=embed)

    except Exception as e:
        await ctx.send(embed=create_error_embed("Clone Failed", f"Error: {str(e)}"))

@bot.command(name='migrate-vps')
@is_admin()
async def migrate_vps(ctx, container_name: str, target_pool: str):
    await ctx.send(embed=create_info_embed("Migrating VPS", f"Migrating UnixNodes VPS `{container_name}` to storage pool `{target_pool}`..."))
    try:
        await execute_lxc(f"lxc stop {container_name}")

        temp_name = f"unixnodes-{container_name}-temp-{int(time.time())}"

        await execute_lxc(f"lxc copy {container_name} {temp_name} -s {target_pool}")

        await execute_lxc(f"lxc delete {container_name} --force")

        await execute_lxc(f"lxc rename {temp_name} {container_name}")

        await apply_advanced_permissions(container_name)

        await execute_lxc(f"lxc start {container_name}")

        for user_id, vps_list in vps_data.items():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    vps['status'] = 'running'
                    vps['suspended'] = False
                    save_vps_data()
                    break

        await ctx.send(embed=create_success_embed("VPS Migrated", f"Successfully migrated UnixNodes VPS `{container_name}` to storage pool `{target_pool}`"))

    except Exception as e:
        await ctx.send(embed=create_error_embed("Migration Failed", f"Error: {str(e)}"))

@bot.command(name='vps-stats')
@is_admin()
async def vps_stats(ctx, container_name: str):
    await ctx.send(embed=create_info_embed("Gathering Statistics", f"Collecting statistics for UnixNodes VPS `{container_name}`..."))
    try:
        status = await get_container_status(container_name)
        cpu_usage = await get_container_cpu(container_name)
        memory_usage = await get_container_memory(container_name)
        disk_usage = await get_container_disk(container_name)
        uptime = await get_container_uptime(container_name)
        proc = await asyncio.create_subprocess_exec(
            "lxc", "info", container_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode()
        network_usage = "N/A"
        for line in output.splitlines():
            if "Network usage" in line:
                network_usage = line.split(":")[1].strip()
                break

        embed = create_embed(f"📊 UnixNodes VPS Statistics - {container_name}", f"Resource usage statistics", 0x1a1a1a)
        add_field(embed, "📈 Status", f"**{status.upper()}**", False)
        add_field(embed, "💻 CPU Usage", f"**{cpu_usage}**", True)
        add_field(embed, "🧠 Memory Usage", f"**{memory_usage}**", True)
        add_field(embed, "💾 Disk Usage", f"**{disk_usage}**", True)
        add_field(embed, "⏱️ Uptime", f"**{uptime}**", True)
        add_field(embed, "🌐 Network Usage", f"**{network_usage}**", False)

        found_vps = None
        for vps_list in vps_data.values():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    found_vps = vps
                    break
            if found_vps:
                break

        if found_vps:
            suspended_text = " (SUSPENDED)" if found_vps.get('suspended', False) else ""
            whitelisted_text = " (WHITELISTED)" if found_vps.get('whitelisted', False) else ""
            add_field(embed, "📋 Allocated Resources",
                           f"**RAM:** {found_vps['ram']}\n**CPU:** {found_vps['cpu']} Cores\n**Storage:** {found_vps['storage']}\n**Status:** {found_vps.get('status', 'unknown').upper()}{suspended_text}{whitelisted_text}",
                           False)

        await ctx.send(embed=embed)

    except Exception as e:
        await ctx.send(embed=create_error_embed("Statistics Failed", f"Error: {str(e)}"))

@bot.command(name='vps-network')
@is_admin()
async def vps_network(ctx, container_name: str, action: str, value: str = None):
    if action.lower() not in ["list", "add", "remove", "limit"]:
        await ctx.send(embed=create_error_embed("Invalid Action", "Use: `!vps-network <container> <list|add|remove|limit> [value]`"))
        return
    try:
        if action.lower() == "list":
            proc = await asyncio.create_subprocess_exec(
                "lxc", "exec", container_name, "--", "ip", "addr",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                output = stdout.decode()
                if len(output) > 1000:
                    output = output[:1000] + "\n... (truncated)"

                embed = create_embed(f"🌐 UnixNodes Network Interfaces - {container_name}", "Network configuration", 0x1a1a1a)
                add_field(embed, "Interfaces", f"```\n{output}\n```", False)
                await ctx.send(embed=embed)
            else:
                await ctx.send(embed=create_error_embed("Error", f"Failed to list network interfaces: {stderr.decode()}"))

        elif action.lower() == "limit" and value:
            await execute_lxc(f"lxc config device set {container_name} eth0 limits.egress {value}")
            await execute_lxc(f"lxc config device set {container_name} eth0 limits.ingress {value}")
            await ctx.send(embed=create_success_embed("Network Limited", f"Set UnixNodes network limit to {value} for `{container_name}`"))

        elif action.lower() == "add" and value:
            await execute_lxc(f"lxc config device add {container_name} eth1 nic nictype=bridged parent={value}")
            await ctx.send(embed=create_success_embed("Network Added", f"Added network interface to UnixNodes VPS `{container_name}` with bridge `{value}`"))

        elif action.lower() == "remove" and value:
            await execute_lxc(f"lxc config device remove {container_name} {value}")
            await ctx.send(embed=create_success_embed("Network Removed", f"Removed network interface `{value}` from UnixNodes VPS `{container_name}`"))

        else:
            await ctx.send(embed=create_error_embed("Invalid Parameters", "Please provide valid parameters for the action"))
    except Exception as e:
        await ctx.send(embed=create_error_embed("Network Management Failed", f"Error: {str(e)}"))

@bot.command(name='vps-processes')
@is_admin()
async def vps_processes(ctx, container_name: str):
    await ctx.send(embed=create_info_embed("Gathering Processes", f"Listing processes in UnixNodes VPS `{container_name}`..."))
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "ps", "aux",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode == 0:
            output = stdout.decode()
            if len(output) > 1000:
                output = output[:1000] + "\n... (truncated)"

            embed = create_embed(f"⚙️ UnixNodes Processes - {container_name}", "Running processes", 0x1a1a1a)
            add_field(embed, "Process List", f"```\n{output}\n```", False)
            await ctx.send(embed=embed)
        else:
            await ctx.send(embed=create_error_embed("Error", f"Failed to list processes: {stderr.decode()}"))
    except Exception as e:
        await ctx.send(embed=create_error_embed("Process Listing Failed", f"Error: {str(e)}"))

@bot.command(name='vps-logs')
@is_admin()
async def vps_logs(ctx, container_name: str, lines: int = 50):
    await ctx.send(embed=create_info_embed("Gathering Logs", f"Fetching last {lines} lines from UnixNodes VPS `{container_name}`..."))
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "journalctl", "-n", str(lines),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode == 0:
            output = stdout.decode()
            if len(output) > 1000:
                output = output[:1000] + "\n... (truncated)"

            embed = create_embed(f"📋 UnixNodes Logs - {container_name}", f"Last {lines} log lines", 0x1a1a1a)
            add_field(embed, "System Logs", f"```\n{output}\n```", False)
            await ctx.send(embed=embed)
        else:
            await ctx.send(embed=create_error_embed("Error", f"Failed to fetch logs: {stderr.decode()}"))
    except Exception as e:
        await ctx.send(embed=create_error_embed("Log Retrieval Failed", f"Error: {str(e)}"))

@bot.command(name='vps-uptime')
@is_admin()
async def vps_uptime(ctx, container_name: str):
    uptime = await get_container_uptime(container_name)
    embed = create_info_embed("VPS Uptime", f"Uptime for `{container_name}`: {uptime}")
    await ctx.send(embed=embed)

@bot.command(name='suspend-vps')
@is_admin()
async def suspend_vps(ctx, container_name: str, *, reason: str = "Admin action"):
    found = False
    for uid, lst in vps_data.items():
        for vps in lst:
            if vps['container_name'] == container_name:
                if vps.get('status') != 'running':
                    await ctx.send(embed=create_error_embed("Cannot Suspend", "UnixNodes VPS must be running to suspend."))
                    return
                try:
                    await execute_lxc(f"lxc stop {container_name}")
                    vps['status'] = 'stopped'
                    vps['suspended'] = True
                    if 'suspension_history' not in vps:
                        vps['suspension_history'] = []
                    vps['suspension_history'].append({
                        'time': datetime.now().isoformat(),
                        'reason': reason,
                        'by': f"{ctx.author.name} ({ctx.author.id})"
                    })
                    save_vps_data()
                except Exception as e:
                    await ctx.send(embed=create_error_embed("Suspend Failed", str(e)))
                    return
                try:
                    owner = await bot.fetch_user(int(uid))
                    embed = create_warning_embed("🚨 UnixNodes VPS Suspended", f"Your VPS `{container_name}` has been suspended by an admin.\n\n**Reason:** {reason}\n\nContact a UnixNodes admin to unsuspend.")
                    await owner.send(embed=embed)
                except Exception as dm_e:
                    logger.error(f"Failed to DM owner {uid}: {dm_e}")
                await ctx.send(embed=create_success_embed("VPS Suspended", f"UnixNodes VPS `{container_name}` suspended. Reason: {reason}"))
                found = True
                break
        if found:
            break
    if not found:
        await ctx.send(embed=create_error_embed("Not Found", f"UnixNodes VPS `{container_name}` not found."))

@bot.command(name='unsuspend-vps')
@is_admin()
async def unsuspend_vps(ctx, container_name: str):
    found = False
    for uid, lst in vps_data.items():
        for vps in lst:
            if vps['container_name'] == container_name:
                if not vps.get('suspended', False):
                    await ctx.send(embed=create_error_embed("Not Suspended", "UnixNodes VPS is not suspended."))
                    return
                try:
                    vps['suspended'] = False
                    vps['status'] = 'running'
                    await execute_lxc(f"lxc start {container_name}")
                    save_vps_data()
                    await ctx.send(embed=create_success_embed("VPS Unsuspended", f"UnixNodes VPS `{container_name}` unsuspended and started."))
                    found = True
                except Exception as e:
                    await ctx.send(embed=create_error_embed("Start Failed", str(e)))
                try:
                    owner = await bot.fetch_user(int(uid))
                    embed = create_success_embed("🟢 UnixNodes VPS Unsuspended", f"Your VPS `{container_name}` has been unsuspended by an admin.\nYou can now manage it again.")
                    await owner.send(embed=embed)
                except Exception as dm_e:
                    logger.error(f"Failed to DM owner {uid} about unsuspension: {dm_e}")
                break
        if found:
            break
    if not found:
        await ctx.send(embed=create_error_embed("Not Found", f"UnixNodes VPS `{container_name}` not found."))

@bot.command(name='suspension-logs')
@is_admin()
async def suspension_logs(ctx, container_name: str = None):
    if container_name:
        found = None
        for lst in vps_data.values():
            for vps in lst:
                if vps['container_name'] == container_name:
                    found = vps
                    break
            if found:
                break
        if not found:
            await ctx.send(embed=create_error_embed("Not Found", f"UnixNodes VPS `{container_name}` not found."))
            return
        history = found.get('suspension_history', [])
        if not history:
            await ctx.send(embed=create_info_embed("No Suspensions", f"No UnixNodes suspension history for `{container_name}`."))
            return
        embed = create_embed("UnixNodes Suspension History", f"For `{container_name}`")
        text = []
        for h in sorted(history, key=lambda x: x['time'], reverse=True)[:10]:
            t = datetime.fromisoformat(h['time']).strftime('%Y-%m-%d %H:%M:%S')
            text.append(f"**{t}** - {h['reason']} (by {h['by']})")
        add_field(embed, "History", "\n".join(text), False)
        if len(history) > 10:
            add_field(embed, "Note", "Showing last 10 entries.")
        await ctx.send(embed=embed)
    else:
        all_logs = []
        for uid, lst in vps_data.items():
            for vps in lst:
                h = vps.get('suspension_history', [])
                for event in sorted(h, key=lambda x: x['time'], reverse=True):
                    t = datetime.fromisoformat(event['time']).strftime('%Y-%m-%d %H:%M')
                    all_logs.append(f"**{t}** - VPS `{vps['container_name']}` (Owner: <@{uid}>) - {event['reason']} (by {event['by']})")
        if not all_logs:
            await ctx.send(embed=create_info_embed("No Suspensions", "No UnixNodes suspension events recorded."))
            return
        logs_text = "\n".join(all_logs)
        chunks = [logs_text[i:i+1024] for i in range(0, len(logs_text), 1024)]
        for idx, chunk in enumerate(chunks, 1):
            embed = create_embed(f"UnixNodes Suspension Logs (Part {idx})", f"Global suspension events (newest first)")
            add_field(embed, "Events", chunk, False)
            await ctx.send(embed=embed)

@bot.command(name='apply-permissions')
@is_admin()
async def apply_permissions(ctx, container_name: str):
    await ctx.send(embed=create_info_embed("Applying Permissions", f"Applying advanced permissions to `{container_name}`..."))
    try:
        status = await get_container_status(container_name)
        was_running = status == 'running'
        if was_running:
            await execute_lxc(f"lxc stop {container_name}")

        await apply_advanced_permissions(container_name)

        await execute_lxc(f"lxc start {container_name}")

        for user_id, vps_list in vps_data.items():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    vps['status'] = 'running'
                    vps['suspended'] = False
                    save_vps_data()
                    break

        await ctx.send(embed=create_success_embed("Permissions Applied", f"Advanced permissions applied to UnixNodes VPS `{container_name}`. Docker-ready!"))
    except Exception as e:
        await ctx.send(embed=create_error_embed("Apply Failed", f"Error: {str(e)}"))

@bot.command(name='resource-check')
@is_admin()
async def resource_check(ctx):
    suspended_count = 0
    embed = create_info_embed("Resource Check", "Checking all running VPS for high resource usage...")
    msg = await ctx.send(embed=embed)
    for user_id, vps_list in vps_data.items():
        for vps in vps_list:
            if vps.get('status') == 'running' and not vps.get('suspended', False) and not vps.get('whitelisted', False):
                container = vps['container_name']
                cpu = await get_container_cpu_pct(container)
                ram = await get_container_ram_pct(container)
                if cpu > CPU_THRESHOLD or ram > RAM_THRESHOLD:
                    reason = f"High resource usage: CPU {cpu:.1f}%, RAM {ram:.1f}% (threshold: {CPU_THRESHOLD}% CPU / {RAM_THRESHOLD}% RAM)"
                    logger.warning(f"Suspending {container}: {reason}")
                    try:
                        await execute_lxc(f"lxc stop {container}")
                        vps['status'] = 'stopped'
                        vps['suspended'] = True
                        if 'suspension_history' not in vps:
                            vps['suspension_history'] = []
                        vps['suspension_history'].append({
                            'time': datetime.now().isoformat(),
                            'reason': reason,
                            'by': 'UnixNodes Auto Resource Check'
                        })
                        save_vps_data()
                        try:
                            owner = await bot.fetch_user(int(user_id))
                            warn_embed = create_warning_embed("🚨 VPS Auto-Suspended", f"Your VPS `{container}` has been automatically suspended due to high resource usage.\n\n**Reason:** {reason}\n\nContact UnixNodes admin to unsuspend and address the issue.")
                            await owner.send(embed=warn_embed)
                        except Exception as dm_e:
                            logger.error(f"Failed to DM owner {user_id}: {dm_e}")
                        suspended_count += 1
                    except Exception as e:
                        logger.error(f"Failed to suspend {container}: {e}")
    final_embed = create_info_embed("Resource Check Complete", f"Checked all VPS. Suspended {suspended_count} high-usage VPS.")
    await msg.edit(embed=final_embed)

@bot.command(name='whitelist-vps')
@is_admin()
async def whitelist_vps(ctx, container_name: str, action: str):
    if action.lower() not in ['add', 'remove']:
        await ctx.send(embed=create_error_embed("Invalid Action", "Use: `!whitelist-vps <container> <add|remove>`"))
        return
    found = False
    for user_id, vps_list in vps_data.items():
        for vps in vps_list:
            if vps['container_name'] == container_name:
                if action.lower() == 'add':
                    vps['whitelisted'] = True
                    msg = "added to whitelist (exempt from auto-suspension)"
                else:
                    vps['whitelisted'] = False
                    msg = "removed from whitelist"
                save_vps_data()
                await ctx.send(embed=create_success_embed("Whitelist Updated", f"VPS `{container_name}` {msg}."))
                found = True
                break
        if found:
            break
    if not found:
        await ctx.send(embed=create_error_embed("Not Found", f"UnixNodes VPS `{container_name}` not found."))

@bot.command(name='snapshot')
@is_admin()
async def snapshot_vps(ctx, container_name: str, snap_name: str = "snap0"):
    await ctx.send(embed=create_info_embed("Creating Snapshot", f"Creating snapshot '{snap_name}' for `{container_name}`..."))
    try:
        await execute_lxc(f"lxc snapshot {container_name} {snap_name}")
        await ctx.send(embed=create_success_embed("Snapshot Created", f"Snapshot '{snap_name}' created for UnixNodes VPS `{container_name}`."))
    except Exception as e:
        await ctx.send(embed=create_error_embed("Snapshot Failed", f"Error: {str(e)}"))

@bot.command(name='list-snapshots')
@is_admin()
async def list_snapshots(ctx, container_name: str):
    try:
        result = await execute_lxc(f"lxc snapshot list {container_name}")
        embed = create_info_embed(f"Snapshots for {container_name}", result)
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(embed=create_error_embed("List Failed", f"Error: {str(e)}"))

@bot.command(name='restore-snapshot')
@is_admin()
async def restore_snapshot(ctx, container_name: str, snap_name: str):
    await ctx.send(embed=create_warning_embed("Restore Snapshot", f"Restoring snapshot '{snap_name}' for `{container_name}` will overwrite current state. Continue?"))
    class RestoreConfirm(discord.ui.View):
        def __init__(self):
            super().__init__(timeout=60)

        @discord.ui.button(label="Confirm Restore", style=discord.ButtonStyle.danger)
        async def confirm(self, inter: discord.Interaction, item: discord.ui.Button):
            await inter.response.defer()
            try:
                await execute_lxc(f"lxc stop {container_name}")
                await execute_lxc(f"lxc restore {container_name} {snap_name}")
                await execute_lxc(f"lxc start {container_name}")
                for uid, lst in vps_data.items():
                    for vps in lst:
                        if vps['container_name'] == container_name:
                            vps['status'] = 'running'
                            vps['suspended'] = False
                            save_vps_data()
                            break
                await inter.followup.send(embed=create_success_embed("Snapshot Restored", f"Restored '{snap_name}' for UnixNodes VPS `{container_name}`."))
            except Exception as e:
                await inter.followup.send(embed=create_error_embed("Restore Failed", f"Error: {str(e)}"))

        @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
        async def cancel(self, inter: discord.Interaction, item: discord.ui.Button):
            await inter.response.edit_message(embed=create_info_embed("Cancelled", "Snapshot restore cancelled."))
    await ctx.send(view=RestoreConfirm())

# PORT FORWARDING COMMANDS

@bot.command(name='port-add')
@is_main_admin()
async def port_add(ctx, user: discord.Member, max_ports: int):
    """Main admin only: Add port quota to a user"""
    if max_ports <= 0:
        await ctx.send(embed=create_error_embed("Invalid Quota", "Maximum ports must be greater than 0."))
        return
    
    set_user_port_quota(str(user.id), max_ports)
    
    quota = get_user_port_quota(str(user.id))
    embed = create_success_embed("Port Quota Added", f"Added port quota for {user.mention}")
    add_field(embed, "Details", f"**Maximum Ports:** {quota['max_ports']}\n**Used Ports:** {quota['used_ports']}", False)
    await ctx.send(embed=embed)
    
    try:
        await user.send(embed=create_success_embed("Port Quota Granted", 
            f"You have been granted {max_ports} port forwarding slots by {ctx.author.mention}.\n\nUse `!port-list` to see your port forwardings and `!port <vps_id> <internal_port>` to create new ones."))
    except discord.Forbidden:
        await ctx.send(embed=create_info_embed("Notification Failed", f"Could not DM {user.mention}"))

@bot.command(name='port-list')
async def port_list(ctx):
    """User can see their port forwardings"""
    user_id = str(ctx.author.id)
    
    # Check if user has any VPS
    if user_id not in vps_data:
        await ctx.send(embed=create_error_embed("No VPS", "You don't have any UnixNodes VPS to manage port forwardings."))
        return
    
    # Get user's quota
    quota = get_user_port_quota(user_id)
    
    # Get user's port forwardings
    port_forwardings = get_user_port_forwardings(user_id)
    
    embed = create_embed("📡 UnixNodes Port Forwardings", f"Your port forwarding configuration", 0x1a1a1a)
    
    # Add quota info
    add_field(embed, "📊 Port Quota", 
              f"**Maximum:** {quota['max_ports']} ports\n**Used:** {quota['used_ports']} ports\n**Available:** {quota['max_ports'] - quota['used_ports']} ports", 
              False)
    
    if port_forwardings:
        forwardings_text = []
        for pf in port_forwardings:
            # Get VPS info
            vps_info = None
            for vps_list in vps_data.values():
                for vps in vps_list:
                    if vps['container_name'] == pf['container_name']:
                        vps_info = vps
                        break
                if vps_info:
                    break
            
            vps_name = pf['container_name']
            if vps_info:
                ram = vps_info['ram']
                cpu = vps_info['cpu']
                vps_name = f"{vps_name} ({ram}/{cpu})"
            
            created = datetime.fromisoformat(pf['created_at']).strftime('%Y-%m-%d')
            forwardings_text.append(
                f"**{pf['container_name']}**\n"
                f"`{pf['internal_port']}` → `{pf['external_port']}` ({pf['protocol'].upper()})\n"
                f"Created: {created}"
            )
        
        if forwardings_text:
            add_field(embed, "🔗 Active Forwardings", "\n\n".join(forwardings_text), False)
    else:
        add_field(embed, "🔗 Active Forwardings", "No active port forwardings", False)
    
    # Add usage instructions
    add_field(embed, "📖 Usage", 
              "**To add a port:** `!port <vps_id> <internal_port>`\n"
              "**To remove a port:** `!port-remove <external_port>`\n"
              "**Example:** `!port myvps-1 22` forwards SSH\n"
              "**Note:** Ports are automatically assigned from 30000-40000 range", 
              False)
    
    await ctx.send(embed=embed)

@bot.command(name='port')
async def port_forward(ctx, container_name: str, internal_port: int, protocol: str = "tcp", description: str = ""):
    """User can forward a port for their VPS"""
    user_id = str(ctx.author.id)
    
    # Validate protocol
    if protocol.lower() not in ['tcp', 'udp', 'both']:
        await ctx.send(embed=create_error_embed("Invalid Protocol", "Protocol must be 'tcp', 'udp', or 'both'."))
        return
    
    # Validate internal port
    if internal_port < 1 or internal_port > 65535:
        await ctx.send(embed=create_error_embed("Invalid Port", "Internal port must be between 1 and 65535."))
        return
    
    # Check if user has VPS
    if user_id not in vps_data:
        await ctx.send(embed=create_error_embed("No VPS", "You don't have any UnixNodes VPS."))
        return
    
    # Check if container exists and belongs to user
    container_found = False
    for vps in vps_data[user_id]:
        if vps['container_name'] == container_name:
            container_found = True
            # Check if VPS is running
            if vps.get('status') != 'running' or vps.get('suspended', False):
                await ctx.send(embed=create_error_embed("VPS Not Running", "VPS must be running to add port forwarding."))
                return
            break
    
    if not container_found:
        await ctx.send(embed=create_error_embed("VPS Not Found", f"No VPS found with name `{container_name}`."))
        return
    
    # Check user's quota
    quota = get_user_port_quota(user_id)
    if quota['used_ports'] >= quota['max_ports']:
        await ctx.send(embed=create_error_embed("Quota Exceeded", 
            f"You have used all {quota['max_ports']} port slots. Contact admin for more."))
        return
    
    # Check if internal port is already forwarded for this container
    existing_forwardings = get_vps_port_forwardings(container_name)
    for pf in existing_forwardings:
        if pf['internal_port'] == internal_port and pf['protocol'] == protocol:
            await ctx.send(embed=create_error_embed("Port Already Forwarded", 
                f"Internal port {internal_port} ({protocol}) is already forwarded on this VPS."))
            return
    
    await ctx.send(embed=create_info_embed("Setting Up Port Forwarding", 
        f"Setting up port forwarding for `{container_name}`..."))
    
    # Get available external port
    external_port = get_available_port()
    if not external_port:
        await ctx.send(embed=create_error_embed("No Ports Available", "No available external ports. Contact admin."))
        return
    
    # Add port forwarding
    success, message = add_port_forwarding(user_id, container_name, internal_port, external_port, protocol, description)
    
    if success:
        # Get container IP for connection details
        container_ip = get_container_ip(container_name)
        
        embed = create_success_embed("Port Forwarding Added", 
            f"Successfully added port forwarding for `{container_name}`")
        
        add_field(embed, "📊 Forwarding Details", 
            f"**Internal:** `{internal_port}` ({protocol.upper()})\n"
            f"**External:** `{external_port}`\n"
            f"**Status:** Active", 
            False)
        
        if container_ip:
            add_field(embed, "🔗 Connection Details",
                f"**SSH/External Access:**\n"
                f"```\n"
                f"Host: your-server-ip\n"
                f"Port: {external_port}\n"
                f"```\n"
                f"**Internal Container:** `{container_ip}:{internal_port}`",
                False)
        
        add_field(embed, "📝 Notes",
            f"• This port forwarding will persist through VPS restarts\n"
            f"• Use `!port-remove {external_port}` to remove\n"
            f"• Use `!port-list` to see all your forwardings",
            False)
        
        await ctx.send(embed=embed)
        
        # Send DM with details
        try:
            dm_embed = create_success_embed("🔗 Port Forwarding Created", 
                f"Your port forwarding has been successfully set up!")
            
            add_field(dm_embed, "Forwarding Details",
                f"**VPS:** `{container_name}`\n"
                f"**Internal Port:** `{internal_port}`\n"
                f"**External Port:** `{external_port}`\n"
                f"**Protocol:** {protocol.upper()}\n"
                f"**Created:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                False)
            
            if container_ip:
                add_field(dm_embed, "Connection Information",
                    f"**For external access:**\n"
                    f"```\n"
                    f"Host: your-server-ip\n"
                    f"Port: {external_port}\n"
                    f"```\n\n"
                    f"**Container internal:**\n"
                    f"```\n"
                    f"IP: {container_ip}\n"
                    f"Port: {internal_port}\n"
                    f"```",
                    False)
            
            add_field(dm_embed, "Example Usage",
                f"**SSH:** `ssh root@your-server-ip -p {external_port}`\n"
                f"**Web Server:** `http://your-server-ip:{external_port}`\n"
                f"**Game Server:** Connect to `your-server-ip:{external_port}`",
                False)
            
            await ctx.author.send(embed=dm_embed)
            
        except discord.Forbidden:
            await ctx.send(embed=create_info_embed("DM Failed", 
                "Could not send DM with port details. Please enable DMs."))
    else:
        await ctx.send(embed=create_error_embed("Port Forwarding Failed", message))

@bot.command(name='port-remove')
async def port_remove(ctx, external_port: int):
    """User can remove their port forwarding"""
    user_id = str(ctx.author.id)
    
    # Validate port
    if external_port < 1 or external_port > 65535:
        await ctx.send(embed=create_error_embed("Invalid Port", "Port must be between 1 and 65535."))
        return
    
    # Check if port forwarding exists and belongs to user
    port_forwardings = get_user_port_forwardings(user_id)
    port_found = False
    
    for pf in port_forwardings:
        if pf['external_port'] == external_port:
            port_found = True
            break
    
    if not port_found:
        await ctx.send(embed=create_error_embed("Port Not Found", 
            f"No port forwarding found with external port `{external_port}`."))
        return
    
    # Remove port forwarding
    success, message = remove_port_forwarding(external_port)
    
    if success:
        embed = create_success_embed("Port Forwarding Removed", 
            f"Successfully removed port forwarding for external port `{external_port}`")
        await ctx.send(embed=embed)
    else:
        await ctx.send(embed=create_error_embed("Removal Failed", message))

@bot.command(name='port-admin-list')
@is_admin()
async def port_admin_list(ctx, user: discord.Member = None):
    """Admin can list all port forwardings or user's forwardings"""
    if user:
        # List specific user's forwardings
        user_id = str(user.id)
        port_forwardings = get_user_port_forwardings(user_id)
        quota = get_user_port_quota(user_id)
        
        embed = create_embed(f"📡 Port Forwardings - {user.name}", 
            f"Port forwardings for {user.mention}", 0x1a1a1a)
        
        add_field(embed, "📊 Quota",
            f"**Maximum:** {quota['max_ports']}\n**Used:** {quota['used_ports']}\n**Available:** {quota['max_ports'] - quota['used_ports']}",
            True)
        
        if port_forwardings:
            forwardings_text = []
            for pf in port_forwardings:
                created = datetime.fromisoformat(pf['created_at']).strftime('%Y-%m-%d %H:%M')
                forwardings_text.append(
                    f"**{pf['container_name']}**\n"
                    f"`{pf['internal_port']}` → `{pf['external_port']}` ({pf['protocol']})\n"
                    f"Created: {created}"
                )
            
            if forwardings_text:
                add_field(embed, "🔗 Forwardings", "\n\n".join(forwardings_text), False)
        else:
            add_field(embed, "🔗 Forwardings", "No active forwardings", False)
        
        await ctx.send(embed=embed)
    else:
        # List all port forwardings
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''SELECT pf.*, u.username 
                      FROM port_forwarding pf 
                      LEFT JOIN (SELECT DISTINCT user_id FROM vps) v ON pf.user_id = v.user_id
                      WHERE pf.status = 'active'
                      ORDER BY pf.created_at DESC''')
        rows = cur.fetchall()
        conn.close()
        
        if not rows:
            await ctx.send(embed=create_info_embed("No Port Forwardings", "No active port forwardings found."))
            return
        
        embed = create_embed("📡 All Port Forwardings", "All active port forwardings on the server", 0x1a1a1a)
        
        forwardings_by_user = {}
        for row in rows:
            user_id = row['user_id']
            if user_id not in forwardings_by_user:
                forwardings_by_user[user_id] = []
            forwardings_by_user[user_id].append(dict(row))
        
        for user_id, forwardings in forwardings_by_user.items():
            try:
                user_obj = await bot.fetch_user(int(user_id))
                user_text = f"{user_obj.mention} ({user_obj.name})"
            except:
                user_text = f"User {user_id}"
            
            user_forwardings = []
            for pf in forwardings:
                created = datetime.fromisoformat(pf['created_at']).strftime('%m-%d %H:%M')
                user_forwardings.append(
                    f"`{pf['container_name']}`: {pf['internal_port']}→{pf['external_port']} ({pf['protocol']})"
                )
            
            if user_forwardings:
                add_field(embed, f"👤 {user_text}", "\n".join(user_forwardings), False)
        
        await ctx.send(embed=embed)

@bot.command(name='port-admin-remove')
@is_admin()
async def port_admin_remove(ctx, external_port: int, *, reason: str = "Admin action"):
    """Admin can remove any port forwarding"""
    # Validate port
    if external_port < 1 or external_port > 65535:
        await ctx.send(embed=create_error_embed("Invalid Port", "Port must be between 1 and 65535."))
        return
    
    # Get port info before removal
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT user_id, container_name FROM port_forwarding WHERE external_port = ?', (external_port,))
    row = cur.fetchone()
    conn.close()
    
    if not row:
        await ctx.send(embed=create_error_embed("Port Not Found", 
            f"No port forwarding found with external port `{external_port}`."))
        return
    
    user_id = row['user_id']
    container_name = row['container_name']
    
    # Remove port forwarding
    success, message = remove_port_forwarding(external_port)
    
    if success:
        embed = create_success_embed("Port Forwarding Removed", 
            f"Admin removed port forwarding `{external_port}`")
        add_field(embed, "Details",
            f"**User:** <@{user_id}>\n"
            f"**Container:** `{container_name}`\n"
            f"**Reason:** {reason}",
            False)
        await ctx.send(embed=embed)
        
        # Notify user
        try:
            user = await bot.fetch_user(int(user_id))
            dm_embed = create_warning_embed("🚨 Port Forwarding Removed",
                f"Your port forwarding on `{container_name}` (external port `{external_port}`) has been removed by an admin.\n\n**Reason:** {reason}")
            await user.send(embed=dm_embed)
        except discord.Forbidden:
            logger.warning(f"Could not DM user {user_id} about port removal")
    else:
        await ctx.send(embed=create_error_embed("Removal Failed", message))

@bot.command(name='port-stats')
@is_admin()
async def port_stats(ctx):
    """Show port forwarding statistics"""
    conn = get_db()
    cur = conn.cursor()
    
    # Get total stats
    cur.execute('SELECT COUNT(*) as total, SUM(allocated) as used FROM port_allocations')
    alloc_row = cur.fetchone()
    
    cur.execute('SELECT COUNT(*) as active FROM port_forwarding WHERE status = "active"')
    active_row = cur.fetchone()
    
    cur.execute('SELECT COUNT(DISTINCT user_id) as users FROM port_forwarding WHERE status = "active"')
    users_row = cur.fetchone()
    
    # Get port range
    min_port = int(get_setting('min_port', 30000))
    max_port = int(get_setting('max_port', 40000))
    
    conn.close()
    
    total_ports = max_port - min_port + 1
    used_ports = alloc_row['used'] if alloc_row['used'] else 0
    available_ports = total_ports - used_ports
    usage_percentage = (used_ports / total_ports * 100) if total_ports > 0 else 0
    
    embed = create_embed("📡 Port Forwarding Statistics", "Server-wide port forwarding stats", 0x1a1a1a)
    
    add_field(embed, "📊 Port Pool",
        f"**Range:** {min_port} - {max_port}\n"
        f"**Total Ports:** {total_ports}\n"
        f"**Used Ports:** {used_ports}\n"
        f"**Available Ports:** {available_ports}\n"
        f"**Usage:** {usage_percentage:.1f}%",
        True)
    
    add_field(embed, "👥 User Statistics",
        f"**Active Users:** {users_row['users'] if users_row else 0}\n"
        f"**Active Forwardings:** {active_row['active'] if active_row else 0}",
        True)
    
    # Get top users by port usage
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''SELECT user_id, COUNT(*) as count 
                  FROM port_forwarding 
                  WHERE status = 'active' 
                  GROUP BY user_id 
                  ORDER BY count DESC 
                  LIMIT 5''')
    top_users = cur.fetchall()
    conn.close()
    
    if top_users:
        top_users_text = []
        for row in top_users:
            try:
                user = await bot.fetch_user(int(row['user_id']))
                user_name = user.name
            except:
                user_name = f"User {row['user_id']}"
            top_users_text.append(f"**{user_name}:** {row['count']} ports")
        
        add_field(embed, "🏆 Top Users", "\n".join(top_users_text), False)
    
    await ctx.send(embed=embed)

@bot.command(name='help')
async def show_help(ctx):
    user_id = str(ctx.author.id)
    is_user_admin = user_id == str(MAIN_ADMIN_ID) or user_id in admin_data.get("admins", [])
    is_user_main_admin = user_id == str(MAIN_ADMIN_ID)
    embed = create_embed("📚 UnixNodes Command Help - User Commands", "UnixNodes VPS Manager Commands:", 0x1a1a1a)
    user_commands = [
        ("!ping", "Check UnixNodes bot latency"),
        ("!uptime", "Show host uptime"),
        ("!myvps", "List your UnixNodes VPS"),
        ("!manage [@user]", "Manage your VPS or another user's VPS (Admin only)"),
        ("!share-user @user <vps_number>", "Share UnixNodes VPS access"),
        ("!share-ruser @user <vps_number>", "Revoke UnixNodes VPS access"),
        ("!manage-shared @owner <vps_number>", "Manage shared UnixNodes VPS"),
        ("!port-list", "List your port forwardings"),
        ("!port <vps_id> <internal_port> [protocol]", "Add port forwarding (tcp/udp/both)"),
        ("!port-remove <external_port>", "Remove port forwarding")
    ]
    user_commands_text = "\n".join([f"**{cmd}** - {desc}" for cmd, desc in user_commands])
    add_field(embed, "👤 User Commands", user_commands_text, False)
    await ctx.send(embed=embed)
    if is_user_admin:
        embed = create_embed("📚 UnixNodes Command Help - Admin Commands", "UnixNodes VPS Manager Commands:", 0x1a1a1a)
        admin_commands = [
            ("!lxc-list", "List all LXC containers"),
            ("!create <ram_gb> <cpu_cores> <disk_gb> @user", "Create VPS with OS selection"),
            ("!delete-vps @user <vps_number> [reason]", "Delete user's UnixNodes VPS"),
            ("!add-resources <container> [ram] [cpu] [disk]", "Add resources to UnixNodes VPS"),
            ("!resize-vps <container> [ram] [cpu] [disk]", "Resize UnixNodes VPS resources"),
            ("!suspend-vps <container> [reason]", "Suspend UnixNodes VPS"),
            ("!unsuspend-vps <container>", "Unsuspend UnixNodes VPS"),
            ("!suspension-logs [container]", "View suspension logs"),
            ("!whitelist-vps <container> <add|remove>", "Whitelist VPS from auto-suspend"),
            ("!resource-check", "Check and suspend high-usage VPS"),
            ("!userinfo @user", "User information"),
            ("!serverstats", "Server statistics"),
            ("!vpsinfo [container]", "VPS information"),
            ("!list-all", "List all VPS"),
            ("!restart-vps <container>", "Restart VPS"),
            ("!exec <container> <command>", "Execute command"),
            ("!stop-vps-all", "Stop all VPS"),
            ("!cpu-monitor <status|enable|disable>", "Resource monitor control"),
            ("!clone-vps <container> [new_name]", "Clone VPS"),
            ("!migrate-vps <container> <pool>", "Migrate VPS"),
            ("!vps-stats <container>", "VPS stats"),
            ("!vps-network <container> <action> [value]", "Network management"),
            ("!vps-processes <container>", "List processes"),
            ("!vps-logs <container> [lines]", "Show logs"),
            ("!vps-uptime <container>", "VPS uptime"),
            ("!apply-permissions <container>", "Apply Docker-ready permissions"),
            ("!snapshot <container> [snap_name]", "Create snapshot"),
            ("!list-snapshots <container>", "List snapshots"),
            ("!restore-snapshot <container> <snap_name>", "Restore snapshot"),
            ("!thresholds", "View resource thresholds"),
            ("!set-threshold <cpu> <ram>", "Set resource thresholds"),
            ("!set-status <type> <name>", "Set bot status"),
            ("!port-admin-list [@user]", "Admin: List port forwardings"),
            ("!port-admin-remove <port> [reason]", "Admin: Remove port forwarding"),
            ("!port-stats", "Port forwarding statistics")
        ]
        admin_commands_text = "\n".join([f"**{cmd}** - {desc}" for cmd, desc in admin_commands])
        add_field(embed, "🛡️ Admin Commands", admin_commands_text, False)
        await ctx.send(embed=embed)
    if is_user_main_admin:
        embed = create_embed("📚 UnixNodes Command Help - Main Admin Commands", "UnixNodes VPS Manager Commands:", 0x1a1a1a)
        main_admin_commands = [
            ("!admin-add @user", "Add admin"),
            ("!admin-remove @user", "Remove admin"),
            ("!admin-list", "List admins"),
            ("!port-add @user <max_ports>", "Add port quota to user")
        ]
        main_admin_commands_text = "\n".join([f"**{cmd}** - {desc}" for cmd, desc in main_admin_commands])
        add_field(embed, "👑 Main Admin Commands", main_admin_commands_text, False)
        embed.set_footer(text="UnixNodes VPS Manager • Port Forwarding • Auto-suspend • Whitelist support • Multi-OS • Enhanced monitoring • Docker-ready VPS • Snapshots")
        await ctx.send(embed=embed)

# Command aliases for typos
@bot.command(name='mangage')
async def manage_typo(ctx):
    await ctx.send(embed=create_info_embed("Command Correction", "Did you mean `!manage`? Use the correct UnixNodes command."))

@bot.command(name='stats')
async def stats_alias(ctx):
    if str(ctx.author.id) == str(MAIN_ADMIN_ID) or str(ctx.author.id) in admin_data.get("admins", []):
        await server_stats(ctx)
    else:
        await ctx.send(embed=create_error_embed("Access Denied", "This UnixNodes command requires admin privileges."))

@bot.command(name='info')
async def info_alias(ctx, user: discord.Member = None):
    if str(ctx.author.id) == str(MAIN_ADMIN_ID) or str(ctx.author.id) in admin_data.get("admins", []):
        if user:
            await user_info(ctx, user)
        else:
            await ctx.send(embed=create_error_embed("Usage", "Please specify a user: `!info @user`"))
    else:
        await ctx.send(embed=create_error_embed("Access Denied", "This UnixNodes command requires admin privileges."))

# Run the bot
if __name__ == "__main__":
    if DISCORD_TOKEN:
        bot.run(DISCORD_TOKEN)
    else:
        logger.error("No Discord token found in DISCORD_TOKEN environment variable.")