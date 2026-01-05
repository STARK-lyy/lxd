
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
        ('next_available_port', '40000')
    ]
    for key, value in settings_init:
        cur.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (key, value))

    cur.execute('''CREATE TABLE IF NOT EXISTS user_port_slots (
        user_id TEXT PRIMARY KEY,
        slots INTEGER DEFAULT 0
    )''')

    cur.execute('''CREATE TABLE IF NOT EXISTS forwarded_ports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        container_name TEXT NOT NULL,
        host_port INTEGER NOT NULL,
        container_port INTEGER NOT NULL,
        created_at TEXT NOT NULL
    )''')

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

def get_user_slots(user_id: str) -> int:
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT slots FROM user_port_slots WHERE user_id = ?', (user_id,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else 0

def set_user_slots(user_id: str, slots: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('INSERT OR REPLACE INTO user_port_slots (user_id, slots) VALUES (?, ?)', (user_id, slots))
    conn.commit()
    conn.close()

def get_next_port() -> int:
    next_port = int(get_setting('next_available_port', '40000'))
    set_setting('next_available_port', str(next_port + 1))
    return next_port

def add_forwarded_port(user_id: str, container_name: str, host_port: int, container_port: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('INSERT INTO forwarded_ports (user_id, container_name, host_port, container_port, created_at) VALUES (?, ?, ?, ?, ?)',
                (user_id, container_name, host_port, container_port, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_user_forwards(user_id: str) -> List[Dict]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM forwarded_ports WHERE user_id = ?', (user_id,))
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def remove_forwarded_port(user_id: str, container_name: str, container_port: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM forwarded_ports WHERE user_id = ? AND container_name = ? AND container_port = ?', (user_id, container_name, container_port))
    conn.commit()
    conn.close()

def remove_all_forwards_for_container(user_id: str, container_name: str):
    forwards = [f for f in get_user_forwards(user_id) if f['container_name'] == container_name]
    for f in forwards:
        remove_forwarded_port(user_id, container_name, f['container_port'])
    slots = get_user_slots(user_id)
    set_user_slots(user_id, slots + len(forwards))

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
            total = 
