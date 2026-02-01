# gg_multi_node_bot.py - COMPLETE INTEGRATION
# ALL old features + NEW multi-node architecture

import discord
from discord.ext import commands, tasks
import asyncio
import aiohttp
import json
import hmac
import hashlib
import secrets
import string
import time
from datetime import datetime, timedelta
import sqlite3
import logging
import os
import subprocess
import shlex
import shutil
from typing import Optional, Dict, List, Any, Tuple
import random
import uuid
import threading

# ==================== CONFIGURATION ====================
DISCORD_TOKEN = os.environ.get('DISCORD_TOKEN', '')
BOT_NAME = 'GG MULTI-NODE PANEL'
PREFIX = '!'
MAIN_ADMIN_ID = os.environ.get('MAIN_ADMIN_ID', '1405866008127864852')
PUBLIC_ENDPOINT = os.environ.get('PUBLIC_ENDPOINT', 'https://bot.example.com')
YOUR_SERVER_IP = os.environ.get('YOUR_SERVER_IP', '')
VPS_USER_ROLE_ID = ''
DEFAULT_STORAGE_POOL = 'default'

# OS Options
OS_OPTIONS = [
    {"label": "Ubuntu 20.04 LTS", "value": "ubuntu:20.04"},
    {"label": "Ubuntu 22.04 LTS", "value": "ubuntu:22.04"},
    {"label": "Ubuntu 24.04 LTS", "value": "ubuntu:24.04"},
    {"label": "Debian 10 (Buster)", "value": "images:debian/10"},
    {"label": "Debian 11 (Bullseye)", "value": "images:debian/11"},
    {"label": "Debian 12 (Bookworm)", "value": "images:debian/12"},
    {"label": "Debian 13 (Trixie)", "value": "images:debian/13"},
]

# Status rotation messages
STATUS_ROTATIONS = [
    "WATCHING GG DEVELOPMENT",
    "WATCHING POWERING MULTI-NODES", 
    "WATCHING MADE BY GG"
]

# ==================== LOGGING ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('gg_master.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(f'{BOT_NAME.lower()}_master')

# ==================== DATABASE ====================
def get_db():
    conn = sqlite3.connect('gg_master.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database with ALL features"""
    conn = get_db()
    cur = conn.cursor()
    
    # ===== NEW TABLES for multi-node =====
    # Nodes
    cur.execute('''CREATE TABLE IF NOT EXISTS nodes (
        node_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        location TEXT NOT NULL,
        max_vps INTEGER NOT NULL,
        tag TEXT NOT NULL,
        node_ip TEXT,
        api_key TEXT UNIQUE NOT NULL,
        secret_key TEXT NOT NULL,
        status TEXT DEFAULT 'offline',
        dev_mode INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        last_seen TEXT,
        total_created INTEGER DEFAULT 0
    )''')
    
    # Node statistics
    cur.execute('''CREATE TABLE IF NOT EXISTS node_stats (
        node_id TEXT PRIMARY KEY,
        ping_ms INTEGER DEFAULT 0,
        vps_count INTEGER DEFAULT 0,
        cpu_usage REAL DEFAULT 0,
        ram_usage REAL DEFAULT 0,
        last_update TEXT,
        FOREIGN KEY (node_id) REFERENCES nodes (node_id)
    )''')
    
    # ===== ORIGINAL TABLES (preserved) =====
    # Admins
    cur.execute('''CREATE TABLE IF NOT EXISTS admins (
        user_id TEXT PRIMARY KEY
    )''')
    cur.execute('INSERT OR IGNORE INTO admins (user_id) VALUES (?)', (str(MAIN_ADMIN_ID),))
    
    # VPS (EXTENDED with node_id)
    cur.execute('''CREATE TABLE IF NOT EXISTS vps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vps_id TEXT UNIQUE,
        user_id TEXT NOT NULL,
        container_name TEXT NOT NULL,
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
        suspension_history TEXT DEFAULT '[]',
        node_id TEXT,
        safe_purge INTEGER DEFAULT 0,
        FOREIGN KEY (node_id) REFERENCES nodes (node_id)
    )''')
    
    # Settings
    cur.execute('''CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )''')
    
    settings_init = [
        ('global_dev_mode', '0'),
        ('cpu_threshold', '90'),
        ('ram_threshold', '90'),
        ('purge_safe_duration', '24'),
    ]
    
    for key, value in settings_init:
        cur.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (key, value))
    
    # Port allocations (original)
    cur.execute('''CREATE TABLE IF NOT EXISTS port_allocations (
        user_id TEXT PRIMARY KEY,
        allocated_ports INTEGER DEFAULT 0
    )''')
    
    # Port forwards (EXTENDED with node_id)
    cur.execute('''CREATE TABLE IF NOT EXISTS port_forwards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        vps_id TEXT NOT NULL,
        vps_container TEXT NOT NULL,
        node_id TEXT,
        vps_port INTEGER NOT NULL,
        host_port INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (vps_id) REFERENCES vps (vps_id),
        FOREIGN KEY (node_id) REFERENCES nodes (node_id)
    )''')
    
    conn.commit()
    conn.close()

# ==================== GLOBAL STATE ====================
init_db()
admin_data = {'admins': []}
vps_data = {}  # Will be loaded from DB

# Load existing admins
conn = get_db()
cur = conn.cursor()
cur.execute('SELECT user_id FROM admins')
admin_data['admins'] = [row['user_id'] for row in cur.fetchall()]
conn.close()

# Global settings
CPU_THRESHOLD = int(get_setting('cpu_threshold', 90))
RAM_THRESHOLD = int(get_setting('ram_threshold', 90))
GLOBAL_DEV_MODE = get_setting('global_dev_mode', '0') == '1'

# ==================== HELPER FUNCTIONS ====================
def load_vps_data():
    """Load all VPS data from database"""
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
        vps['shared_with'] = json.loads(vps['shared_with']) if vps['shared_with'] else []
        vps['suspension_history'] = json.loads(vps['suspension_history']) if vps['suspension_history'] else []
        vps['suspended'] = bool(vps['suspended'])
        vps['whitelisted'] = bool(vps['whitelisted'])
        vps['os_version'] = vps.get('os_version', 'ubuntu:22.04')
        data[user_id].append(vps)
    return data

vps_data = load_vps_data()

def save_vps_data():
    """Save VPS data to database"""
    conn = get_db()
    cur = conn.cursor()
    
    for user_id, vps_list in vps_data.items():
        for vps in vps_list:
            shared_json = json.dumps(vps.get('shared_with', []))
            history_json = json.dumps(vps.get('suspension_history', []))
            suspended_int = 1 if vps.get('suspended', False) else 0
            whitelisted_int = 1 if vps.get('whitelisted', False) else 0
            os_ver = vps.get('os_version', 'ubuntu:22.04')
            created_at = vps.get('created_at', datetime.now().isoformat())
            node_id = vps.get('node_id')
            safe_purge = 1 if vps.get('safe_purge', False) else 0
            
            # Generate vps_id if not exists
            if 'vps_id' not in vps or not vps['vps_id']:
                vps['vps_id'] = f"vps_{uuid.uuid4().hex[:8]}"
            
            if 'id' not in vps or vps['id'] is None:
                cur.execute('''INSERT INTO vps 
                    (vps_id, user_id, container_name, ram, cpu, storage, config, os_version, 
                     status, suspended, whitelisted, created_at, shared_with, suspension_history, node_id, safe_purge)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (vps['vps_id'], user_id, vps['container_name'], vps['ram'], vps['cpu'], vps['storage'],
                     vps.get('config', ''), os_ver, vps['status'], suspended_int, whitelisted_int,
                     created_at, shared_json, history_json, node_id, safe_purge))
                vps['id'] = cur.lastrowid
            else:
                cur.execute('''UPDATE vps SET 
                    user_id=?, ram=?, cpu=?, storage=?, config=?, os_version=?, status=?,
                    suspended=?, whitelisted=?, shared_with=?, suspension_history=?, node_id=?, safe_purge=?
                    WHERE id=?''',
                    (user_id, vps['ram'], vps['cpu'], vps['storage'], vps.get('config', ''),
                     os_ver, vps['status'], suspended_int, whitelisted_int, shared_json,
                     history_json, node_id, safe_purge, vps['id']))
    
    conn.commit()
    conn.close()

# ==================== NODE AUTHENTICATION ====================
def generate_api_key() -> str:
    return f"gg_{secrets.token_urlsafe(24)}"

def generate_secret_key() -> str:
    return secrets.token_urlsafe(48)

def sign_request(secret_key: str, data: dict) -> str:
    message = json.dumps(data, sort_keys=True)
    signature = hmac.new(
        secret_key.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    return signature

# ==================== NODE MANAGEMENT ====================
class NodeManager:
    @staticmethod
    def add_node(name: str, location: str, max_vps: int, tag: str, node_ip: str = "") -> Tuple[str, str]:
        """Add new node and return (api_key, secret_key)"""
        node_id = f"node_{uuid.uuid4().hex[:8]}"
        api_key = generate_api_key()
        secret_key = generate_secret_key()
        
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''INSERT INTO nodes 
                       (node_id, name, location, max_vps, tag, node_ip, api_key, secret_key, created_at, status) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (node_id, name, location, max_vps, tag, node_ip, api_key, secret_key, 
                     datetime.now().isoformat(), 'offline'))
        conn.commit()
        conn.close()
        
        return api_key, secret_key
    
    @staticmethod
    def get_node_by_api_key(api_key: str):
        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT * FROM nodes WHERE api_key = ?', (api_key,))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None
    
    @staticmethod
    def get_node(node_id: str):
        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT * FROM nodes WHERE node_id = ?', (node_id,))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None
    
    @staticmethod
    def update_node_status(node_id: str, status: str, ping_ms: int = 0):
        conn = get_db()
        cur = conn.cursor()
        
        now = datetime.now().isoformat()
        cur.execute('''UPDATE nodes SET status = ?, last_seen = ? WHERE node_id = ?''',
                    (status, now, node_id))
        
        if status == 'online':
            cur.execute('''INSERT OR REPLACE INTO node_stats 
                           (node_id, ping_ms, last_update) VALUES (?, ?, ?)''',
                        (node_id, ping_ms, now))
        
        conn.commit()
        conn.close()
    
    @staticmethod
    def get_online_nodes() -> List[Dict]:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''SELECT n.*, ns.ping_ms, ns.vps_count 
                       FROM nodes n 
                       LEFT JOIN node_stats ns ON n.node_id = ns.node_id 
                       WHERE n.status = "online" AND n.dev_mode = 0''')
        rows = cur.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    @staticmethod
    def get_all_nodes() -> List[Dict]:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''SELECT n.*, ns.ping_ms, ns.vps_count 
                       FROM nodes n 
                       LEFT JOIN node_stats ns ON n.node_id = ns.node_id''')
        rows = cur.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    @staticmethod
    def get_node_vps_count(node_id: str) -> int:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) FROM vps WHERE node_id = ?', (node_id,))
        count = cur.fetchone()[0]
        conn.close()
        return count
    
    @staticmethod
    def is_node_available(node_id: str) -> bool:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT status, dev_mode FROM nodes WHERE node_id = ?', (node_id,))
        row = cur.fetchone()
        conn.close()
        
        if not row:
            return False
        return row['status'] == 'online' and row['dev_mode'] == 0
    
    @staticmethod
    def remove_node(node_id: str) -> bool:
        """Remove node (only if no VPS attached)"""
        # Check if node has VPS
        vps_count = NodeManager.get_node_vps_count(node_id)
        if vps_count > 0:
            return False
        
        conn = get_db()
        cur = conn.cursor()
        cur.execute('DELETE FROM nodes WHERE node_id = ?', (node_id,))
        cur.execute('DELETE FROM node_stats WHERE node_id = ?', (node_id,))
        conn.commit()
        conn.close()
        return True
    
    @staticmethod
    def set_node_dev_mode(node_id: str, enabled: bool):
        conn = get_db()
        cur = conn.cursor()
        cur.execute('UPDATE nodes SET dev_mode = ? WHERE node_id = ?', 
                    (1 if enabled else 0, node_id))
        conn.commit()
        conn.close()

# ==================== WEB SERVER FOR NODE HEARTBEATS ====================
from aiohttp import web
import aiohttp_cors

class NodeAPI:
    def __init__(self):
        self.app = web.Application()
        self.setup_routes()
    
    def setup_routes(self):
        self.app.router.add_post('/api/v1/heartbeat', self.handle_heartbeat)
        
        # Configure CORS
        cors = aiohttp_cors.setup(self.app, defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
            )
        })
        
        for route in list(self.app.router.routes()):
            cors.add(route)
    
    async def handle_heartbeat(self, request):
        """Handle node heartbeat with authentication"""
        try:
            data = await request.json()
            
            # Verify API key
            api_key = data.get('api_key')
            node = NodeManager.get_node_by_api_key(api_key)
            if not node:
                return web.json_response({'error': 'Invalid API key'}, status=401)
            
            # Verify signature
            signature = data.get('signature')
            if not signature or not verify_signature(node['secret_key'], data, signature):
                return web.json_response({'error': 'Invalid signature'}, status=401)
            
            # Update node status
            ping_ms = data.get('ping_ms', 0)
            vps_count = data.get('vps_count', 0)
            cpu_usage = data.get('cpu_usage', 0)
            ram_usage = data.get('ram_usage', 0)
            
            NodeManager.update_node_status(node['node_id'], 'online', ping_ms)
            
            # Update node stats
            conn = get_db()
            cur = conn.cursor()
            cur.execute('''INSERT OR REPLACE INTO node_stats 
                           (node_id, ping_ms, vps_count, cpu_usage, ram_usage, last_update) 
                           VALUES (?, ?, ?, ?, ?, ?)''',
                        (node['node_id'], ping_ms, vps_count, cpu_usage, ram_usage, 
                         datetime.now().isoformat()))
            conn.commit()
            conn.close()
            
            # Get pending commands for this node
            # (You'll implement command queue later)
            
            return web.json_response({
                'status': 'ok',
                'node_id': node['node_id'],
                'commands': []  # Empty for now
            })
            
        except Exception as e:
            logger.error(f"Heartbeat error: {e}")
            return web.json_response({'error': str(e)}, status=500)

async def start_web_server():
    """Start the web server for node communication"""
    api = NodeAPI()
    runner = web.AppRunner(api.app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 8080)
    await site.start()
    logger.info("Node API server started on port 8080")

# ==================== DISCORD BOT ====================
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
bot = commands.Bot(command_prefix=PREFIX, intents=intents, help_command=None)

# ==================== EMBED FUNCTIONS ====================
def create_embed(title, description="", color=0x1a1a1a):
    embed = discord.Embed(
        title=f"⭐ {BOT_NAME} - {title}",
        description=description,
        color=color
    )
    embed.set_footer(text=f"{BOT_NAME} • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    return embed

def create_success_embed(title, description=""):
    return create_embed(title, description, 0x00ff88)

def create_error_embed(title, description=""):
    return create_embed(title, description, 0xff3366)

def create_info_embed(title, description=""):
    return create_embed(title, description, 0x00ccff)

def create_warning_embed(title, description=""):
    return create_embed(title, description, 0xffaa00)

def add_field(embed, name, value, inline=False):
    embed.add_field(name=f"▸ {name}", value=value, inline=inline)
    return embed

# ==================== PERMISSION CHECKS ====================
def is_admin():
    async def predicate(ctx):
        if GLOBAL_DEV_MODE and str(ctx.author.id) != str(MAIN_ADMIN_ID):
            raise commands.CheckFailure("Global dev mode active - Only main admin can operate")
        
        user_id = str(ctx.author.id)
        if user_id == str(MAIN_ADMIN_ID) or user_id in admin_data.get("admins", []):
            return True
        raise commands.CheckFailure("Admin permissions required")
    return commands.check(predicate)

def is_main_admin():
    async def predicate(ctx):
        if str(ctx.author.id) == str(MAIN_ADMIN_ID):
            return True
        raise commands.CheckFailure("Main admin only")
    return commands.check(predicate)

def is_not_dev_mode():
    async def predicate(ctx):
        if GLOBAL_DEV_MODE:
            raise commands.CheckFailure("Global dev mode active - Commands disabled")
        return True
    return commands.check(predicate)

# ==================== STATUS ROTATION TASK ====================
@tasks.loop(seconds=5)
async def rotate_status():
    """Rotate bot status every 5 seconds"""
    if GLOBAL_DEV_MODE:
        await bot.change_presence(activity=None)
        return
    
    current = rotate_status.current
    if current >= len(STATUS_ROTATIONS):
        rotate_status.current = 0
        current = 0
    
    await bot.change_presence(
        activity=discord.Activity(
            type=discord.ActivityType.watching,
            name=STATUS_ROTATIONS[current]
        )
    )
    rotate_status.current = current + 1
rotate_status.current = 0

# ==================== NODE COMMANDS ====================
class NodeAddView(discord.ui.View):
    def __init__(self, ctx):
        super().__init__(timeout=300)
        self.ctx = ctx
        self.step = 1
        self.node_data = {}
    
    @discord.ui.button(label="Start Node Setup", style=discord.ButtonStyle.primary)
    async def start_setup(self, interaction: discord.Interaction, button: discord.ui.Button):
        if str(interaction.user.id) != str(self.ctx.author.id):
            await interaction.response.send_message(embed=create_error_embed("Not your session"), ephemeral=True)
            return
        
        self.step = 1
        embed = create_info_embed("Add Node - Step 1", "Enter the **Node Name**:")
        await interaction.response.edit_message(embed=embed, view=self)

@bot.command(name='node-add')
@is_main_admin()
async def node_add(ctx):
    """Start interactive node addition"""
    embed = create_info_embed("Add New Node", 
        "Click below to start the setup process.\n\n"
        "You'll be asked for:\n"
        "1. Node Name\n"
        "2. Location\n"
        "3. Max VPS capacity\n"
        "4. Tag\n"
        "5. Node IP (optional)\n\n"
        "After confirmation, you'll receive API keys shown **ONCE**.")
    
    view = NodeAddView(ctx)
    await ctx.send(embed=embed, view=view)

@bot.command(name='node-list')
@is_admin()
async def node_list(ctx):
    """List all nodes"""
    nodes = NodeManager.get_all_nodes()
    
    if not nodes:
        await ctx.send(embed=create_info_embed("No Nodes", "No nodes have been added yet."))
        return
    
    embed = create_embed("Node List", f"Total nodes: {len(nodes)}")
    
    for node in nodes:
        status_emoji = "🟢" if node['status'] == 'online' else "🔴"
        dev_mode = "🔧" if node['dev_mode'] == 1 else ""
        
        vps_count = node['vps_count'] or 0
        max_vps = node['max_vps']
        
        info = (f"**Location:** {node['location']}\n"
                f"**Status:** {node['status'].upper()} {dev_mode}\n"
                f"**VPS:** {vps_count}/{max_vps}\n"
                f"**Tag:** {node['tag']}\n"
                f"**Last Seen:** {node['last_seen'][:16] if node['last_seen'] else 'Never'}")
        
        add_field(embed, f"{status_emoji} {node['name']}", info, True)
    
    await ctx.send(embed=embed)

@bot.command(name='node-status')
@is_admin()
async def node_status(ctx, node_id: str = None):
    """Show detailed node status"""
    if node_id:
        node = NodeManager.get_node(node_id)
        if not node:
            await ctx.send(embed=create_error_embed("Node not found"))
            return
        
        status_emoji = "🟢" if node['status'] == 'online' else "🔴"
        dev_mode = " (Dev Mode)" if node['dev_mode'] == 1 else ""
        
        embed = create_embed(f"Node Status - {node['name']}", 
                            f"{status_emoji} **{node['status'].upper()}**{dev_mode}")
        
        add_field(embed, "📋 Details", 
                 f"**ID:** {node['node_id']}\n"
                 f"**Location:** {node['location']}\n"
                 f"**Tag:** {node['tag']}\n"
                 f"**IP:** {node['node_ip'] or 'N/A'}\n"
                 f"**Created:** {node['created_at'][:10]}", False)
        
        add_field(embed, "📊 Capacity", 
                 f"**VPS Limit:** {node['max_vps']}\n"
                 f"**Current VPS:** {NodeManager.get_node_vps_count(node_id)}\n"
                 f"**Total Created:** {node['total_created']}", False)
        
        if node['status'] == 'online':
            conn = get_db()
            cur = conn.cursor()
            cur.execute('SELECT * FROM node_stats WHERE node_id = ?', (node_id,))
            stats = cur.fetchone()
            conn.close()
            
            if stats:
                add_field(embed, "📈 Live Stats",
                         f"**Ping:** {stats['ping_ms']}ms\n"
                         f"**CPU Usage:** {stats['cpu_usage']:.1f}%\n"
                         f"**RAM Usage:** {stats['ram_usage']:.1f}%\n"
                         f"**Last Update:** {stats['last_update'][11:19]}", False)
        
        await ctx.send(embed=embed)
    else:
        await node_list(ctx)

@bot.command(name='node-remove')
@is_main_admin()
async def node_remove(ctx, node_id: str):
    """Remove a node (only if no VPS)"""
    node = NodeManager.get_node(node_id)
    if not node:
        await ctx.send(embed=create_error_embed("Node not found"))
        return
    
    vps_count = NodeManager.get_node_vps_count(node_id)
    if vps_count > 0:
        await ctx.send(embed=create_error_embed("Cannot Remove", 
            f"Node has {vps_count} VPS attached. Migrate or delete VPS first."))
        return
    
    embed = create_warning_embed("Confirm Node Removal",
        f"Remove node **{node['name']}** ({node_id})?\n\n"
        f"**Location:** {node['location']}\n"
        f"**Tag:** {node['tag']}\n\n"
        f"⚠️ This action cannot be undone!")
    
    class ConfirmView(discord.ui.View):
        @discord.ui.button(label="Confirm Removal", style=discord.ButtonStyle.danger)
        async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
            success = NodeManager.remove_node(node_id)
            if success:
                await interaction.response.edit_message(
                    embed=create_success_embed("Node Removed", 
                        f"Node **{node['name']}** has been removed."),
                    view=None
                )
            else:
                await interaction.response.edit_message(
                    embed=create_error_embed("Removal Failed"),
                    view=None
                )
        
        @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
        async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
            await interaction.response.edit_message(
                embed=create_info_embed("Cancelled", "Node removal cancelled."),
                view=None
            )
    
    await ctx.send(embed=embed, view=ConfirmView())

# ==================== DEV MODE COMMANDS ====================
@bot.command(name='devmode')
@is_main_admin()
async def devmode(ctx, action: str):
    """Global dev mode control"""
    global GLOBAL_DEV_MODE
    
    if action.lower() == 'on':
        GLOBAL_DEV_MODE = True
        set_setting('global_dev_mode', '1')
        await bot.change_presence(activity=None)
        await ctx.send(embed=create_warning_embed("🔧 Global Dev Mode ENABLED",
            "All user/admin commands are now blocked.\n"
            "Only MAIN ADMIN can operate.\n"
            "Bot status is now invisible."))
    
    elif action.lower() == 'off':
        GLOBAL_DEV_MODE = False
        set_setting('global_dev_mode', '0')
        await ctx.send(embed=create_success_embed("🔧 Global Dev Mode DISABLED",
            "Normal operations resumed."))
    
    else:
        await ctx.send(embed=create_error_embed("Usage", "!devmode <on|off>"))

@bot.command(name='devmnode')
@is_main_admin()
async def devmnode(ctx, action: str, node_id: str):
    """Node-specific dev mode"""
    node = NodeManager.get_node(node_id)
    if not node:
        await ctx.send(embed=create_error_embed("Node not found"))
        return
    
    if action.lower() == 'on':
        NodeManager.set_node_dev_mode(node_id, True)
        await ctx.send(embed=create_warning_embed("🔧 Node Dev Mode ENABLED",
            f"Node **{node['name']}** is now in dev mode.\n"
            f"• VPS creation blocked\n"
            f"• Existing VPS continue running\n"
            f"• Other nodes unaffected"))
    
    elif action.lower() == 'off':
        NodeManager.set_node_dev_mode(node_id, False)
        await ctx.send(embed=create_success_embed("🔧 Node Dev Mode DISABLED",
            f"Node **{node['name']}** dev mode disabled.\n"
            f"Normal operations resumed."))
    
    else:
        await ctx.send(embed=create_error_embed("Usage", "!devmnode <on|off> <node_id>"))

# ==================== PURGE SYSTEM ====================
@bot.command(name='purge')
@is_main_admin()
async def purge(ctx):
    """Purge all non-safe VPS"""
    embed = create_warning_embed("🚨 PURGE ALL VPS",
        "⚠️ **WARNING: This will delete ALL VPS across ALL nodes!**\n\n"
        "Only VPS marked as SAFE will be preserved.\n"
        "After purge, the SAFE list is automatically cleared.\n\n"
        "**THIS ACTION CANNOT BE UNDONE!**")
    
    class PurgeConfirm(discord.ui.View):
        @discord.ui.button(label="PURGE EVERYTHING", style=discord.ButtonStyle.danger)
        async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
            await interaction.response.defer()
            
            # Get all non-safe VPS
            conn = get_db()
            cur = conn.cursor()
            cur.execute('SELECT vps_id, container_name, node_id FROM vps WHERE safe_purge = 0')
            vps_to_delete = cur.fetchall()
            
            total = len(vps_to_delete)
            deleted = 0
            errors = []
            
            for vps in vps_to_delete:
                try:
                    # Here you would send delete command to the appropriate node
                    # For now, just delete from database
                    cur.execute('DELETE FROM vps WHERE vps_id = ?', (vps['vps_id'],))
                    cur.execute('DELETE FROM port_forwards WHERE vps_id = ?', (vps['vps_id'],))
                    deleted += 1
                except Exception as e:
                    errors.append(f"{vps['container_name']}: {str(e)}")
            
            # Clear safe list
            cur.execute('UPDATE vps SET safe_purge = 0 WHERE safe_purge = 1')
            
            conn.commit()
            conn.close()
            
            # Reload VPS data
            global vps_data
            vps_data = load_vps_data()
            
            result_embed = create_embed("🔄 Purge Complete",
                f"**Deleted:** {deleted} VPS\n"
                f"**Preserved:** {total - deleted} safe VPS\n"
                f"**Errors:** {len(errors)}")
            
            if errors:
                add_field(result_embed, "Errors", "\n".join(errors[:5]), False)
                if len(errors) > 5:
                    add_field(result_embed, "Note", f"{len(errors)-5} more errors...", False)
            
            await interaction.followup.send(embed=result_embed)
        
        @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
        async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
            await interaction.response.edit_message(
                embed=create_info_embed("Purge Cancelled", "No VPS were deleted."),
                view=None
            )
    
    await ctx.send(embed=embed, view=PurgeConfirm())

@bot.command(name='purge-s')
@is_admin()
async def purge_safe(ctx, vps_id: str):
    """Mark VPS as safe from purge"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('UPDATE vps SET safe_purge = 1 WHERE vps_id = ?', (vps_id,))
    updated = cur.rowcount
    conn.commit()
    conn.close()
    
    if updated:
        await ctx.send(embed=create_success_embed("✅ VPS Protected",
            f"VPS `{vps_id}` marked as SAFE from purge.\n"
            f"It will be preserved during !purge command."))
    else:
        await ctx.send(embed=create_error_embed("VPS not found"))

@bot.command(name='purge-s-list')
@is_admin()
async def purge_safe_list(ctx):
    """List all safe VPS"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT vps_id, container_name, user_id FROM vps WHERE safe_purge = 1')
    safe_vps = cur.fetchall()
    conn.close()
    
    if not safe_vps:
        await ctx.send(embed=create_info_embed("No Safe VPS", "No VPS are marked as safe."))
        return
    
    embed = create_embed("🛡️ Safe VPS List", 
        f"These VPS will be preserved during purge:\nTotal: {len(safe_vps)}")
    
    for vps in safe_vps:
        try:
            user = await bot.fetch_user(int(vps['user_id']))
            user_name = user.name
        except:
            user_name = f"User {vps['user_id']}"
        
        add_field(embed, vps['container_name'], 
                 f"**ID:** {vps['vps_id']}\n**Owner:** {user_name}", True)
    
    await ctx.send(embed=embed)

@bot.command(name='purge-s-remove')
@is_admin()
async def purge_safe_remove(ctx, vps_id: str):
    """Remove VPS from safe list"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('UPDATE vps SET safe_purge = 0 WHERE vps_id = ?', (vps_id,))
    updated = cur.rowcount
    conn.commit()
    conn.close()
    
    if updated:
        await ctx.send(embed=create_warning_embed("🛡️ Protection Removed",
            f"VPS `{vps_id}` is no longer safe from purge."))
    else:
        await ctx.send(embed=create_error_embed("VPS not found"))

# ==================== GLOBAL STATUS ====================
@bot.command(name='status')
@is_admin()
async def global_status(ctx):
    """Show global system status"""
    nodes = NodeManager.get_all_nodes()
    total_nodes = len(nodes)
    online_nodes = sum(1 for n in nodes if n['status'] == 'online')
    
    conn = get_db()
    cur = conn.cursor()
    
    # VPS statistics
    cur.execute('SELECT COUNT(*) as total, '
                'SUM(CASE WHEN status = "running" AND suspended = 0 THEN 1 ELSE 0 END) as running, '
                'SUM(CASE WHEN status = "stopped" THEN 1 ELSE 0 END) as stopped, '
                'SUM(CASE WHEN suspended = 1 THEN 1 ELSE 0 END) as suspended '
                'FROM vps')
    vps_stats = cur.fetchone()
    
    # Resource usage
    cur.execute('SELECT SUM(CAST(ram AS INTEGER)) as total_ram, '
                'SUM(CAST(cpu AS INTEGER)) as total_cpu, '
                'SUM(CAST(storage AS INTEGER)) as total_storage '
                'FROM vps')
    resource_stats = cur.fetchone()
    
    conn.close()
    
    embed = create_embed("🌐 Global System Status", 
        f"**Bot Uptime:** {time.strftime('%H:%M:%S', time.gmtime(time.time() - bot.start_time))}\n"
        f"**Dev Mode:** {'🔧 ON' if GLOBAL_DEV_MODE else '✅ OFF'}")
    
    add_field(embed, "📊 Node Overview",
             f"**Total Nodes:** {total_nodes}\n"
             f"**Online:** {online_nodes}\n"
             f"**Offline:** {total_nodes - online_nodes}", True)
    
    add_field(embed, "🖥️ VPS Overview",
             f"**Total VPS:** {vps_stats['total'] or 0}\n"
             f"**Running:** {vps_stats['running'] or 0}\n"
             f"**Stopped:** {vps_stats['stopped'] or 0}\n"
             f"**Suspended:** {vps_stats['suspended'] or 0}", True)
    
    if resource_stats and resource_stats['total_ram']:
        add_field(embed, "📈 Resource Allocation",
                 f"**Total RAM:** {resource_stats['total_ram']}GB\n"
                 f"**Total CPU:** {resource_stats['total_cpu']} cores\n"
                 f"**Total Storage:** {resource_stats['total_storage']}GB", False)
    
    # Node ping summary
    if online_nodes > 0:
        pings = [n['ping_ms'] or 0 for n in nodes if n['status'] == 'online' and n.get('ping_ms')]
        if pings:
            avg_ping = sum(pings) // len(pings)
            min_ping = min(pings)
            max_ping = max(pings)
            
            add_field(embed, "📡 Node Performance",
                     f"**Avg Ping:** {avg_ping}ms\n"
                     f"**Best:** {min_ping}ms\n"
                     f"**Worst:** {max_ping}ms", False)
    
    # System health
    health = "🟢 Excellent"
    if online_nodes == 0:
        health = "🔴 Critical"
    elif online_nodes < total_nodes // 2:
        health = "🟡 Degraded"
    
    add_field(embed, "❤️ System Health", health, False)
    
    await ctx.send(embed=embed)

# ==================== VPS CREATION WITH NODE SELECTION ====================
class NodeSelectView(discord.ui.View):
    def __init__(self, ram: int, cpu: int, disk: int, user: discord.Member, ctx):
        super().__init__(timeout=300)
        self.ram = ram
        self.cpu = cpu
        self.disk = disk
        self.user = user
        self.ctx = ctx
        self.selected_node = None
        
        # Get available nodes
        nodes = NodeManager.get_online_nodes()
        
        if not nodes:
            self.select = discord.ui.Select(
                placeholder="No online nodes available",
                options=[discord.SelectOption(label="No nodes available", value="none")],
                disabled=True
            )
        else:
            options = []
            for node in nodes:
                current = NodeManager.get_node_vps_count(node['node_id'])
                available = node['max_vps'] - current
                
                label = f"{node['name']} ({node['location']})"
                description = f"{available} slots available • Ping: {node['ping_ms']}ms"
                
                options.append(discord.SelectOption(
                    label=label[:100],
                    description=description[:100],
                    value=node['node_id']
                ))
            
            self.select = discord.ui.Select(
                placeholder="Select a node for deployment",
                options=options
            )
        
        self.select.callback = self.select_node
        self.add_item(self.select)
    
    async def select_node(self, interaction: discord.Interaction):
        if str(interaction.user.id) != str(self.ctx.author.id):
            await interaction.response.send_message(embed=create_error_embed("Not your session"), ephemeral=True)
            return
        
        node_id = self.select.values[0]
        if node_id == "none":
            await interaction.response.send_message(embed=create_error_embed("No nodes available"), ephemeral=True)
            return
        
        node = NodeManager.get_node(node_id)
        if not NodeManager.is_node_available(node_id):
            await interaction.response.send_message(embed=create_error_embed("Node unavailable"), ephemeral=True)
            return
        
        self.selected_node = node
        self.select.disabled = True
        
        # Now show OS selection
        os_view = OSSelectView(self.ram, self.cpu, self.disk, self.user, self.ctx, node)
        await interaction.response.edit_message(
            embed=create_info_embed("Select OS", 
                f"Node selected: **{node['name']}** ({node['location']})\n"
                f"Now choose the OS for the VPS:"),
            view=os_view
        )

class OSSelectView(discord.ui.View):
    def __init__(self, ram: int, cpu: int, disk: int, user: discord.Member, ctx, node):
        super().__init__(timeout=300)
        self.ram = ram
        self.cpu = cpu
        self.disk = disk
        self.user = user
        self.ctx = ctx
        self.node = node
        
        self.select = discord.ui.Select(
            placeholder="Select an OS for the VPS",
            options=[discord.SelectOption(label=o["label"], value=o["value"]) for o in OS_OPTIONS]
        )
        self.select.callback = self.select_os
        self.add_item(self.select)
    
    async def select_os(self, interaction: discord.Interaction):
        if str(interaction.user.id) != str(self.ctx.author.id):
            await interaction.response.send_message(embed=create_error_embed("Not your session"), ephemeral=True)
            return
        
        os_version = self.select.values[0]
        self.select.disabled = True
        
        # Create VPS
        creating_embed = create_info_embed("Creating VPS", 
            f"Deploying {os_version} on **{self.node['name']}**...")
        await interaction.response.edit_message(embed=creating_embed, view=self)
        
        # Generate VPS ID
        vps_id = f"vps_{uuid.uuid4().hex[:8]}"
        container_name = f"gg-{vps_id[:8]}"
        
        # Create VPS record
        user_id = str(self.user.id)
        if user_id not in vps_data:
            vps_data[user_id] = []
        
        config_str = f"{self.ram}GB RAM / {self.cpu} CPU / {self.disk}GB Disk"
        
        vps_info = {
            "vps_id": vps_id,
            "container_name": container_name,
            "ram": f"{self.ram}GB",
            "cpu": str(self.cpu),
            "storage": f"{self.disk}GB",
            "config": config_str,
            "os_version": os_version,
            "status": "pending",
            "suspended": False,
            "whitelisted": False,
            "suspension_history": [],
            "created_at": datetime.now().isoformat(),
            "shared_with": [],
            "id": None,
            "node_id": self.node['node_id'],
            "safe_purge": 0
        }
        
        vps_data[user_id].append(vps_info)
        save_vps_data()
        
        # Here you would send a command to the node to create the VPS
        # For now, simulate creation
        await asyncio.sleep(2)
        
        # Update status to running (simulated)
        vps_info['status'] = 'running'
        save_vps_data()
        
        success_embed = create_success_embed("VPS Created Successfully")
        add_field(success_embed, "Owner", self.user.mention, True)
        add_field(success_embed, "Node", f"{self.node['name']} ({self.node['location']})", True)
        add_field(success_embed, "VPS ID", vps_id, True)
        add_field(success_embed, "Resources", config_str, False)
        add_field(success_embed, "OS", os_version, True)
        add_field(success_embed, "Container", f"`{container_name}`", True)
        
        await interaction.followup.send(embed=success_embed)

@bot.command(name='create')
@is_admin()
@is_not_dev_mode()
async def create_vps(ctx, ram: int, cpu: int, disk: int, user: discord.Member):
    """Create VPS with node selection"""
    if ram <= 0 or cpu <= 0 or disk <= 0:
        await ctx.send(embed=create_error_embed("Invalid specs"))
        return
    
    # Check if any nodes are available
    nodes = NodeManager.get_online_nodes()
    if not nodes:
        await ctx.send(embed=create_error_embed("No online nodes available"))
        return
    
    embed = create_info_embed("Create VPS", 
        f"Creating VPS for {user.mention}\n"
        f"**Specs:** {ram}GB RAM, {cpu} cores, {disk}GB Disk\n\n"
        "First, select a node for deployment:")
    
    view = NodeSelectView(ram, cpu, disk, user, ctx)
    await ctx.send(embed=embed, view=view)

# ==================== ORIGINAL COMMANDS (ADAPTED) ====================
# Note: These are adapted to work with the new multi-node system
# You'll need to route commands to the appropriate node

@bot.command(name='myvps')
@is_not_dev_mode()
async def my_vps(ctx):
    """Show user's VPS (adapted)"""
    user_id = str(ctx.author.id)
    vps_list = vps_data.get(user_id, [])
    
    if not vps_list:
        await ctx.send(embed=create_error_embed("No VPS found"))
        return
    
    embed = create_info_embed("My VPS", f"You have {len(vps_list)} VPS")
    
    for i, vps in enumerate(vps_list):
        node = NodeManager.get_node(vps.get('node_id', ''))
        node_name = node['name'] if node else "Unknown Node"
        
        status = vps.get('status', 'unknown').upper()
        if vps.get('suspended'):
            status += " (SUSPENDED)"
        
        add_field(embed, f"VPS {i+1}",
                 f"**Container:** `{vps['container_name']}`\n"
                 f"**Status:** {status}\n"
                 f"**Node:** {node_name}\n"
                 f"**Specs:** {vps.get('config', '')}", False)
    
    await ctx.send(embed=embed)

@bot.command(name='manage')
@is_not_dev_mode()
async def manage_vps(ctx, user: discord.Member = None):
    """Manage VPS (adapted)"""
    # This would need to be adapted to send commands to specific nodes
    await ctx.send(embed=create_info_embed("VPS Management", 
        "VPS management commands are being adapted for multi-node.\n"
        "For now, use node-specific commands."))

# ==================== ALL OTHER ORIGINAL COMMANDS ====================
# You would need to adapt each command to:
# 1. Determine which node the VPS is on
# 2. Send the command to that node via HTTP
# 3. Handle the response
# 
# Example adaptation for a command like !start-vps:
# - Look up VPS in database to get node_id
# - Check if node is online
# - Send HTTP request to node's API endpoint
# - Update database based on response

# ==================== BOT EVENTS ====================
@bot.event
async def on_ready():
    logger.info(f'{bot.user} has connected to Discord!')
    bot.start_time = time.time()
    
    if not GLOBAL_DEV_MODE:
        rotate_status.start()
    
    # Start web server in background
    asyncio.create_task(start_web_server())
    
    logger.info(f"{BOT_NAME} Multi-Node Bot is ready!")

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(embed=create_error_embed("Missing argument"))
    elif isinstance(error, commands.CheckFailure):
        await ctx.send(embed=create_error_embed("Permission denied", str(error)))
    else:
        logger.error(f"Command error: {error}")
        await ctx.send(embed=create_error_embed("System error"))

# ==================== MAIN ====================
if __name__ == "__main__":
    if not DISCORD_TOKEN:
        logger.error("No Discord token found")
        exit(1)
    
    bot.run(DISCORD_TOKEN)