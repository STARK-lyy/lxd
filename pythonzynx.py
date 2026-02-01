#!/usr/bin/env python3
"""
ZynexForge Advanced Cloud Management Bot
Unified Version v3.0-PRO
Combined Node Agent and Discord Bot with Advanced Features
Upgraded by Zorvix AI
"""

import discord
from discord.ext import commands, tasks
import asyncio
import subprocess
import json
from datetime import datetime, timedelta
import shlex
import logging
import shutil
import os
import sys
import re
import random
import threading
import time
import sqlite3
import requests
import argparse
import signal
from typing import Dict, Any, Optional, List, Tuple, Union
from flask import Flask, request, jsonify, abort
import uuid
import psutil
import hashlib
import secrets

# ========== CONFIGURATION ==========
# Load from environment variables with defaults
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN', '')
BOT_NAME = os.getenv('BOT_NAME', 'ZynexForge')
PREFIX = os.getenv('PREFIX', '!')
YOUR_SERVER_IP = os.getenv('YOUR_SERVER_IP', '127.0.0.1')
MAIN_ADMIN_ID = int(os.getenv('MAIN_ADMIN_ID', '1210291131301101618'))
VPS_USER_ROLE_ID = int(os.getenv('VPS_USER_ROLE_ID', '1210291131301101618'))
DEFAULT_STORAGE_POOL = os.getenv('DEFAULT_STORAGE_POOL', 'default')
BOT_VERSION = os.getenv('BOT_VERSION', 'V3.0-PRO')
BOT_DEVELOPER = os.getenv('BOT_DEVELOPER', 'FaaizXD')
API_KEY = os.getenv('API_KEY', secrets.token_urlsafe(32))
HOST = os.getenv('HOST', '0.0.0.0')
PORT = int(os.getenv('PORT', '5000'))
HEALTH_INTERVAL = int(os.getenv('HEALTH_INTERVAL', '60'))
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FILE = os.getenv('LOG_FILE', 'zynexforge.log')
MAX_CONTAINERS_PER_USER = int(os.getenv('MAX_CONTAINERS_PER_USER', '10'))
BACKUP_DIR = os.getenv('BACKUP_DIR', 'backups')
AUDIT_LOG_FILE = os.getenv('AUDIT_LOG_FILE', 'audit.log')

# ASCII Art Banner
BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║    ███████╗██╗   ██╗███╗   ██╗███████╗██╗  ██╗███████╗      ║
║    ╚══███╔╝╚██╗ ██╔╝████╗  ██║██╔════╝╚██╗██╔╝██╔════╝      ║
║      ███╔╝  ╚████╔╝ ██╔██╗ ██║█████╗   ╚███╔╝ █████╗        ║
║     ███╔╝    ╚██╔╝  ██║╚██╗██║██╔══╝   ██╔██╗ ██╔══╝        ║
║    ███████╗   ██║   ██║ ╚████║███████╗██╔╝ ██╗███████╗      ║
║    ╚══════╝   ╚═╝   ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝      ║
║                                                              ║
║                 Z Y N E X F O R G E   C L O U D              ║
║                 Advanced v3.0-PRO Multi-Node                 ║
╚══════════════════════════════════════════════════════════════╝
"""
print(BANNER)
print(f"🚀 {BOT_NAME} v{BOT_VERSION} - Enterprise Cloud Management Platform")
print(f"⚡ Upgraded by Zorvix AI - Maximum Performance & Reliability")
print("=" * 60)

# OS Options for VPS Creation and Reinstall
OS_OPTIONS = [
    {"label": "Ubuntu 20.04 LTS", "value": "ubuntu:20.04", "image": "ubuntu/focal"},
    {"label": "Ubuntu 22.04 LTS", "value": "ubuntu:22.04", "image": "ubuntu/jammy"},
    {"label": "Ubuntu 24.04 LTS", "value": "ubuntu:24.04", "image": "ubuntu/noble"},
    {"label": "Debian 11 (Bullseye)", "value": "debian:11", "image": "debian/bullseye"},
    {"label": "Debian 12 (Bookworm)", "value": "debian:12", "image": "debian/bookworm"},
    {"label": "Alpine Linux 3.18", "value": "alpine:3.18", "image": "alpine/3.18"},
    {"label": "CentOS Stream 9", "value": "centos:9", "image": "centos/9"},
    {"label": "Rocky Linux 9", "value": "rockylinux:9", "image": "rockylinux/9"},
]

# Template configurations
TEMPLATE_CONFIGS = {
    "ubuntu:20.04": "-t download -- -d ubuntu -r focal -a amd64",
    "ubuntu:22.04": "-t download -- -d ubuntu -r jammy -a amd64",
    "ubuntu:24.04": "-t download -- -d ubuntu -r noble -a amd64",
    "debian:11": "-t download -- -d debian -r bullseye -a amd64",
    "debian:12": "-t download -- -d debian -r bookworm -a amd64",
    "alpine:3.18": "-t download -- -d alpine -r 3.18 -a amd64",
    "centos:9": "-t download -- -d centos -r 9 -a amd64",
    "rockylinux:9": "-t download -- -d rockylinux -r 9 -a amd64",
}

# Resource packages (predefined configurations)
RESOURCE_PACKAGES = {
    "starter": {"ram": 1, "cpu": 1, "disk": 10, "price": 0},
    "basic": {"ram": 2, "cpu": 2, "disk": 25, "price": 0},
    "standard": {"ram": 4, "cpu": 4, "disk": 50, "price": 0},
    "advanced": {"ram": 8, "cpu": 6, "disk": 100, "price": 0},
    "premium": {"ram": 16, "cpu": 8, "disk": 200, "price": 0},
    "enterprise": {"ram": 32, "cpu": 16, "disk": 500, "price": 0},
}

# ========== LOGGING CONFIGURATION ==========
def setup_logging():
    """Configure comprehensive logging system"""
    os.makedirs('logs', exist_ok=True)
    
    # Main logger
    logger = logging.getLogger('ZynexForge')
    logger.setLevel(getattr(logging, LOG_LEVEL.upper()))
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_format)
    
    # File handler
    file_handler = logging.FileHandler(
        filename=f'logs/{LOG_FILE}',
        encoding='utf-8',
        mode='a'
    )
    file_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
    )
    file_handler.setFormatter(file_format)
    
    # Audit logger
    audit_logger = logging.getLogger('ZynexForge.Audit')
    audit_logger.setLevel(logging.INFO)
    audit_handler = logging.FileHandler(
        filename=f'logs/{AUDIT_LOG_FILE}',
        encoding='utf-8',
        mode='a'
    )
    audit_format = logging.Formatter(
        '%(asctime)s - USER:%(user_id)s - ACTION:%(action)s - DETAILS:%(details)s'
    )
    audit_handler.setFormatter(audit_format)
    audit_logger.addHandler(audit_handler)
    audit_logger.propagate = False
    
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    # Disable propagation to avoid duplicate logs
    logger.propagate = False
    
    return logger, audit_logger

logger, audit_logger = setup_logging()

def audit_log(user_id: str, action: str, details: str = ""):
    """Log user actions for auditing"""
    audit_logger.info('', extra={
        'user_id': user_id,
        'action': action,
        'details': details
    })

# ========== DATABASE SYSTEM ==========
def get_db_connection():
    """Get database connection with WAL mode enabled"""
    conn = sqlite3.connect('vps.db', timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """Initialize database with all required tables"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Admins table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS admins (
        user_id TEXT PRIMARY KEY,
        added_by TEXT,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        permissions TEXT DEFAULT 'all'
    )
    ''')
    
    # Nodes table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS nodes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        location TEXT,
        total_vps INTEGER DEFAULT 100,
        used_vps INTEGER DEFAULT 0,
        tags TEXT DEFAULT '[]',
        api_key TEXT,
        url TEXT,
        is_local INTEGER DEFAULT 0,
        enabled INTEGER DEFAULT 1,
        priority INTEGER DEFAULT 1,
        max_ram INTEGER DEFAULT 16384,  # 16GB in MB
        max_cpu INTEGER DEFAULT 16,
        max_disk INTEGER DEFAULT 500,   # 500GB
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP
    )
    ''')
    
    # VPS containers table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS vps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        node_id INTEGER NOT NULL DEFAULT 1,
        container_name TEXT UNIQUE NOT NULL,
        ram TEXT NOT NULL,
        cpu TEXT NOT NULL,
        storage TEXT NOT NULL,
        config TEXT NOT NULL,
        os_version TEXT DEFAULT 'ubuntu:22.04',
        ip_address TEXT,
        status TEXT DEFAULT 'stopped',
        suspended INTEGER DEFAULT 0,
        whitelisted INTEGER DEFAULT 0,
        created_at TIMESTAMP NOT NULL,
        expires_at TIMESTAMP,
        shared_with TEXT DEFAULT '[]',
        suspension_history TEXT DEFAULT '[]',
        backup_schedule TEXT DEFAULT 'none',
        last_backup TIMESTAMP,
        notes TEXT DEFAULT '',
        FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE SET DEFAULT
    )
    ''')
    
    # Settings table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        description TEXT
    )
    ''')
    
    # Port allocations table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS port_allocations (
        user_id TEXT PRIMARY KEY,
        allocated_ports INTEGER DEFAULT 5,
        max_ports INTEGER DEFAULT 20,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Port forwards table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS port_forwards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        vps_container TEXT NOT NULL,
        vps_port INTEGER NOT NULL,
        host_port INTEGER NOT NULL,
        protocol TEXT DEFAULT 'tcp',
        enabled INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (vps_container) REFERENCES vps (container_name) ON DELETE CASCADE
    )
    ''')
    
    # Backups table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS backups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        container_name TEXT NOT NULL,
        backup_name TEXT NOT NULL,
        size_mb REAL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        location TEXT,
        status TEXT DEFAULT 'completed',
        notes TEXT,
        FOREIGN KEY (container_name) REFERENCES vps (container_name) ON DELETE CASCADE
    )
    ''')
    
    # User quotas table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_quotas (
        user_id TEXT PRIMARY KEY,
        max_containers INTEGER DEFAULT 5,
        total_ram INTEGER DEFAULT 4096,  # 4GB in MB
        total_cpu INTEGER DEFAULT 4,
        total_disk INTEGER DEFAULT 100,  # 100GB
        used_ram INTEGER DEFAULT 0,
        used_cpu INTEGER DEFAULT 0,
        used_disk INTEGER DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Activity log table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        action TEXT NOT NULL,
        target TEXT,
        details TEXT,
        ip_address TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Insert default settings
    default_settings = [
        ('cpu_threshold', '90', 'CPU usage threshold for auto-suspension'),
        ('ram_threshold', '90', 'RAM usage threshold for auto-suspension'),
        ('disk_threshold', '90', 'Disk usage threshold for alerts'),
        ('auto_backup', '1', 'Enable automatic backups'),
        ('backup_retention_days', '7', 'Number of days to keep backups'),
        ('monitor_interval', '60', 'Resource monitoring interval in seconds'),
        ('max_suspension_days', '30', 'Maximum days before permanent deletion'),
        ('enable_auto_suspend', '1', 'Enable automatic suspension'),
        ('enable_audit_log', '1', 'Enable audit logging'),
        ('enable_rate_limiting', '1', 'Enable rate limiting'),
        ('api_rate_limit', '60', 'API requests per minute'),
        ('discord_rate_limit', '10', 'Discord commands per minute'),
        ('maintenance_mode', '0', 'Enable maintenance mode'),
        ('registration_enabled', '1', 'Allow new container registrations'),
        ('default_package', 'basic', 'Default resource package'),
    ]
    
    for key, value, desc in default_settings:
        cursor.execute('''
        INSERT OR IGNORE INTO settings (key, value, description)
        VALUES (?, ?, ?)
        ''', (key, value, desc))
    
    # Insert main admin if not exists
    cursor.execute('INSERT OR IGNORE INTO admins (user_id, added_by, permissions) VALUES (?, ?, ?)',
                  (str(MAIN_ADMIN_ID), 'system', 'all'))
    
    # Insert local node if not exists
    cursor.execute('SELECT COUNT(*) FROM nodes WHERE is_local = 1')
    if cursor.fetchone()[0] == 0:
        cursor.execute('''
        INSERT INTO nodes (name, location, total_vps, tags, api_key, url, is_local)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', ('Local Node', 'Local', 100, '[]', None, None, 1))
    
    conn.commit()
    conn.close()
    logger.info("Database initialized successfully")

def get_setting(key: str, default: Any = None):
    """Get a setting from database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else default

def set_setting(key: str, value: str):
    """Update a setting in database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    INSERT OR REPLACE INTO settings (key, value, updated_at)
    VALUES (?, ?, CURRENT_TIMESTAMP)
    ''', (key, value))
    conn.commit()
    conn.close()

# ========== NODE MANAGEMENT ==========
def get_nodes(enabled_only: bool = True) -> List[Dict]:
    """Get all nodes from database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if enabled_only:
        cursor.execute('SELECT * FROM nodes WHERE enabled = 1 ORDER BY priority, id')
    else:
        cursor.execute('SELECT * FROM nodes ORDER BY priority, id')
    
    rows = cursor.fetchall()
    conn.close()
    
    nodes = []
    for row in rows:
        node = dict(row)
        node['tags'] = json.loads(node.get('tags', '[]'))
        nodes.append(node)
    
    return nodes

def get_node(node_id: int) -> Optional[Dict]:
    """Get a specific node by ID"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM nodes WHERE id = ?', (node_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        node = dict(row)
        node['tags'] = json.loads(node.get('tags', '[]'))
        return node
    return None

def get_node_by_name(name: str) -> Optional[Dict]:
    """Get a node by name"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM nodes WHERE name = ?', (name,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        node = dict(row)
        node['tags'] = json.loads(node.get('tags', '[]'))
        return node
    return None

def update_node_usage(node_id: int):
    """Update node usage statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Count containers on this node
    cursor.execute('SELECT COUNT(*) FROM vps WHERE node_id = ? AND suspended = 0', (node_id,))
    used_vps = cursor.fetchone()[0]
    
    cursor.execute('UPDATE nodes SET used_vps = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?',
                  (used_vps, node_id))
    conn.commit()
    conn.close()

def find_best_node() -> Optional[int]:
    """Find the best node for new container deployment"""
    nodes = get_nodes()
    if not nodes:
        return None
    
    # Find node with lowest usage percentage
    best_node = None
    best_score = float('inf')
    
    for node in nodes:
        usage_percent = (node['used_vps'] / node['total_vps']) * 100
        score = usage_percent - node['priority'] * 10
        
        if score < best_score:
            best_score = score
            best_node = node['id']
    
    return best_node

# ========== VPS MANAGEMENT ==========
def get_vps_by_user(user_id: str) -> List[Dict]:
    """Get all VPS containers for a user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    SELECT vps.*, nodes.name as node_name, nodes.location as node_location
    FROM vps
    LEFT JOIN nodes ON vps.node_id = nodes.id
    WHERE vps.user_id = ?
    ORDER BY vps.created_at DESC
    ''', (user_id,))
    
    rows = cursor.fetchall()
    conn.close()
    
    containers = []
    for row in rows:
        container = dict(row)
        container['shared_with'] = json.loads(container.get('shared_with', '[]'))
        container['suspension_history'] = json.loads(container.get('suspension_history', '[]'))
        containers.append(container)
    
    return containers

def get_vps_by_container(container_name: str) -> Optional[Dict]:
    """Get VPS container by name"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    SELECT vps.*, nodes.name as node_name, nodes.location as node_location
    FROM vps
    LEFT JOIN nodes ON vps.node_id = nodes.id
    WHERE vps.container_name = ?
    ''', (container_name,))
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        container = dict(row)
        container['shared_with'] = json.loads(container.get('shared_with', '[]'))
        container['suspension_history'] = json.loads(container.get('suspension_history', '[]'))
        return container
    return None

def get_all_vps() -> List[Dict]:
    """Get all VPS containers"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    SELECT vps.*, nodes.name as node_name, nodes.location as node_location
    FROM vps
    LEFT JOIN nodes ON vps.node_id = nodes.id
    ORDER BY vps.created_at DESC
    ''')
    
    rows = cursor.fetchall()
    conn.close()
    
    containers = []
    for row in rows:
        container = dict(row)
        container['shared_with'] = json.loads(container.get('shared_with', '[]'))
        container['suspension_history'] = json.loads(container.get('suspension_history', '[]'))
        containers.append(container)
    
    return containers

def create_vps_record(data: Dict) -> bool:
    """Create a new VPS record in database"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO vps (
            user_id, node_id, container_name, ram, cpu, storage,
            config, os_version, status, created_at, shared_with, suspension_history
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['user_id'], data['node_id'], data['container_name'],
            data['ram'], data['cpu'], data['storage'], data['config'],
            data['os_version'], data['status'], data['created_at'],
            json.dumps(data.get('shared_with', [])),
            json.dumps(data.get('suspension_history', []))
        ))
        
        # Update node usage
        update_node_usage(data['node_id'])
        
        # Update user quota
        update_user_quota(data['user_id'])
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Failed to create VPS record: {e}")
        return False

def update_vps_record(container_name: str, updates: Dict) -> bool:
    """Update VPS container record"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Build update query
        set_clause = []
        values = []
        
        for key, value in updates.items():
            if key in ['shared_with', 'suspension_history']:
                value = json.dumps(value)
            set_clause.append(f"{key} = ?")
            values.append(value)
        
        values.append(container_name)
        
        query = f"UPDATE vps SET {', '.join(set_clause)} WHERE container_name = ?"
        cursor.execute(query, values)
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Failed to update VPS record: {e}")
        return False

def delete_vps_record(container_name: str) -> bool:
    """Delete VPS container record"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get container info before deletion
        cursor.execute('SELECT user_id, node_id FROM vps WHERE container_name = ?', (container_name,))
        container = cursor.fetchone()
        
        if container:
            user_id = container['user_id']
            node_id = container['node_id']
            
            # Delete the container
            cursor.execute('DELETE FROM vps WHERE container_name = ?', (container_name,))
            
            # Delete associated port forwards
            cursor.execute('DELETE FROM port_forwards WHERE vps_container = ?', (container_name,))
            
            # Delete associated backups
            cursor.execute('DELETE FROM backups WHERE container_name = ?', (container_name,))
            
            # Update node usage
            update_node_usage(node_id)
            
            # Update user quota
            update_user_quota(user_id)
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Failed to delete VPS record: {e}")
        return False

# ========== USER QUOTA MANAGEMENT ==========
def get_user_quota(user_id: str) -> Dict:
    """Get user quota information"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get or create user quota
    cursor.execute('SELECT * FROM user_quotas WHERE user_id = ?', (user_id,))
    quota = cursor.fetchone()
    
    if not quota:
        # Create default quota
        cursor.execute('''
        INSERT INTO user_quotas (user_id, max_containers, total_ram, total_cpu, total_disk)
        VALUES (?, ?, ?, ?, ?)
        ''', (user_id, 5, 4096, 4, 100))
        
        cursor.execute('SELECT * FROM user_quotas WHERE user_id = ?', (user_id,))
        quota = cursor.fetchone()
    
    conn.close()
    return dict(quota) if quota else {}

def update_user_quota(user_id: str):
    """Update user quota usage statistics"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get all containers for user
        cursor.execute('''
        SELECT ram, cpu, storage FROM vps 
        WHERE user_id = ? AND suspended = 0
        ''', (user_id,))
        
        containers = cursor.fetchall()
        
        # Calculate total usage
        total_ram = 0
        total_cpu = 0
        total_disk = 0
        
        for container in containers:
            try:
                # Extract numeric values from strings like "2GB", "4 Cores", "50GB"
                ram_str = container['ram']
                cpu_str = container['cpu']
                disk_str = container['storage']
                
                # Parse RAM (e.g., "2GB" -> 2048 MB)
                if 'GB' in ram_str:
                    total_ram += int(float(ram_str.replace('GB', '').strip()) * 1024)
                elif 'MB' in ram_str:
                    total_ram += int(ram_str.replace('MB', '').strip())
                
                # Parse CPU (e.g., "4 Cores" -> 4)
                total_cpu += int(float(cpu_str.replace('Cores', '').replace('Core', '').strip()))
                
                # Parse Disk (e.g., "50GB" -> 50)
                if 'GB' in disk_str:
                    total_disk += int(float(disk_str.replace('GB', '').strip()))
                elif 'TB' in disk_str:
                    total_disk += int(float(disk_str.replace('TB', '').strip()) * 1024)
                    
            except (ValueError, AttributeError) as e:
                logger.warning(f"Error parsing container resources: {e}")
                continue
        
        # Update quota
        cursor.execute('''
        UPDATE user_quotas 
        SET used_ram = ?, used_cpu = ?, used_disk = ?, updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ?
        ''', (total_ram, total_cpu, total_disk, user_id))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        logger.error(f"Failed to update user quota: {e}")

def check_user_quota(user_id: str, ram_gb: int, cpu: int, disk_gb: int) -> Tuple[bool, str]:
    """Check if user has enough quota for new container"""
    quota = get_user_quota(user_id)
    
    # Convert GB to MB for RAM
    ram_mb = ram_gb * 1024
    disk_gb_total = disk_gb
    
    # Check container count
    containers = get_vps_by_user(user_id)
    container_count = len([c for c in containers if not c.get('suspended')])
    
    if container_count >= quota['max_containers']:
        return False, f"Maximum containers ({quota['max_containers']}) reached"
    
    # Check RAM
    if quota['used_ram'] + ram_mb > quota['total_ram']:
        available = (quota['total_ram'] - quota['used_ram']) / 1024
        return False, f"Insufficient RAM quota. Available: {available:.1f}GB, Requested: {ram_gb}GB"
    
    # Check CPU
    if quota['used_cpu'] + cpu > quota['total_cpu']:
        available = quota['total_cpu'] - quota['used_cpu']
        return False, f"Insufficient CPU quota. Available: {available} cores, Requested: {cpu} cores"
    
    # Check Disk
    if quota['used_disk'] + disk_gb_total > quota['total_disk']:
        available = quota['total_disk'] - quota['used_disk']
        return False, f"Insufficient Disk quota. Available: {available}GB, Requested: {disk_gb_total}GB"
    
    return True, "Quota check passed"

# ========== PORT FORWARDING ==========
def allocate_ports_for_user(user_id: str, amount: int = 5):
    """Allocate port slots to user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
    INSERT OR REPLACE INTO port_allocations 
    (user_id, allocated_ports, updated_at) 
    VALUES (?, COALESCE((SELECT allocated_ports FROM port_allocations WHERE user_id = ?), 0) + ?, CURRENT_TIMESTAMP)
    ''', (user_id, user_id, amount))
    
    conn.commit()
    conn.close()

def get_user_port_quota(user_id: str) -> Dict:
    """Get user port quota information"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM port_allocations WHERE user_id = ?', (user_id,))
    quota = cursor.fetchone()
    
    if not quota:
        # Create default quota
        cursor.execute('''
        INSERT INTO port_allocations (user_id, allocated_ports, max_ports)
        VALUES (?, ?, ?)
        ''', (user_id, 5, 20))
        
        cursor.execute('SELECT * FROM port_allocations WHERE user_id = ?', (user_id,))
        quota = cursor.fetchone()
    
    # Count used ports
    cursor.execute('SELECT COUNT(*) FROM port_forwards WHERE user_id = ? AND enabled = 1', (user_id,))
    used_ports = cursor.fetchone()[0]
    
    conn.close()
    
    if quota:
        quota_dict = dict(quota)
        quota_dict['used_ports'] = used_ports
        quota_dict['available_ports'] = quota_dict['allocated_ports'] - used_ports
        return quota_dict
    
    return {'allocated_ports': 5, 'max_ports': 20, 'used_ports': 0, 'available_ports': 5}

def create_port_forward_record(user_id: str, container: str, vps_port: int, host_port: int, protocol: str = 'tcp') -> int:
    """Create port forward record"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
    INSERT INTO port_forwards (user_id, vps_container, vps_port, host_port, protocol)
    VALUES (?, ?, ?, ?, ?)
    ''', (user_id, container, vps_port, host_port, protocol))
    
    forward_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return forward_id

def get_port_forwards_by_user(user_id: str) -> List[Dict]:
    """Get all port forwards for a user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT * FROM port_forwards 
    WHERE user_id = ? 
    ORDER BY created_at DESC
    ''', (user_id,))
    
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

def get_port_forward_by_id(forward_id: int) -> Optional[Dict]:
    """Get port forward by ID"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM port_forwards WHERE id = ?', (forward_id,))
    row = cursor.fetchone()
    conn.close()
    
    return dict(row) if row else None

def delete_port_forward(forward_id: int) -> bool:
    """Delete port forward"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM port_forwards WHERE id = ?', (forward_id,))
    
    conn.commit()
    conn.close()
    return cursor.rowcount > 0

# ========== ADMIN MANAGEMENT ==========
def get_admins() -> List[str]:
    """Get list of admin user IDs"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM admins')
    rows = cursor.fetchall()
    conn.close()
    
    return [row['user_id'] for row in rows]

def is_admin(user_id: str) -> bool:
    """Check if user is admin"""
    return user_id == str(MAIN_ADMIN_ID) or user_id in get_admins()

def is_main_admin(user_id: str) -> bool:
    """Check if user is main admin"""
    return user_id == str(MAIN_ADMIN_ID)

def add_admin(user_id: str, added_by: str) -> bool:
    """Add user as admin"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT OR REPLACE INTO admins (user_id, added_by, added_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ''', (user_id, added_by))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Failed to add admin: {e}")
        return False

def remove_admin(user_id: str) -> bool:
    """Remove user from admins"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM admins WHERE user_id = ?', (user_id,))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Failed to remove admin: {e}")
        return False

# ========== LXC COMMAND EXECUTION ==========
async def execute_lxc(container_name: str, command: str, timeout: int = 120, node_id: Optional[int] = None) -> str:
    """
    Execute LXC command on appropriate node
    Supports both local and remote nodes
    """
    try:
        if node_id is None:
            # Find node for container
            container = get_vps_by_container(container_name)
            if container:
                node_id = container['node_id']
            else:
                node_id = 1  # Default to local node
        
        node = get_node(node_id)
        if not node:
            raise Exception(f"Node {node_id} not found")
        
        full_command = f"lxc {command}"
        
        if node['is_local']:
            # Local execution
            return await execute_lxc_local(full_command, timeout)
        else:
            # Remote execution via API
            return await execute_lxc_remote(node, full_command, timeout)
            
    except Exception as e:
        logger.error(f"LXC execution error: {e}")
        raise

async def execute_lxc_local(command: str, timeout: int = 120) -> str:
    """Execute LXC command locally"""
    try:
        # Parse command
        cmd_parts = shlex.split(command)
        
        # Create subprocess with timeout
        process = await asyncio.create_subprocess_exec(
            *cmd_parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise TimeoutError(f"Command timed out after {timeout} seconds")
        
        if process.returncode != 0:
            error = stderr.decode().strip() if stderr else "Unknown error"
            raise Exception(f"Command failed with code {process.returncode}: {error}")
        
        return stdout.decode().strip() if stdout else ""
        
    except Exception as e:
        logger.error(f"Local LXC execution error: {e}")
        raise

async def execute_lxc_remote(node: Dict, command: str, timeout: int = 120) -> str:
    """Execute LXC command on remote node via API"""
    try:
        url = f"{node['url']}/api/execute"
        data = {
            "command": command,
            "timeout": timeout
        }
        params = {"api_key": node['api_key']}
        
        async with asyncio.timeout(timeout + 10):
            response = await asyncio.to_thread(
                requests.post, url, json=data, params=params, timeout=timeout
            )
        
        if response.status_code != 200:
            raise Exception(f"API request failed: {response.status_code} - {response.text}")
        
        result = response.json()
        if result.get("returncode", 1) != 0:
            raise Exception(f"Remote command failed: {result.get('stderr', 'Unknown error')}")
        
        return result.get("stdout", "")
        
    except Exception as e:
        logger.error(f"Remote LXC execution error on node {node['name']}: {e}")
        raise

# ========== CONTAINER MANAGEMENT FUNCTIONS ==========
async def create_container(container_name: str, os_version: str, ram_gb: int, cpu: int, disk_gb: int, node_id: int) -> bool:
    """Create a new LXC container"""
    try:
        # Get template configuration
        template = TEMPLATE_CONFIGS.get(os_version, TEMPLATE_CONFIGS["ubuntu:22.04"])
        
        # Create container
        create_cmd = f"init {container_name} {template} -s {DEFAULT_STORAGE_POOL}"
        await execute_lxc(container_name, create_cmd, timeout=600, node_id=node_id)
        
        # Set resource limits
        ram_mb = ram_gb * 1024
        await execute_lxc(container_name, f"config set {container_name} limits.memory {ram_mb}MB", node_id=node_id)
        await execute_lxc(container_name, f"config set {container_name} limits.cpu {cpu}", node_id=node_id)
        await execute_lxc(container_name, f"config device set {container_name} root size={disk_gb}GB", node_id=node_id)
        
        # Apply security and performance configurations
        await apply_container_config(container_name, node_id)
        
        # Start container
        await execute_lxc(container_name, f"start {container_name}", node_id=node_id)
        
        # Apply internal configurations
        await apply_internal_config(container_name, node_id)
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to create container {container_name}: {e}")
        
        # Clean up if creation failed
        try:
            await execute_lxc(container_name, f"delete {container_name} --force", node_id=node_id)
        except:
            pass
            
        raise

async def apply_container_config(container_name: str, node_id: int):
    """Apply security and performance configurations to container"""
    try:
        # Security settings
        await execute_lxc(container_name, f"config set {container_name} security.nesting true", node_id=node_id)
        await execute_lxc(container_name, f"config set {container_name} security.privileged true", node_id=node_id)
        await execute_lxc(container_name, f"config set {container_name} security.syscalls.intercept.mknod true", node_id=node_id)
        await execute_lxc(container_name, f"config set {container_name} security.syscalls.intercept.setxattr true", node_id=node_id)
        
        # Kernel modules for Docker and virtualization
        await execute_lxc(container_name, 
                         f"config set {container_name} linux.kernel_modules overlay,loop,nf_nat,ip_tables,ip6_tables,netlink_diag,br_netfilter,nft_compat",
                         node_id=node_id)
        
        # FUSE device for Docker
        try:
            await execute_lxc(container_name, f"config device add {container_name} fuse unix-char path=/dev/fuse", node_id=node_id)
        except:
            pass  # FUSE might already exist
        
        # Raw LXC configuration
        raw_lxc = """
lxc.apparmor.profile = unconfined
lxc.apparmor.allow_nesting = 1
lxc.apparmor.allow_incomplete = 1
lxc.cap.drop = 
lxc.cgroup.devices.allow = a
lxc.cgroup2.devices.allow = a
lxc.mount.auto = proc:rw sys:rw cgroup:rw shmounts:rw
lxc.mount.entry = /dev/fuse dev/fuse none bind,create=file 0 0
"""
        await execute_lxc(container_name, f"config set {container_name} raw.lxc \"{raw_lxc}\"", node_id=node_id)
        
        # Network configuration
        await execute_lxc(container_name, f"config device set {container_name} eth0 ipv4.address auto", node_id=node_id)
        await execute_lxc(container_name, f"config device set {container_name} eth0 ipv6.address auto", node_id=node_id)
        
        logger.info(f"Applied configurations to container {container_name}")
        
    except Exception as e:
        logger.error(f"Failed to apply configurations to {container_name}: {e}")
        raise

async def apply_internal_config(container_name: str, node_id: int):
    """Apply internal container configurations"""
    try:
        # Wait for container to be ready
        await asyncio.sleep(5)
        
        # System configurations
        commands = [
            # System tuning
            "mkdir -p /etc/sysctl.d/",
            "echo 'net.ipv4.ip_unprivileged_port_start=0' > /etc/sysctl.d/99-zynexforge.conf",
            "echo 'net.ipv4.ping_group_range=0 2147483647' >> /etc/sysctl.d/99-zynexforge.conf",
            "echo 'fs.inotify.max_user_watches=524288' >> /etc/sysctl.d/99-zynexforge.conf",
            "echo 'kernel.unprivileged_userns_clone=1' >> /etc/sysctl.d/99-zynexforge.conf",
            "echo 'vm.swappiness=10' >> /etc/sysctl.d/99-zynexforge.conf",
            "echo 'vm.vfs_cache_pressure=50' >> /etc/sysctl.d/99-zynexforge.conf",
            
            # Apply sysctl
            "sysctl -p /etc/sysctl.d/99-zynexforge.conf 2>/dev/null || true",
            
            # Update and install basic tools
            "apt-get update && apt-get install -y curl wget net-tools htop nano 2>/dev/null || true",
            "yum update -y && yum install -y curl wget net-tools htop nano 2>/dev/null || true",
            "apk update && apk add curl wget net-tools htop nano 2>/dev/null || true",
            
            # Create swap file if needed (1GB)
            "fallocate -l 1G /swapfile 2>/dev/null || true",
            "chmod 600 /swapfile 2>/dev/null || true",
            "mkswap /swapfile 2>/dev/null || true",
            "swapon /swapfile 2>/dev/null || true",
            "echo '/swapfile none swap sw 0 0' >> /etc/fstab 2>/dev/null || true",
            
            # Create admin user
            "useradd -m -s /bin/bash admin 2>/dev/null || true",
            "echo 'admin:admin123' | chpasswd 2>/dev/null || true",
            "usermod -aG sudo admin 2>/dev/null || true",
            "usermod -aG wheel admin 2>/dev/null || true",
            
            # SSH configuration
            "mkdir -p /home/admin/.ssh 2>/dev/null || true",
            "chown -R admin:admin /home/admin/.ssh 2>/dev/null || true",
            "chmod 700 /home/admin/.ssh 2>/dev/null || true",
        ]
        
        for cmd in commands:
            try:
                await execute_lxc(container_name, f"exec {container_name} -- bash -c \"{cmd}\"", node_id=node_id, timeout=30)
            except Exception as cmd_error:
                logger.warning(f"Command failed in {container_name}: {cmd} - {cmd_error}")
        
        logger.info(f"Applied internal configurations to {container_name}")
        
    except Exception as e:
        logger.error(f"Failed to apply internal configurations to {container_name}: {e}")

async def get_container_status(container_name: str, node_id: Optional[int] = None) -> str:
    """Get container status"""
    try:
        if node_id is None:
            container = get_vps_by_container(container_name)
            if container:
                node_id = container['node_id']
            else:
                return "unknown"
        
        output = await execute_lxc(container_name, f"info {container_name}", node_id=node_id, timeout=10)
        
        for line in output.split('\n'):
            if line.startswith("Status:"):
                return line.split(":", 1)[1].strip().lower()
        
        return "unknown"
        
    except Exception as e:
        logger.error(f"Failed to get status for {container_name}: {e}")
        return "unknown"

async def get_container_stats(container_name: str, node_id: Optional[int] = None) -> Dict:
    """Get comprehensive container statistics"""
    stats = {
        "status": "unknown",
        "cpu": 0.0,
        "ram": {"used": 0, "total": 0, "percent": 0.0},
        "disk": {"used": 0, "total": 0, "percent": 0.0},
        "network": {"rx": 0, "tx": 0},
        "uptime": "unknown"
    }
    
    try:
        if node_id is None:
            container = get_vps_by_container(container_name)
            if container:
                node_id = container['node_id']
            else:
                return stats
        
        # Get basic info
        info_output = await execute_lxc(container_name, f"info {container_name}", node_id=node_id, timeout=10)
        
        # Parse status
        for line in info_output.split('\n'):
            if line.startswith("Status:"):
                stats["status"] = line.split(":", 1)[1].strip().lower()
                break
        
        if stats["status"] != "running":
            return stats
        
        # Get CPU usage
        try:
            top_output = await execute_lxc(container_name, f"exec {container_name} -- top -bn1", node_id=node_id, timeout=10)
            for line in top_output.split('\n'):
                if '%Cpu(s):' in line:
                    parts = line.split()
                    if len(parts) >= 8:
                        us = float(parts[1].rstrip(','))
                        sy = float(parts[3].rstrip(','))
                        stats["cpu"] = round(us + sy, 1)
                        break
        except:
            pass
        
        # Get RAM usage
        try:
            mem_output = await execute_lxc(container_name, f"exec {container_name} -- free -m", node_id=node_id, timeout=10)
            lines = mem_output.split('\n')
            if len(lines) > 1:
                parts = lines[1].split()
                if len(parts) >= 3:
                    total = int(parts[1])
                    used = int(parts[2])
                    stats["ram"] = {
                        "used": used,
                        "total": total,
                        "percent": round((used / total * 100), 1) if total > 0 else 0.0
                    }
        except:
            pass
        
        # Get disk usage
        try:
            disk_output = await execute_lxc(container_name, f"exec {container_name} -- df -m /", node_id=node_id, timeout=10)
            lines = disk_output.split('\n')
            if len(lines) > 1:
                parts = lines[1].split()
                if len(parts) >= 3:
                    total = int(parts[1])
                    used = int(parts[2])
                    stats["disk"] = {
                        "used": used,
                        "total": total,
                        "percent": round((used / total * 100), 1) if total > 0 else 0.0
                    }
        except:
            pass
        
        # Get uptime
        try:
            uptime_output = await execute_lxc(container_name, f"exec {container_name} -- uptime -p", node_id=node_id, timeout=10)
            stats["uptime"] = uptime_output.strip() if uptime_output else "unknown"
        except:
            stats["uptime"] = "unknown"
        
        # Get network stats
        try:
            network_output = await execute_lxc(container_name, f"exec {container_name} -- cat /proc/net/dev", node_id=node_id, timeout=10)
            for line in network_output.split('\n'):
                if 'eth0:' in line or 'ens3:' in line:
                    parts = line.split()
                    if len(parts) >= 10:
                        stats["network"]["rx"] = int(parts[1])
                        stats["network"]["tx"] = int(parts[9])
                        break
        except:
            pass
        
    except Exception as e:
        logger.error(f"Failed to get stats for {container_name}: {e}")
    
    return stats

async def start_container(container_name: str, node_id: Optional[int] = None) -> bool:
    """Start container"""
    try:
        await execute_lxc(container_name, f"start {container_name}", node_id=node_id, timeout=60)
        
        # Update database
        update_vps_record(container_name, {"status": "running", "suspended": 0})
        
        # Reapply configurations
        if node_id:
            await apply_internal_config(container_name, node_id)
        
        # Restore port forwards
        await restore_port_forwards(container_name)
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to start container {container_name}: {e}")
        return False

async def stop_container(container_name: str, node_id: Optional[int] = None, force: bool = False) -> bool:
    """Stop container"""
    try:
        command = f"stop {container_name}"
        if force:
            command += " --force"
        
        await execute_lxc(container_name, command, node_id=node_id, timeout=120)
        
        # Update database
        update_vps_record(container_name, {"status": "stopped"})
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to stop container {container_name}: {e}")
        return False

async def restart_container(container_name: str, node_id: Optional[int] = None) -> bool:
    """Restart container"""
    try:
        await execute_lxc(container_name, f"restart {container_name}", node_id=node_id, timeout=120)
        
        # Update database
        update_vps_record(container_name, {"status": "running", "suspended": 0})
        
        # Reapply configurations
        if node_id:
            await apply_internal_config(container_name, node_id)
        
        # Restore port forwards
        await restore_port_forwards(container_name)
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to restart container {container_name}: {e}")
        return False

async def delete_container(container_name: str, node_id: Optional[int] = None, force: bool = True) -> bool:
    """Delete container"""
    try:
        command = f"delete {container_name}"
        if force:
            command += " --force"
        
        await execute_lxc(container_name, command, node_id=node_id, timeout=180)
        
        # Delete from database
        delete_vps_record(container_name)
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to delete container {container_name}: {e}")
        return False

async def reinstall_container(container_name: str, os_version: str, node_id: Optional[int] = None) -> bool:
    """Reinstall container with new OS"""
    try:
        if node_id is None:
            container = get_vps_by_container(container_name)
            if container:
                node_id = container['node_id']
                ram_gb = int(container['ram'].replace('GB', ''))
                cpu = int(container['cpu'].replace(' Cores', ''))
                disk_gb = int(container['storage'].replace('GB', ''))
            else:
                return False
        
        # Stop container if running
        status = await get_container_status(container_name, node_id)
        if status == "running":
            await stop_container(container_name, node_id, force=True)
        
        # Delete container
        await delete_container(container_name, node_id, force=True)
        
        # Recreate container
        await create_container(container_name, os_version, ram_gb, cpu, disk_gb, node_id)
        
        # Update database
        update_vps_record(container_name, {
            "os_version": os_version,
            "status": "running",
            "suspended": 0
        })
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to reinstall container {container_name}: {e}")
        return False

# ========== PORT FORWARDING FUNCTIONS ==========
async def create_port_forward(container_name: str, vps_port: int, protocol: str = 'tcp', node_id: Optional[int] = None) -> Optional[int]:
    """Create port forward for container"""
    try:
        if node_id is None:
            container = get_vps_by_container(container_name)
            if container:
                node_id = container['node_id']
            else:
                return None
        
        # Find available host port
        host_port = await find_available_port(node_id)
        if not host_port:
            return None
        
        # Create proxy device
        device_name = f"proxy_{protocol}_{host_port}"
        if protocol == 'tcp':
            await execute_lxc(container_name, 
                            f"config device add {container_name} {device_name} proxy "
                            f"listen=tcp:0.0.0.0:{host_port} connect=tcp:127.0.0.1:{vps_port}",
                            node_id=node_id)
        elif protocol == 'udp':
            await execute_lxc(container_name,
                            f"config device add {container_name} {device_name} proxy "
                            f"listen=udp:0.0.0.0:{host_port} connect=udp:127.0.0.1:{vps_port}",
                            node_id=node_id)
        else:  # both
            await execute_lxc(container_name,
                            f"config device add {container_name} {device_name}_tcp proxy "
                            f"listen=tcp:0.0.0.0:{host_port} connect=tcp:127.0.0.1:{vps_port}",
                            node_id=node_id)
            await execute_lxc(container_name,
                            f"config device add {container_name} {device_name}_udp proxy "
                            f"listen=udp:0.0.0.0:{host_port} connect=udp:127.0.0.1:{vps_port}",
                            node_id=node_id)
        
        # Get user ID from container
        container = get_vps_by_container(container_name)
        if container:
            user_id = container['user_id']
            
            # Create record in database
            forward_id = create_port_forward_record(user_id, container_name, vps_port, host_port, protocol)
            
            logger.info(f"Created port forward {host_port}->{vps_port} ({protocol}) for {container_name}")
            return forward_id
        
        return None
        
    except Exception as e:
        logger.error(f"Failed to create port forward for {container_name}: {e}")
        return None

async def remove_port_forward(forward_id: int) -> bool:
    """Remove port forward"""
    try:
        forward = get_port_forward_by_id(forward_id)
        if not forward:
            return False
        
        container_name = forward['vps_container']
        host_port = forward['host_port']
        protocol = forward['protocol']
        
        # Get node ID
        container = get_vps_by_container(container_name)
        if not container:
            return False
        
        node_id = container['node_id']
        
        # Remove proxy device
        device_name = f"proxy_{protocol}_{host_port}"
        try:
            await execute_lxc(container_name, f"config device remove {container_name} {device_name}", node_id=node_id)
        except:
            pass  # Device might not exist
        
        # If protocol is 'both', also remove UDP device
        if protocol == 'both':
            try:
                await execute_lxc(container_name, f"config device remove {container_name} {device_name}_udp", node_id=node_id)
            except:
                pass
        
        # Delete from database
        delete_port_forward(forward_id)
        
        logger.info(f"Removed port forward {host_port} ({protocol}) for {container_name}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to remove port forward {forward_id}: {e}")
        return False

async def restore_port_forwards(container_name: str) -> int:
    """Restore all port forwards for a container after restart"""
    try:
        forwards = get_port_forwards_by_user(get_vps_by_container(container_name)['user_id'])
        restored = 0
        
        for forward in forwards:
            if forward['vps_container'] == container_name and forward['enabled'] == 1:
                try:
                    await create_port_forward(container_name, forward['vps_port'], forward['protocol'])
                    restored += 1
                except Exception as e:
                    logger.warning(f"Failed to restore port forward {forward['id']}: {e}")
        
        logger.info(f"Restored {restored} port forwards for {container_name}")
        return restored
        
    except Exception as e:
        logger.error(f"Failed to restore port forwards for {container_name}: {e}")
        return 0

async def find_available_port(node_id: int) -> Optional[int]:
    """Find available host port for forwarding"""
    # Get used ports from database
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT host_port FROM port_forwards 
    WHERE vps_container IN (SELECT container_name FROM vps WHERE node_id = ?)
    ''', (node_id,))
    
    used_ports = {row['host_port'] for row in cursor.fetchall()}
    conn.close()
    
    # Try random ports in range
    for _ in range(100):
        port = random.randint(20000, 50000)
        if port not in used_ports:
            # Check if port is actually available
            try:
                # Quick socket test
                import socket
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex(('127.0.0.1', port)) != 0:
                        return port
            except:
                pass
    
    return None

# ========== BACKUP SYSTEM ==========
async def create_backup(container_name: str, backup_name: str = None, node_id: Optional[int] = None) -> Optional[Dict]:
    """Create backup of container"""
    try:
        if node_id is None:
            container = get_vps_by_container(container_name)
            if container:
                node_id = container['node_id']
            else:
                return None
        
        if not backup_name:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_name = f"{container_name}_backup_{timestamp}"
        
        # Create snapshot
        await execute_lxc(container_name, f"snapshot {container_name} {backup_name}", node_id=node_id)
        
        # Publish snapshot as image
        image_name = f"{container_name}/{backup_name}"
        await execute_lxc(container_name, f"publish {container_name}/{backup_name} --alias {image_name}", node_id=node_id)
        
        # Export image to file
        backup_dir = BACKUP_DIR
        os.makedirs(backup_dir, exist_ok=True)
        backup_file = os.path.join(backup_dir, f"{image_name.replace('/', '_')}.tar.gz")
        
        await execute_lxc(container_name, f"image export {image_name} {backup_file}", node_id=node_id)
        
        # Get file size
        size_mb = os.path.getsize(backup_file) / (1024 * 1024) if os.path.exists(backup_file) else 0
        
        # Create backup record
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO backups (container_name, backup_name, size_mb, location, status)
        VALUES (?, ?, ?, ?, ?)
        ''', (container_name, backup_name, size_mb, backup_file, 'completed'))
        
        backup_id = cursor.lastrowid
        
        # Update container's last backup time
        update_vps_record(container_name, {"last_backup": datetime.now().isoformat()})
        
        conn.commit()
        conn.close()
        
        logger.info(f"Created backup {backup_name} for {container_name} ({size_mb:.1f} MB)")
        
        return {
            "id": backup_id,
            "name": backup_name,
            "size_mb": size_mb,
            "file": backup_file,
            "created_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to create backup for {container_name}: {e}")
        return None

async def restore_backup(container_name: str, backup_id: int, new_name: str = None, node_id: Optional[int] = None) -> bool:
    """Restore container from backup"""
    try:
        # Get backup info
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM backups WHERE id = ?', (backup_id,))
        backup = cursor.fetchone()
        conn.close()
        
        if not backup:
            return False
        
        backup_file = backup['location']
        if not os.path.exists(backup_file):
            return False
        
        if node_id is None:
            # Use original node or find best node
            container = get_vps_by_container(container_name)
            if container:
                node_id = container['node_id']
            else:
                node_id = find_best_node() or 1
        
        if not new_name:
            new_name = container_name
        
        # Import image
        await execute_lxc(new_name, f"image import {backup_file} --alias {new_name}_restored", node_id=node_id)
        
        # Create container from image
        await execute_lxc(new_name, f"init {new_name}_restored {new_name}", node_id=node_id)
        
        # Start container
        await execute_lxc(new_name, f"start {new_name}", node_id=node_id)
        
        # Update database
        container_data = {
            "container_name": new_name,
            "user_id": backup['user_id'] if 'user_id' in backup else get_vps_by_container(container_name)['user_id'],
            "node_id": node_id,
            "status": "running",
            "created_at": datetime.now().isoformat()
        }
        create_vps_record(container_data)
        
        logger.info(f"Restored backup {backup_id} to {new_name}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to restore backup {backup_id}: {e}")
        return False

# ========== DISCORD BOT SETUP ==========
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
intents.guilds = True
intents.presences = True

bot = commands.Bot(
    command_prefix=commands.when_mentioned_or(PREFIX),
    intents=intents,
    help_command=None,
    case_insensitive=True,
    strip_after_prefix=True
)

# ========== RATE LIMITING ==========
class RateLimiter:
    """Simple rate limiter for commands"""
    def __init__(self):
        self.user_limits = {}
        self.clear_old_entries.start()
    
    def check_limit(self, user_id: str, command: str, limit: int, window: int = 60) -> bool:
        """Check if user is rate limited for a command"""
        key = f"{user_id}:{command}"
        now = time.time()
        
        if key not in self.user_limits:
            self.user_limits[key] = []
        
        # Remove old entries
        self.user_limits[key] = [t for t in self.user_limits[key] if now - t < window]
        
        # Check if limit exceeded
        if len(self.user_limits[key]) >= limit:
            return False
        
        # Add current timestamp
        self.user_limits[key].append(now)
        return True
    
    @tasks.loop(seconds=60)
    async def clear_old_entries(self):
        """Clear old rate limit entries"""
        now = time.time()
        to_remove = []
        
        for key, timestamps in list(self.user_limits.items()):
            self.user_limits[key] = [t for t in timestamps if now - t < 300]  # 5 minutes
            
            if not self.user_limits[key]:
                to_remove.append(key)
        
        for key in to_remove:
            del self.user_limits[key]

rate_limiter = RateLimiter()

# ========== EMBED BUILDER ==========
def build_embed(
    title: str,
    description: str = "",
    color: int = 0x3498db,
    fields: List[Tuple[str, str, bool]] = None,
    footer: bool = True,
    timestamp: bool = True,
    thumbnail: str = None,
    image: str = None
) -> discord.Embed:
    """Build a consistent embed message"""
    embed = discord.Embed(
        title=title,
        description=description,
        color=color,
        timestamp=datetime.utcnow() if timestamp else None
    )
    
    if fields:
        for name, value, inline in fields:
            embed.add_field(name=name, value=value, inline=inline)
    
    if footer:
        embed.set_footer(text=f"{BOT_NAME} v{BOT_VERSION} • Upgraded by Zorvix AI")
    
    if thumbnail:
        embed.set_thumbnail(url=thumbnail)
    
    if image:
        embed.set_image(url=image)
    
    return embed

def success_embed(title: str, description: str = "", **kwargs) -> discord.Embed:
    """Create success embed (green)"""
    return build_embed(f"✅ {title}", description, 0x2ecc71, **kwargs)

def error_embed(title: str, description: str = "", **kwargs) -> discord.Embed:
    """Create error embed (red)"""
    return build_embed(f"❌ {title}", description, 0xe74c3c, **kwargs)

def warning_embed(title: str, description: str = "", **kwargs) -> discord.Embed:
    """Create warning embed (orange)"""
    return build_embed(f"⚠️ {title}", description, 0xf39c12, **kwargs)

def info_embed(title: str, description: str = "", **kwargs) -> discord.Embed:
    """Create info embed (blue)"""
    return build_embed(f"ℹ️ {title}", description, 0x3498db, **kwargs)

def premium_embed(title: str, description: str = "", **kwargs) -> discord.Embed:
    """Create premium embed (purple)"""
    return build_embed(f"💎 {title}", description, 0x9b59b6, **kwargs)

# ========== VIEWS AND UI COMPONENTS ==========
class PaginationView(discord.ui.View):
    """Paginated view for long lists"""
    def __init__(self, embeds: List[discord.Embed], user_id: int):
        super().__init__(timeout=180)
        self.embeds = embeds
        self.current_page = 0
        self.user_id = user_id
        self.update_buttons()
    
    def update_buttons(self):
        """Update button states based on current page"""
        self.clear_items()
        
        # First page button
        first_btn = discord.ui.Button(label="⏮️ First", style=discord.ButtonStyle.secondary, disabled=self.current_page == 0)
        first_btn.callback = self.first_page
        self.add_item(first_btn)
        
        # Previous button
        prev_btn = discord.ui.Button(label="◀️ Prev", style=discord.ButtonStyle.primary, disabled=self.current_page == 0)
        prev_btn.callback = self.prev_page
        self.add_item(prev_btn)
        
        # Page indicator
        page_btn = discord.ui.Button(
            label=f"Page {self.current_page + 1}/{len(self.embeds)}",
            style=discord.ButtonStyle.secondary,
            disabled=True
        )
        self.add_item(page_btn)
        
        # Next button
        next_btn = discord.ui.Button(label="Next ▶️", style=discord.ButtonStyle.primary, disabled=self.current_page == len(self.embeds) - 1)
        next_btn.callback = self.next_page
        self.add_item(next_btn)
        
        # Last page button
        last_btn = discord.ui.Button(label="Last ⏭️", style=discord.ButtonStyle.secondary, disabled=self.current_page == len(self.embeds) - 1)
        last_btn.callback = self.last_page
        self.add_item(last_btn)
        
        # Close button
        close_btn = discord.ui.Button(label="❌ Close", style=discord.ButtonStyle.danger)
        close_btn.callback = self.close_view
        self.add_item(close_btn)
    
    async def first_page(self, interaction: discord.Interaction):
        """Go to first page"""
        if interaction.user.id != self.user_id:
            await interaction.response.send_message("This is not your pagination!", ephemeral=True)
            return
        
        self.current_page = 0
        self.update_buttons()
        await interaction.response.edit_message(embed=self.embeds[self.current_page], view=self)
    
    async def prev_page(self, interaction: discord.Interaction):
        """Go to previous page"""
        if interaction.user.id != self.user_id:
            await interaction.response.send_message("This is not your pagination!", ephemeral=True)
            return
        
        self.current_page = max(0, self.current_page - 1)
        self.update_buttons()
        await interaction.response.edit_message(embed=self.embeds[self.current_page], view=self)
    
    async def next_page(self, interaction: discord.Interaction):
        """Go to next page"""
        if interaction.user.id != self.user_id:
            await interaction.response.send_message("This is not your pagination!", ephemeral=True)
            return
        
        self.current_page = min(len(self.embeds) - 1, self.current_page + 1)
        self.update_buttons()
        await interaction.response.edit_message(embed=self.embeds[self.current_page], view=self)
    
    async def last_page(self, interaction: discord.Interaction):
        """Go to last page"""
        if interaction.user.id != self.user_id:
            await interaction.response.send_message("This is not your pagination!", ephemeral=True)
            return
        
        self.current_page = len(self.embeds) - 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.embeds[self.current_page], view=self)
    
    async def close_view(self, interaction: discord.Interaction):
        """Close the pagination view"""
        if interaction.user.id != self.user_id:
            await interaction.response.send_message("This is not your pagination!", ephemeral=True)
            return
        
        await interaction.message.delete()
        self.stop()
    
    async def on_timeout(self):
        """Handle view timeout"""
        try:
            if hasattr(self, 'message'):
                embed = warning_embed("Session Expired", "This pagination session has expired.")
                await self.message.edit(embed=embed, view=None)
        except:
            pass

class ConfirmView(discord.ui.View):
    """Confirmation dialog view"""
    def __init__(self, user_id: int):
        super().__init__(timeout=60)
        self.user_id = user_id
        self.value = None
    
    @discord.ui.button(label="✅ Confirm", style=discord.ButtonStyle.success)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.user_id:
            await interaction.response.send_message("You cannot confirm this action!", ephemeral=True)
            return
        
        self.value = True
        await interaction.response.defer()
        self.stop()
    
    @discord.ui.button(label="❌ Cancel", style=discord.ButtonStyle.danger)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.user_id:
            await interaction.response.send_message("You cannot cancel this action!", ephemeral=True)
            return
        
        self.value = False
        await interaction.response.defer()
        self.stop()
    
    async def on_timeout(self):
        """Handle timeout"""
        self.value = False
        self.stop()

# ========== COMMAND CHECKS ==========
def admin_only():
    """Check if user is admin"""
    async def predicate(ctx):
        if not is_admin(str(ctx.author.id)):
            raise commands.CheckFailure("This command requires administrator privileges.")
        return True
    return commands.check(predicate)

def main_admin_only():
    """Check if user is main admin"""
    async def predicate(ctx):
        if not is_main_admin(str(ctx.author.id)):
            raise commands.CheckFailure("This command requires main administrator privileges.")
        return True
    return commands.check(predicate)

def rate_limit(limit: int = 5, window: int = 60):
    """Rate limit decorator"""
    async def predicate(ctx):
        if not rate_limiter.check_limit(str(ctx.author.id), ctx.command.name, limit, window):
            raise commands.CheckFailure(f"Rate limit exceeded. Please wait {window} seconds.")
        return True
    return commands.check(predicate)

# ========== BOT EVENTS ==========
@bot.event
async def on_ready():
    """Bot ready event"""
    logger.info(f"{bot.user} is now online!")
    logger.info(f"Guilds: {len(bot.guilds)}")
    logger.info(f"Users: {sum(g.member_count for g in bot.guilds)}")
    
    # Set bot presence
    await bot.change_presence(
        activity=discord.Activity(
            type=discord.ActivityType.watching,
            name=f"ZynexForge Cloud • {BOT_VERSION}"
        )
    )
    
    # Initialize database
    init_database()
    
    # Start background tasks
    if not monitor_resources.is_running():
        monitor_resources.start()
    
    if not cleanup_backups.is_running():
        cleanup_backups.start()
    
    if not update_node_status.is_running():
        update_node_status.start()
    
    logger.info("Background tasks started")

@bot.event
async def on_command_error(ctx, error):
    """Handle command errors"""
    if isinstance(error, commands.CommandNotFound):
        # Suggest similar commands
        available_commands = [cmd.name for cmd in bot.commands]
        user_input = ctx.message.content[len(ctx.prefix):].split()[0]
        
        # Find similar commands
        import difflib
        matches = difflib.get_close_matches(user_input, available_commands, n=3, cutoff=0.4)
        
        if matches:
            suggestions = "\n".join([f"• `{PREFIX}{cmd}`" for cmd in matches])
            embed = error_embed(
                "Command Not Found",
                f"Command `{user_input}` not found. Did you mean:\n{suggestions}"
            )
        else:
            embed = error_embed(
                "Command Not Found",
                f"Command `{user_input}` not found. Use `{PREFIX}help` to see available commands."
            )
        
        await ctx.send(embed=embed)
    
    elif isinstance(error, commands.MissingRequiredArgument):
        embed = error_embed(
            "Missing Argument",
            f"Missing required argument: `{error.param.name}`\n"
            f"Usage: `{PREFIX}{ctx.command.name} {ctx.command.signature}`"
        )
        await ctx.send(embed=embed)
    
    elif isinstance(error, commands.BadArgument):
        embed = error_embed(
            "Invalid Argument",
            f"Invalid argument provided.\n"
            f"Usage: `{PREFIX}{ctx.command.name} {ctx.command.signature}`"
        )
        await ctx.send(embed=embed)
    
    elif isinstance(error, commands.CheckFailure):
        if "administrator" in str(error):
            embed = error_embed(
                "Permission Denied",
                "This command requires administrator privileges."
            )
        elif "main administrator" in str(error):
            embed = error_embed(
                "Permission Denied",
                "This command requires main administrator privileges."
            )
        elif "Rate limit" in str(error):
            embed = error_embed(
                "Rate Limit Exceeded",
                str(error)
            )
        else:
            embed = error_embed(
                "Permission Denied",
                str(error) or "You don't have permission to use this command."
            )
        await ctx.send(embed=embed)
    
    elif isinstance(error, commands.CommandOnCooldown):
        embed = error_embed(
            "Command on Cooldown",
            f"Please wait {error.retry_after:.1f} seconds before using this command again."
        )
        await ctx.send(embed=embed)
    
    else:
        # Log unexpected errors
        logger.error(f"Command error in {ctx.command.name}: {error}", exc_info=error)
        
        embed = error_embed(
            "Unexpected Error",
            "An unexpected error occurred. The developers have been notified."
        )
        await ctx.send(embed=embed)

# ========== BACKGROUND TASKS ==========
@tasks.loop(seconds=60)
async def monitor_resources():
    """Monitor resource usage and auto-suspend if needed"""
    try:
        cpu_threshold = int(get_setting('cpu_threshold', 90))
        ram_threshold = int(get_setting('ram_threshold', 90))
        enable_auto_suspend = get_setting('enable_auto_suspend', '1') == '1'
        
        if not enable_auto_suspend:
            return
        
        # Get all running, non-whitelisted containers
        all_vps = get_all_vps()
        
        for container in all_vps:
            if (container['status'] == 'running' and 
                not container['suspended'] and 
                not container['whitelisted']):
                
                try:
                    stats = await get_container_stats(container['container_name'], container['node_id'])
                    
                    if stats['cpu'] > cpu_threshold or stats['ram']['percent'] > ram_threshold:
                        # Suspend container
                        await stop_container(container['container_name'], container['node_id'])
                        
                        # Update suspension history
                        history = container['suspension_history']
                        history.append({
                            'time': datetime.now().isoformat(),
                            'reason': f'High resource usage (CPU: {stats["cpu"]}%, RAM: {stats["ram"]["percent"]}%)',
                            'by': 'Auto-Suspension System'
                        })
                        
                        update_vps_record(container['container_name'], {
                            'suspended': 1,
                            'suspension_history': history
                        })
                        
                        # Log action
                        logger.warning(f"Auto-suspended {container['container_name']} for high resource usage")
                        
                        # Notify owner (if possible)
                        try:
                            user = await bot.fetch_user(int(container['user_id']))
                            embed = warning_embed(
                                "Container Auto-Suspended",
                                f"Your container `{container['container_name']}` has been suspended due to high resource usage.\n\n"
                                f"**CPU Usage:** {stats['cpu']}% (Threshold: {cpu_threshold}%)\n"
                                f"**RAM Usage:** {stats['ram']['percent']}% (Threshold: {ram_threshold}%)\n\n"
                                f"Contact an administrator to unsuspend."
                            )
                            await user.send(embed=embed)
                        except:
                            pass
                            
                except Exception as e:
                    logger.error(f"Error monitoring {container['container_name']}: {e}")
                    
    except Exception as e:
        logger.error(f"Error in monitor_resources: {e}")

@tasks.loop(hours=1)
async def cleanup_backups():
    """Clean up old backups"""
    try:
        retention_days = int(get_setting('backup_retention_days', 7))
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Find expired backups
        cursor.execute('SELECT id, location FROM backups WHERE created_at < ?', (cutoff_date.isoformat(),))
        expired_backups = cursor.fetchall()
        
        for backup in expired_backups:
            # Delete file if exists
            if os.path.exists(backup['location']):
                try:
                    os.remove(backup['location'])
                except:
                    pass
            
            # Delete database record
            cursor.execute('DELETE FROM backups WHERE id = ?', (backup['id'],))
        
        conn.commit()
        conn.close()
        
        if expired_backups:
            logger.info(f"Cleaned up {len(expired_backups)} old backups")
            
    except Exception as e:
        logger.error(f"Error in cleanup_backups: {e}")

@tasks.loop(minutes=5)
async def update_node_status():
    """Update node status and statistics"""
    try:
        nodes = get_nodes(enabled_only=False)
        
        for node in nodes:
            try:
                if node['is_local']:
                    # Update local node stats
                    update_node_usage(node['id'])
                else:
                    # Ping remote node
                    try:
                        response = requests.get(
                            f"{node['url']}/api/ping",
                            params={'api_key': node['api_key']},
                            timeout=5
                        )
                        if response.status_code == 200:
                            # Update last seen
                            conn = get_db_connection()
                            cursor = conn.cursor()
                            cursor.execute(
                                'UPDATE nodes SET last_seen = CURRENT_TIMESTAMP WHERE id = ?',
                                (node['id'],)
                            )
                            conn.commit()
                            conn.close()
                    except:
                        pass  # Node might be offline
                        
            except Exception as e:
                logger.error(f"Error updating node {node['name']}: {e}")
                
    except Exception as e:
        logger.error(f"Error in update_node_status: {e}")

# ========== USER COMMANDS ==========
@bot.command(name='ping')
@rate_limit(10, 60)
async def ping_command(ctx):
    """Check bot latency"""
    latency = round(bot.latency * 1000)
    
    embed = success_embed(
        "Pong! 🏓",
        f"**Bot Latency:** {latency}ms\n"
        f"**API Latency:** Calculating..."
    )
    
    # Calculate API latency
    start = time.monotonic()
    msg = await ctx.send(embed=embed)
    end = time.monotonic()
    api_latency = round((end - start) * 1000)
    
    embed.description = (
        f"**Bot Latency:** {latency}ms\n"
        f"**API Latency:** {api_latency}ms\n"
        f"**Total Response:** {latency + api_latency}ms"
    )
    
    await msg.edit(embed=embed)

@bot.command(name='myvps')
@rate_limit(5, 30)
async def my_vps_command(ctx):
    """List your VPS containers"""
    user_id = str(ctx.author.id)
    containers = get_vps_by_user(user_id)
    
    if not containers:
        embed = info_embed(
            "No Containers",
            "You don't have any containers yet. "
            f"Ask an administrator to create one with `{PREFIX}create` command."
        )
        await ctx.send(embed=embed)
        return
    
    # Create paginated embeds
    embeds = []
    items_per_page = 5
    
    for i in range(0, len(containers), items_per_page):
        page_containers = containers[i:i + items_per_page]
        
        embed = info_embed(
            "Your Containers",
            f"Showing {i+1}-{min(i+items_per_page, len(containers))} of {len(containers)} containers"
        )
        
        for idx, container in enumerate(page_containers, start=i+1):
            status_emoji = "🟢" if container['status'] == 'running' and not container['suspended'] else "🟡" if container['suspended'] else "🔴"
            status_text = "Running" if container['status'] == 'running' and not container['suspended'] else "Suspended" if container['suspended'] else "Stopped"
            
            embed.add_field(
                name=f"{status_emoji} Container #{idx}: {container['container_name']}",
                value=(
                    f"**Status:** {status_text}\n"
                    f"**Resources:** {container['ram']} RAM • {container['cpu']} CPU • {container['storage']} Disk\n"
                    f"**OS:** {container['os_version']}\n"
                    f"**Node:** {container.get('node_name', 'Unknown')}\n"
                    f"**Created:** {container['created_at'][:10]}"
                ),
                inline=False
            )
        
        embeds.append(embed)
    
    if len(embeds) == 1:
        await ctx.send(embed=embeds[0])
    else:
        view = PaginationView(embeds, ctx.author.id)
        view.message = await ctx.send(embed=embeds[0], view=view)

@bot.command(name='vpsinfo')
@rate_limit(5, 30)
async def vps_info_command(ctx, container_name: str):
    """Get detailed information about a VPS container"""
    container = get_vps_by_container(container_name)
    
    if not container:
        embed = error_embed(
            "Container Not Found",
            f"Container `{container_name}` not found."
        )
        await ctx.send(embed=embed)
        return
    
    # Check permissions
    user_id = str(ctx.author.id)
    if container['user_id'] != user_id and not is_admin(user_id):
        embed = error_embed(
            "Permission Denied",
            "You don't have permission to view this container."
        )
        await ctx.send(embed=embed)
        return
    
    # Get real-time stats
    stats = await get_container_stats(container_name, container['node_id'])
    
    # Build embed
    status_emoji = "🟢" if stats['status'] == 'running' and not container['suspended'] else "🟡" if container['suspended'] else "🔴"
    status_text = "Running" if stats['status'] == 'running' and not container['suspended'] else "Suspended" if container['suspended'] else "Stopped"
    
    embed = info_embed(
        f"{status_emoji} Container Information",
        f"**Name:** {container['container_name']}"
    )
    
    # Basic info
    embed.add_field(
        name="📋 Basic Information",
        value=(
            f"**Owner:** <@{container['user_id']}>\n"
            f"**Status:** {status_text}\n"
            f"**OS:** {container['os_version']}\n"
            f"**Node:** {container.get('node_name', 'Unknown')}\n"
            f"**Created:** {container['created_at'][:10]}"
        ),
        inline=False
    )
    
    # Resource allocation
    embed.add_field(
        name="⚙️ Resource Allocation",
        value=(
            f"**RAM:** {container['ram']}\n"
            f"**CPU:** {container['cpu']}\n"
            f"**Storage:** {container['storage']}\n"
            f"**Configuration:** {container['config']}"
        ),
        inline=True
    )
    
    # Real-time stats
    embed.add_field(
        name="📊 Real-time Statistics",
        value=(
            f"**CPU Usage:** {stats['cpu']}%\n"
            f"**RAM Usage:** {stats['ram']['percent']}%\n"
            f"**Disk Usage:** {stats['disk']['percent']}%\n"
            f"**Uptime:** {stats['uptime']}"
        ),
        inline=True
    )
    
    # Additional info
    if container['shared_with']:
        shared_users = ", ".join([f"<@{uid}>" for uid in container['shared_with']])
        embed.add_field(
            name="🔗 Shared With",
            value=shared_users,
            inline=False
        )
    
    if container['suspension_history']:
        last_suspension = container['suspension_history'][-1]
        embed.add_field(
            name="⚠️ Last Suspension",
            value=(
                f"**Reason:** {last_suspension.get('reason', 'Unknown')}\n"
                f"**Time:** {last_suspension.get('time', 'Unknown')[:10]}\n"
                f"**By:** {last_suspension.get('by', 'Unknown')}"
            ),
            inline=False
        )
    
    await ctx.send(embed=embed)

@bot.command(name='start')
@rate_limit(5, 30)
async def start_command(ctx, container_name: str):
    """Start a VPS container"""
    container = get_vps_by_container(container_name)
    
    if not container:
        embed = error_embed(
            "Container Not Found",
            f"Container `{container_name}` not found."
        )
        await ctx.send(embed=embed)
        return
    
    # Check permissions
    user_id = str(ctx.author.id)
    if (container['user_id'] != user_id and 
        user_id not in container.get('shared_with', []) and 
        not is_admin(user_id)):
        embed = error_embed(
            "Permission Denied",
            "You don't have permission to manage this container."
        )
        await ctx.send(embed=embed)
        return
    
    # Check if already running
    if container['status'] == 'running' and not container['suspended']:
        embed = warning_embed(
            "Already Running",
            f"Container `{container_name}` is already running."
        )
        await ctx.send(embed=embed)
        return
    
    # Check if suspended
    if container['suspended'] and not is_admin(user_id):
        embed = error_embed(
            "Container Suspended",
            "This container is suspended. Contact an administrator to unsuspend."
        )
        await ctx.send(embed=embed)
        return
    
    # Start container
    embed = info_embed(
        "Starting Container",
        f"Starting `{container_name}`..."
    )
    msg = await ctx.send(embed=embed)
    
    success = await start_container(container_name, container['node_id'])
    
    if success:
        embed = success_embed(
            "Container Started",
            f"Container `{container_name}` has been started successfully."
        )
    else:
        embed = error_embed(
            "Failed to Start",
            f"Failed to start container `{container_name}`."
        )
    
    await msg.edit(embed=embed)

@bot.command(name='stop')
@rate_limit(5, 30)
async def stop_command(ctx, container_name: str):
    """Stop a VPS container"""
    container = get_vps_by_container(container_name)
    
    if not container:
        embed = error_embed(
            "Container Not Found",
            f"Container `{container_name}` not found."
        )
        await ctx.send(embed=embed)
        return
    
    # Check permissions
    user_id = str(ctx.author.id)
    if (container['user_id'] != user_id and 
        user_id not in container.get('shared_with', []) and 
        not is_admin(user_id)):
        embed = error_embed(
            "Permission Denied",
            "You don't have permission to manage this container."
        )
        await ctx.send(embed=embed)
        return
    
    # Check if already stopped
    if container['status'] != 'running':
        embed = warning_embed(
            "Already Stopped",
            f"Container `{container_name}` is already stopped."
        )
        await ctx.send(embed=embed)
        return
    
    # Stop container
    embed = info_embed(
        "Stopping Container",
        f"Stopping `{container_name}`..."
    )
    msg = await ctx.send(embed=embed)
    
    success = await stop_container(container_name, container['node_id'])
    
    if success:
        embed = success_embed(
            "Container Stopped",
            f"Container `{container_name}` has been stopped successfully."
        )
    else:
        embed = error_embed(
            "Failed to Stop",
            f"Failed to stop container `{container_name}`."
        )
    
    await msg.edit(embed=embed)

@bot.command(name='restart')
@rate_limit(5, 30)
async def restart_command(ctx, container_name: str):
    """Restart a VPS container"""
    container = get_vps_by_container(container_name)
    
    if not container:
        embed = error_embed(
            "Container Not Found",
            f"Container `{container_name}` not found."
        )
        await ctx.send(embed=embed)
        return
    
    # Check permissions
    user_id = str(ctx.author.id)
    if (container['user_id'] != user_id and 
        user_id not in container.get('shared_with', []) and 
        not is_admin(user_id)):
        embed = error_embed(
            "Permission Denied",
            "You don't have permission to manage this container."
        )
        await ctx.send(embed=embed)
        return
    
    # Restart container
    embed = info_embed(
        "Restarting Container",
        f"Restarting `{container_name}`..."
    )
    msg = await ctx.send(embed=embed)
    
    success = await restart_container(container_name, container['node_id'])
    
    if success:
        embed = success_embed(
            "Container Restarted",
            f"Container `{container_name}` has been restarted successfully."
        )
    else:
        embed = error_embed(
            "Failed to Restart",
            f"Failed to restart container `{container_name}`."
        )
    
    await msg.edit(embed=embed)

# ========== ADMIN COMMANDS ==========
@bot.command(name='create')
@admin_only()
@rate_limit(3, 60)
async def create_command(ctx, ram: int, cpu: int, disk: int, user: discord.Member):
    """Create a new VPS container for a user"""
    # Validate parameters
    if ram <= 0 or cpu <= 0 or disk <= 0:
        embed = error_embed(
            "Invalid Parameters",
            "RAM, CPU, and Disk must be positive integers."
        )
        await ctx.send(embed=embed)
        return
    
    # Check user quota
    user_id = str(user.id)
    quota_ok, quota_msg = check_user_quota(user_id, ram, cpu, disk)
    if not quota_ok:
        embed = error_embed("Quota Exceeded", quota_msg)
        await ctx.send(embed=embed)
        return
    
    # Find best node
    node_id = find_best_node()
    if not node_id:
        embed = error_embed(
            "No Available Nodes",
            "No nodes available for deployment."
        )
        await ctx.send(embed=embed)
        return
    
    # Generate container name
    user_containers = get_vps_by_user(user_id)
    container_num = len(user_containers) + 1
    container_name = f"zynexforge-{user_id[:8]}-{container_num}"
    
    # Show OS selection
    embed = info_embed(
        "Select OS",
        f"Creating container for {user.mention} with:\n"
        f"**RAM:** {ram}GB\n**CPU:** {cpu} cores\n**Disk:** {disk}GB\n\n"
        "Please select an OS from the dropdown below:"
    )
    
    # Create OS selection view
    class OSSelectView(discord.ui.View):
        def __init__(self, ctx, user, ram, cpu, disk, node_id):
            super().__init__(timeout=120)
            self.ctx = ctx
            self.user = user
            self.ram = ram
            self.cpu = cpu
            self.disk = disk
            self.node_id = node_id
            self.value = None
        
        @discord.ui.select(
            placeholder="Select Operating System",
            options=[
                discord.SelectOption(
                    label=os_option["label"],
                    value=os_option["value"],
                    description=os_option.get("image", "")
                )
                for os_option in OS_OPTIONS
            ]
        )
        async def select_os(self, interaction: discord.Interaction, select: discord.ui.Select):
            if interaction.user != self.ctx.author:
                await interaction.response.send_message("You cannot select an OS!", ephemeral=True)
                return
            
            self.value = select.values[0]
            await interaction.response.defer()
            self.stop()
    
    view = OSSelectView(ctx, user, ram, cpu, disk, node_id)
    msg = await ctx.send(embed=embed, view=view)
    
    # Wait for selection
    await view.wait()
    
    if not view.value:
        await msg.edit(content="OS selection timed out.", embed=None, view=None)
        return
    
    os_version = view.value
    
    # Create container
    embed = info_embed(
        "Creating Container",
        f"Creating container `{container_name}` with {os_version}...\n"
        "This may take a few minutes."
    )
    await msg.edit(embed=embed, view=None)
    
    try:
        # Create container
        success = await create_container(container_name, os_version, ram, cpu, disk, node_id)
        
        if success:
            # Create database record
            container_data = {
                'user_id': user_id,
                'node_id': node_id,
                'container_name': container_name,
                'ram': f"{ram}GB",
                'cpu': f"{cpu} Cores",
                'storage': f"{disk}GB",
                'config': f"{ram}GB RAM / {cpu} CPU / {disk}GB Disk",
                'os_version': os_version,
                'status': 'running',
                'suspended': 0,
                'created_at': datetime.now().isoformat(),
                'shared_with': [],
                'suspension_history': []
            }
            
            create_vps_record(container_data)
            
            # Send success message
            embed = success_embed(
                "Container Created",
                f"Container `{container_name}` has been created successfully for {user.mention}.\n\n"
                f"**Resources:** {ram}GB RAM • {cpu} CPU • {disk}GB Disk\n"
                f"**OS:** {os_version}\n"
                f"**Node:** {get_node(node_id)['name']}\n\n"
                f"User can manage it with `{PREFIX}myvps`"
            )
            
            # Send DM to user
            try:
                user_embed = success_embed(
                    "New Container Created",
                    f"A new container has been created for you by {ctx.author.mention}.\n\n"
                    f"**Container Name:** `{container_name}`\n"
                    f"**Resources:** {ram}GB RAM • {cpu} CPU • {disk}GB Disk\n"
                    f"**OS:** {os_version}\n\n"
                    f"Use `{PREFIX}myvps` to see your containers.\n"
                    f"Use `{PREFIX}start {container_name}` to start it if needed."
                )
                await user.send(embed=user_embed)
            except:
                pass  # User might have DMs disabled
            
        else:
            embed = error_embed(
                "Creation Failed",
                f"Failed to create container `{container_name}`."
            )
        
        await msg.edit(embed=embed)
        
    except Exception as e:
        logger.error(f"Failed to create container: {e}")
        embed = error_embed(
            "Creation Failed",
            f"An error occurred: {str(e)}"
        )
        await msg.edit(embed=embed)

@bot.command(name='delete')
@admin_only()
@rate_limit(3, 60)
async def delete_command(ctx, container_name: str, *, reason: str = "No reason provided"):
    """Delete a VPS container"""
    container = get_vps_by_container(container_name)
    
    if not container:
        embed = error_embed(
            "Container Not Found",
            f"Container `{container_name}` not found."
        )
        await ctx.send(embed=embed)
        return
    
    # Confirmation
    embed = warning_embed(
        "⚠️ Confirm Deletion",
        f"Are you sure you want to delete container `{container_name}`?\n\n"
        f"**Owner:** <@{container['user_id']}>\n"
        f"**Resources:** {container['ram']} RAM • {container['cpu']} CPU • {container['storage']} Disk\n"
        f"**Reason:** {reason}\n\n"
        "This action cannot be undone!"
    )
    
    view = ConfirmView(ctx.author.id)
    msg = await ctx.send(embed=embed, view=view)
    
    await view.wait()
    
    if view.value is None:
        await msg.edit(content="Deletion cancelled (timeout).", embed=None, view=None)
        return
    
    if not view.value:
        await msg.edit(content="Deletion cancelled.", embed=None, view=None)
        return
    
    # Delete container
    embed = info_embed(
        "Deleting Container",
        f"Deleting `{container_name}`..."
    )
    await msg.edit(embed=embed, view=None)
    
    success = await delete_container(container_name, container['node_id'])
    
    if success:
        embed = success_embed(
            "Container Deleted",
            f"Container `{container_name}` has been deleted successfully.\n"
            f"**Reason:** {reason}"
        )
        
        # Notify owner
        try:
            owner = await bot.fetch_user(int(container['user_id']))
            owner_embed = warning_embed(
                "Container Deleted",
                f"Your container `{container_name}` has been deleted by {ctx.author.mention}.\n\n"
                f"**Reason:** {reason}\n\n"
                "Contact an administrator if you have questions."
            )
            await owner.send(embed=owner_embed)
        except:
            pass
        
    else:
        embed = error_embed(
            "Deletion Failed",
            f"Failed to delete container `{container_name}`."
        )
    
    await msg.edit(embed=embed)

@bot.command(name='suspend')
@admin_only()
@rate_limit(5, 30)
async def suspend_command(ctx, container_name: str, *, reason: str = "Administrative action"):
    """Suspend a VPS container"""
    container = get_vps_by_container(container_name)
    
    if not container:
        embed = error_embed(
            "Container Not Found",
            f"Container `{container_name}` not found."
        )
        await ctx.send(embed=embed)
        return
    
    if container['suspended']:
        embed = warning_embed(
            "Already Suspended",
            f"Container `{container_name}` is already suspended."
        )
        await ctx.send(embed=embed)
        return
    
    # Stop container
    success = await stop_container(container_name, container['node_id'])
    
    if success:
        # Update suspension history
        history = container['suspension_history']
        history.append({
            'time': datetime.now().isoformat(),
            'reason': reason,
            'by': f"{ctx.author.name} ({ctx.author.id})"
        })
        
        update_vps_record(container_name, {
            'suspended': 1,
            'suspension_history': history
        })
        
        embed = success_embed(
            "Container Suspended",
            f"Container `{container_name}` has been suspended.\n"
            f"**Reason:** {reason}"
        )
        
        # Notify owner
        try:
            owner = await bot.fetch_user(int(container['user_id']))
            owner_embed = warning_embed(
                "Container Suspended",
                f"Your container `{container_name}` has been suspended by {ctx.author.mention}.\n\n"
                f"**Reason:** {reason}\n\n"
                "Contact an administrator to unsuspend."
            )
            await owner.send(embed=owner_embed)
        except:
            pass
        
    else:
        embed = error_embed(
            "Suspension Failed",
            f"Failed to suspend container `{container_name}`."
        )
    
    await ctx.send(embed=embed)

@bot.command(name='unsuspend')
@admin_only()
@rate_limit(5, 30)
async def unsuspend_command(ctx, container_name: str):
    """Unsuspend a VPS container"""
    container = get_vps_by_container(container_name)
    
    if not container:
        embed = error_embed(
            "Container Not Found",
            f"Container `{container_name}` not found."
        )
        await ctx.send(embed=embed)
        return
    
    if not container['suspended']:
        embed = warning_embed(
            "Not Suspended",
            f"Container `{container_name}` is not suspended."
        )
        await ctx.send(embed=embed)
        return
    
    # Start container
    success = await start_container(container_name, container['node_id'])
    
    if success:
        update_vps_record(container_name, {'suspended': 0})
        
        embed = success_embed(
            "Container Unsuspended",
            f"Container `{container_name}` has been unsuspended and started."
        )
        
        # Notify owner
        try:
            owner = await bot.fetch_user(int(container['user_id']))
            owner_embed = success_embed(
                "Container Unsuspended",
                f"Your container `{container_name}` has been unsuspended by {ctx.author.mention}.\n\n"
                "You can now manage it normally."
            )
            await owner.send(embed=owner_embed)
        except:
            pass
        
    else:
        embed = error_embed(
            "Unsuspension Failed",
            f"Failed to unsuspend container `{container_name}`."
        )
    
    await ctx.send(embed=embed)

# ========== PORT FORWARDING COMMANDS ==========
@bot.command(name='ports')
@rate_limit(5, 30)
async def ports_command(ctx, subcommand: str = None, *args):
    """Manage port forwards"""
    user_id = str(ctx.author.id)
    
    if not subcommand:
        # Show port quota and active forwards
        quota = get_user_port_quota(user_id)
        forwards = get_port_forwards_by_user(user_id)
        
        embed = info_embed(
            "Port Forwarding",
            f"**Allocated Ports:** {quota['allocated_ports']}\n"
            f"**Used Ports:** {quota['used_ports']}\n"
            f"**Available Ports:** {quota['available_ports']}\n"
            f"**Maximum Ports:** {quota['max_ports']}"
        )
        
        if forwards:
            forward_list = []
            for fwd in forwards[:10]:  # Show first 10
                container = get_vps_by_container(fwd['vps_container'])
                container_num = "?"
                if container:
                    user_containers = get_vps_by_user(user_id)
                    for idx, c in enumerate(user_containers, 1):
                        if c['container_name'] == fwd['vps_container']:
                            container_num = idx
                            break
                
                forward_list.append(
                    f"**ID {fwd['id']}:** Container #{container_num} "
                    f"(`{fwd['vps_container']}`)\n"
                    f"   {fwd['vps_port']} ← {YOUR_SERVER_IP}:{fwd['host_port']} ({fwd['protocol'].upper()})"
                )
            
            embed.add_field(
                name="Active Forwards",
                value="\n".join(forward_list) or "No active forwards",
                inline=False
            )
            
            if len(forwards) > 10:
                embed.add_field(
                    name="Note",
                    value=f"Showing 10 of {len(forwards)} forwards. Use `{PREFIX}ports list` to see all.",
                    inline=False
                )
        else:
            embed.add_field(
                name="Active Forwards",
                value="No active port forwards.",
                inline=False
            )
        
        embed.add_field(
            name="Commands",
            value=(
                f"`{PREFIX}ports add <container_num> <port> [protocol]` - Add forward\n"
                f"`{PREFIX}ports list` - List all forwards\n"
                f"`{PREFIX}ports remove <id>` - Remove forward\n"
                f"`{PREFIX}ports quota` - Show quota"
            ),
            inline=False
        )
        
        await ctx.send(embed=embed)
        return
    
    subcommand = subcommand.lower()
    
    if subcommand == 'add':
        if len(args) < 2:
            embed = error_embed(
                "Invalid Usage",
                f"Usage: `{PREFIX}ports add <container_num> <port> [protocol]`\n"
                f"Protocol can be: tcp, udp, both (default: tcp)"
            )
            await ctx.send(embed=embed)
            return
        
        try:
            container_num = int(args[0])
            vps_port = int(args[1])
            protocol = args[2].lower() if len(args) > 2 else 'tcp'
        except ValueError:
            embed = error_embed(
                "Invalid Arguments",
                "Container number and port must be integers."
            )
            await ctx.send(embed=embed)
            return
        
        if protocol not in ['tcp', 'udp', 'both']:
            embed = error_embed(
                "Invalid Protocol",
                "Protocol must be: tcp, udp, or both"
            )
            await ctx.send(embed=embed)
            return
        
        if vps_port < 1 or vps_port > 65535:
            embed = error_embed(
                "Invalid Port",
                "Port must be between 1 and 65535"
            )
            await ctx.send(embed=embed)
            return
        
        # Get user's containers
        containers = get_vps_by_user(user_id)
        if container_num < 1 or container_num > len(containers):
            embed = error_embed(
                "Invalid Container",
                f"You have {len(containers)} containers. Use number 1-{len(containers)}."
            )
            await ctx.send(embed=embed)
            return
        
        container = containers[container_num - 1]
        container_name = container['container_name']
        
        # Check quota
        quota = get_user_port_quota(user_id)
        if quota['used_ports'] >= quota['allocated_ports']:
            embed = error_embed(
                "Quota Exceeded",
                f"You have used all {quota['allocated_ports']} allocated ports. "
                f"Ask an administrator for more ports."
            )
            await ctx.send(embed=embed)
            return
        
        # Create port forward
        embed = info_embed(
            "Creating Port Forward",
            f"Creating port forward for `{container_name}`..."
        )
        msg = await ctx.send(embed=embed)
        
        forward_id = await create_port_forward(container_name, vps_port, protocol)
        
        if forward_id:
            forward = get_port_forward_by_id(forward_id)
            embed = success_embed(
                "Port Forward Created",
                f"Port forward created successfully!\n\n"
                f"**Container:** `{container_name}`\n"
                f"**Container Port:** {vps_port}\n"
                f"**Host Port:** {forward['host_port']}\n"
                f"**Protocol:** {protocol.upper()}\n"
                f"**Access:** `{YOUR_SERVER_IP}:{forward['host_port']}`\n\n"
                f"Quota: {quota['used_ports'] + 1}/{quota['allocated_ports']} ports used"
            )
        else:
            embed = error_embed(
                "Creation Failed",
                "Failed to create port forward. The port might already be in use."
            )
        
        await msg.edit(embed=embed)
    
    elif subcommand == 'list':
        forwards = get_port_forwards_by_user(user_id)
        
        if not forwards:
            embed = info_embed(
                "No Port Forwards",
                "You don't have any active port forwards."
            )
            await ctx.send(embed=embed)
            return
        
        # Create paginated list
        embeds = []
        items_per_page = 8
        
        for i in range(0, len(forwards), items_per_page):
            page_forwards = forwards[i:i + items_per_page]
            
            embed = info_embed(
                "Your Port Forwards",
                f"Showing {i+1}-{min(i+items_per_page, len(forwards))} of {len(forwards)} forwards"
            )
            
            for fwd in page_forwards:
                container = get_vps_by_container(fwd['vps_container'])
                container_num = "?"
                if container:
                    user_containers = get_vps_by_user(user_id)
                    for idx, c in enumerate(user_containers, 1):
                        if c['container_name'] == fwd['vps_container']:
                            container_num = idx
                            break
                
                embed.add_field(
                    name=f"ID {fwd['id']}: Container #{container_num}",
                    value=(
                        f"**Container:** `{fwd['vps_container']}`\n"
                        f"**Port:** {fwd['vps_port']} ← {fwd['host_port']}\n"
                        f"**Protocol:** {fwd['protocol'].upper()}\n"
                        f"**Created:** {fwd['created_at'][:10]}"
                    ),
                    inline=True
                )
            
            embeds.append(embed)
        
        if len(embeds) == 1:
            await ctx.send(embed=embeds[0])
        else:
            view = PaginationView(embeds, ctx.author.id)
            view.message = await ctx.send(embed=embeds[0], view=view)
    
    elif subcommand == 'remove':
        if not args:
            embed = error_embed(
                "Invalid Usage",
                f"Usage: `{PREFIX}ports remove <forward_id>`\n"
                f"Use `{PREFIX}ports list` to see forward IDs."
            )
            await ctx.send(embed=embed)
            return
        
        try:
            forward_id = int(args[0])
        except ValueError:
            embed = error_embed(
                "Invalid ID",
                "Forward ID must be a number."
            )
            await ctx.send(embed=embed)
            return
        
        # Check if forward exists and belongs to user
        forward = get_port_forward_by_id(forward_id)
        if not forward or forward['user_id'] != user_id:
            embed = error_embed(
                "Forward Not Found",
                "Port forward not found or you don't have permission to remove it."
            )
            await ctx.send(embed=embed)
            return
        
        # Remove forward
        success = await remove_port_forward(forward_id)
        
        if success:
            embed = success_embed(
                "Port Forward Removed",
                f"Port forward ID {forward_id} has been removed."
            )
        else:
            embed = error_embed(
                "Removal Failed",
                f"Failed to remove port forward ID {forward_id}."
            )
        
        await ctx.send(embed=embed)
    
    elif subcommand == 'quota':
        quota = get_user_port_quota(user_id)
        
        embed = info_embed(
            "Port Quota",
            f"**Allocated Ports:** {quota['allocated_ports']}\n"
            f"**Used Ports:** {quota['used_ports']}\n"
            f"**Available Ports:** {quota['available_ports']}\n"
            f"**Maximum Ports:** {quota['max_ports']}\n\n"
            f"**Usage:** {quota['used_ports']}/{quota['allocated_ports']} "
            f"({(quota['used_ports']/quota['allocated_ports']*100 if quota['allocated_ports'] > 0 else 0):.1f}%)"
        )
        
        await ctx.send(embed=embed)
    
    else:
        embed = error_embed(
            "Invalid Subcommand",
            f"Available subcommands: add, list, remove, quota\n"
            f"Use `{PREFIX}ports` for help."
        )
        await ctx.send(embed=embed)

# ========== SYSTEM COMMANDS ==========
@bot.command(name='status')
@admin_only()
@rate_limit(5, 60)
async def status_command(ctx):
    """Show system status"""
    embed = info_embed(
        "System Status",
        "Gathering system information..."
    )
    msg = await ctx.send(embed=embed)
    
    try:
        # Gather statistics
        total_users = len(set(c['user_id'] for c in get_all_vps()))
        total_containers = len(get_all_vps())
        
        running_containers = len([c for c in get_all_vps() if c['status'] == 'running' and not c['suspended']])
        suspended_containers = len([c for c in get_all_vps() if c['suspended']])
        stopped_containers = len([c for c in get_all_vps() if c['status'] != 'running' and not c['suspended']])
        
        # Node statistics
        nodes = get_nodes()
        online_nodes = 0
        total_capacity = 0
        used_capacity = 0
        
        for node in nodes:
            if node['is_local']:
                online_nodes += 1
            else:
                try:
                    response = requests.get(
                        f"{node['url']}/api/ping",
                        params={'api_key': node['api_key']},
                        timeout=3
                    )
                    if response.status_code == 200:
                        online_nodes += 1
                except:
                    pass
            
            total_capacity += node['total_vps']
            used_capacity += node['used_vps']
        
        # Resource usage
        cpu_usage = psutil.cpu_percent()
        ram_usage = psutil.virtual_memory().percent
        disk_usage = psutil.disk_usage('/').percent
        
        # Update embed
        embed = info_embed(
            "System Status Dashboard",
            f"**Bot Uptime:** {str(datetime.now() - datetime.fromtimestamp(psutil.boot_time())).split('.')[0]}\n"
            f"**Bot Latency:** {round(bot.latency * 1000)}ms\n"
            f"**Bot Version:** {BOT_VERSION}"
        )
        
        embed.add_field(
            name="📊 Container Statistics",
            value=(
                f"**Total Users:** {total_users}\n"
                f"**Total Containers:** {total_containers}\n"
                f"**🟢 Running:** {running_containers}\n"
                f"**🟡 Suspended:** {suspended_containers}\n"
                f"**🔴 Stopped:** {stopped_containers}"
            ),
            inline=True
        )
        
        embed.add_field(
            name="🛰️ Node Statistics",
            value=(
                f"**Total Nodes:** {len(nodes)}\n"
                f"**🟢 Online:** {online_nodes}\n"
                f"**🔴 Offline:** {len(nodes) - online_nodes}\n"
                f"**Capacity:** {used_capacity}/{total_capacity} "
                f"({(used_capacity/total_capacity*100 if total_capacity > 0 else 0):.1f}%)"
            ),
            inline=True
        )
        
        embed.add_field(
            name="💻 Host Resources",
            value=(
                f"**CPU Usage:** {cpu_usage:.1f}%\n"
                f"**RAM Usage:** {ram_usage:.1f}%\n"
                f"**Disk Usage:** {disk_usage:.1f}%\n"
                f"**Load Average:** {', '.join([str(x) for x in psutil.getloadavg()])}"
            ),
            inline=True
        )
        
        # System health
        health_status = "🟢 Healthy"
        if online_nodes == 0:
            health_status = "🔴 Critical - No nodes online"
        elif online_nodes < len(nodes):
            health_status = "🟡 Warning - Some nodes offline"
        elif cpu_usage > 90 or ram_usage > 90 or disk_usage > 90:
            health_status = "🟡 Warning - High resource usage"
        
        embed.add_field(
            name="🏥 System Health",
            value=health_status,
            inline=False
        )
        
        await msg.edit(embed=embed)
        
    except Exception as e:
        logger.error(f"Error in status command: {e}")
        embed = error_embed(
            "Error",
            f"Failed to gather system status: {str(e)}"
        )
        await msg.edit(embed=embed)

@bot.command(name='nodes')
@admin_only()
@rate_limit(5, 60)
async def nodes_command(ctx):
    """List all nodes"""
    nodes = get_nodes(enabled_only=False)
    
    if not nodes:
        embed = info_embed(
            "No Nodes",
            "No nodes configured. Use `!node create` to add a node."
        )
        await ctx.send(embed=embed)
        return
    
    # Create paginated node list
    embeds = []
    items_per_page = 3
    
    for i in range(0, len(nodes), items_per_page):
        page_nodes = nodes[i:i + items_per_page]
        
        embed = info_embed(
            "Node List",
            f"Showing {i+1}-{min(i+items_per_page, len(nodes))} of {len(nodes)} nodes"
        )
        
        for node in page_nodes:
            # Determine node status
            if node['is_local']:
                status = "🟢 Local"
                last_seen = "Now"
            else:
                try:
                    response = requests.get(
                        f"{node['url']}/api/ping",
                        params={'api_key': node['api_key']},
                        timeout=3
                    )
                    status = "🟢 Online" if response.status_code == 200 else "🔴 Offline"
                except:
                    status = "🔴 Offline"
            
            last_seen = node.get('last_seen', 'Never')
            if last_seen and last_seen != 'Never':
                last_seen = last_seen[:16]  # Trim to date and hour
            
            usage_percent = (node['used_vps'] / node['total_vps'] * 100) if node['total_vps'] > 0 else 0
            
            embed.add_field(
                name=f"{'🖥️' if node['is_local'] else '🌐'} {node['name']} (ID: {node['id']})",
                value=(
                    f"**Status:** {status}\n"
                    f"**Location:** {node['location']}\n"
                    f"**Capacity:** {node['used_vps']}/{node['total_vps']} ({usage_percent:.1f}%)\n"
                    f"**Priority:** {node['priority']}\n"
                    f"**Last Seen:** {last_seen}\n"
                    f"**Tags:** {', '.join(node['tags'])}"
                ),
                inline=False
            )
        
        embeds.append(embed)
    
    if len(embeds) == 1:
        await ctx.send(embed=embeds[0])
    else:
        view = PaginationView(embeds, ctx.author.id)
        view.message = await ctx.send(embed=embeds[0], view=view)

@bot.command(name='help')
@rate_limit(5, 30)
async def help_command(ctx, command: str = None):
    """Show help information"""
    if command:
        # Show specific command help
        cmd = bot.get_command(command.lower())
        if not cmd:
            embed = error_embed(
                "Command Not Found",
                f"Command `{command}` not found. Use `{PREFIX}help` to see all commands."
            )
            await ctx.send(embed=embed)
            return
        
        embed = info_embed(
            f"Command: {PREFIX}{cmd.name}",
            cmd.help or "No description available."
        )
        
        # Add usage
        if cmd.signature:
            embed.add_field(
                name="Usage",
                value=f"`{PREFIX}{cmd.name} {cmd.signature}`",
                inline=False
            )
        
        # Add aliases
        if cmd.aliases:
            embed.add_field(
                name="Aliases",
                value=", ".join([f"`{PREFIX}{alias}`" for alias in cmd.aliases]),
                inline=False
            )
        
        await ctx.send(embed=embed)
        return
    
    # Show general help
    user_id = str(ctx.author.id)
    is_admin_user = is_admin(user_id)
    is_main_admin_user = is_main_admin(user_id)
    
    embed = info_embed(
        "ZynexForge Help",
        f"**Prefix:** `{PREFIX}`\n"
        f"**Version:** {BOT_VERSION}\n"
        f"Use `{PREFIX}help <command>` for detailed help on a specific command."
    )
    
    # User commands
    user_commands = [
        ("ping", "Check bot latency"),
        ("myvps", "List your containers"),
        ("vpsinfo <container>", "Get container information"),
        ("start <container>", "Start a container"),
        ("stop <container>", "Stop a container"),
        ("restart <container>", "Restart a container"),
        ("ports", "Manage port forwards"),
        ("help", "Show this help message")
    ]
    
    embed.add_field(
        name="👤 User Commands",
        value="\n".join([f"`{PREFIX}{cmd}` - {desc}" for cmd, desc in user_commands]),
        inline=False
    )
    
    if is_admin_user:
        # Admin commands
        admin_commands = [
            ("create <ram> <cpu> <disk> @user", "Create container for user"),
            ("delete <container> [reason]", "Delete container"),
            ("suspend <container> [reason]", "Suspend container"),
            ("unsuspend <container>", "Unsuspend container"),
            ("nodes", "List all nodes"),
            ("status", "Show system status")
        ]
        
        embed.add_field(
            name="🛡️ Admin Commands",
            value="\n".join([f"`{PREFIX}{cmd}` - {desc}" for cmd, desc in admin_commands]),
            inline=False
        )
    
    if is_main_admin_user:
        # Main admin commands
        main_admin_commands = [
            ("admin add @user", "Add administrator"),
            ("admin remove @user", "Remove administrator"),
            ("admin list", "List administrators"),
            ("node create", "Create new node"),
            ("node edit <id>", "Edit node"),
            ("node delete <id>", "Delete node")
        ]
        
        embed.add_field(
            name="👑 Main Admin Commands",
            value="\n".join([f"`{PREFIX}{cmd}` - {desc}" for cmd, desc in main_admin_commands]),
            inline=False
        )
    
    await ctx.send(embed=embed)

# ========== MAIN ADMIN COMMANDS ==========
@bot.group(name='admin', invoke_without_command=True)
@main_admin_only()
async def admin_group(ctx):
    """Administrator management commands"""
    await ctx.send_help(ctx.command)

@admin_group.command(name='add')
@main_admin_only()
async def admin_add_command(ctx, user: discord.Member):
    """Add user as administrator"""
    user_id = str(user.id)
    
    if is_admin(user_id):
        embed = warning_embed(
            "Already Admin",
            f"{user.mention} is already an administrator."
        )
        await ctx.send(embed=embed)
        return
    
    success = add_admin(user_id, str(ctx.author.id))
    
    if success:
        embed = success_embed(
            "Admin Added",
            f"{user.mention} has been added as an administrator."
        )
        
        # Notify user
        try:
            user_embed = success_embed(
                "Administrator Privileges",
                f"You have been granted administrator privileges by {ctx.author.mention}.\n\n"
                f"You can now use admin commands with prefix `{PREFIX}`."
            )
            await user.send(embed=user_embed)
        except:
            pass
    else:
        embed = error_embed(
            "Failed to Add Admin",
            f"Failed to add {user.mention} as administrator."
        )
    
    await ctx.send(embed=embed)

@admin_group.command(name='remove')
@main_admin_only()
async def admin_remove_command(ctx, user: discord.Member):
    """Remove user from administrators"""
    user_id = str(user.id)
    
    if not is_admin(user_id) or is_main_admin(user_id):
        embed = error_embed(
            "Cannot Remove",
            f"Cannot remove {user.mention} from administrators."
        )
        await ctx.send(embed=embed)
        return
    
    success = remove_admin(user_id)
    
    if success:
        embed = success_embed(
            "Admin Removed",
            f"{user.mention} has been removed from administrators."
        )
        
        # Notify user
        try:
            user_embed = warning_embed(
                "Administrator Privileges Revoked",
                f"Your administrator privileges have been revoked by {ctx.author.mention}."
            )
            await user.send(embed=user_embed)
        except:
            pass
    else:
        embed = error_embed(
            "Failed to Remove Admin",
            f"Failed to remove {user.mention} from administrators."
        )
    
    await ctx.send(embed=embed)

@admin_group.command(name='list')
@main_admin_only()
async def admin_list_command(ctx):
    """List all administrators"""
    admins = get_admins()
    
    embed = info_embed(
        "Administrators",
        f"**Main Admin:** <@{MAIN_ADMIN_ID}>"
    )
    
    if admins:
        admin_list = []
        for admin_id in admins:
            try:
                admin = await bot.fetch_user(int(admin_id))
                admin_list.append(f"• {admin.mention} (ID: {admin_id})")
            except:
                admin_list.append(f"• Unknown User (ID: {admin_id})")
        
        embed.add_field(
            name="Additional Admins",
            value="\n".join(admin_list),
            inline=False
        )
    else:
        embed.add_field(
            name="Additional Admins",
            value="No additional administrators.",
            inline=False
        )
    
    await ctx.send(embed=embed)

# ========== NODE MANAGEMENT COMMANDS ==========
@bot.group(name='node', invoke_without_command=True)
@main_admin_only()
async def node_group(ctx):
    """Node management commands"""
    await ctx.send_help(ctx.command)

@node_group.command(name='create')
@main_admin_only()
async def node_create_command(ctx):
    """Create a new node"""
    # Interactive node creation
    questions = [
        ("Enter node name:", "name", str),
        ("Enter location:", "location", str),
        ("Enter total capacity (containers):", "total_vps", int),
        ("Enter priority (lower = higher priority):", "priority", int),
        ("Is this a local node? (yes/no):", "is_local", lambda x: x.lower() in ['yes', 'y', 'true']),
    ]
    
    answers = {}
    
    for question, key, converter in questions:
        embed = info_embed("Node Creation", question)
        msg = await ctx.send(embed=embed)
        
        try:
            response = await bot.wait_for(
                'message',
                check=lambda m: m.author == ctx.author and m.channel == ctx.channel,
                timeout=60
            )
            
            answers[key] = converter(response.content.strip())
            await msg.delete()
            await response.delete()
            
        except asyncio.TimeoutError:
            await msg.edit(embed=error_embed("Timeout", "Node creation cancelled due to timeout."))
            return
    
    # For remote nodes, ask for URL and generate API key
    if not answers.get('is_local', False):
        embed = info_embed("Node Creation", "Enter node URL (e.g., http://192.168.1.100:5000):")
        msg = await ctx.send(embed=embed)
        
        try:
            response = await bot.wait_for(
                'message',
                check=lambda m: m.author == ctx.author and m.channel == ctx.channel,
                timeout=60
            )
            
            answers['url'] = response.content.strip()
            answers['api_key'] = secrets.token_urlsafe(32)
            
            await msg.delete()
            await response.delete()
            
        except asyncio.TimeoutError:
            await msg.edit(embed=error_embed("Timeout", "Node creation cancelled due to timeout."))
            return
    else:
        answers['url'] = None
        answers['api_key'] = None
    
    # Ask for tags
    embed = info_embed("Node Creation", "Enter tags (comma separated, or leave empty):")
    msg = await ctx.send(embed=embed)
    
    try:
        response = await bot.wait_for(
            'message',
            check=lambda m: m.author == ctx.author and m.channel == ctx.channel,
            timeout=60
        )
        
        tags = [tag.strip() for tag in response.content.strip().split(',') if tag.strip()]
        answers['tags'] = json.dumps(tags)
        
        await msg.delete()
        await response.delete()
        
    except asyncio.TimeoutError:
        answers['tags'] = '[]'
    
    # Create node in database
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO nodes (name, location, total_vps, priority, is_local, url, api_key, tags)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            answers['name'], answers['location'], answers['total_vps'],
            answers['priority'], int(answers['is_local']), answers['url'],
            answers['api_key'], answers['tags']
        ))
        
        node_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Success embed
        embed = success_embed(
            "Node Created",
            f"Node **{answers['name']}** created successfully with ID: {node_id}"
        )
        
        if not answers['is_local']:
            embed.add_field(
                name="Setup Instructions",
                value=(
                    f"1. Install ZynexForge Node Agent on the server\n"
                    f"2. Run: `python node_agent.py --api_key {answers['api_key']} --port {answers['url'].split(':')[-1] if answers['url'] else '5000'}`\n"
                    f"3. Ensure the server is accessible from this bot"
                ),
                inline=False
            )
        
        await ctx.send(embed=embed)
        
    except Exception as e:
        logger.error(f"Failed to create node: {e}")
        embed = error_embed(
            "Creation Failed",
            f"Failed to create node: {str(e)}"
        )
        await ctx.send(embed=embed)

# ========== FLASK API FOR NODE AGENT ==========
app = Flask(__name__)

@app.route('/api/ping', methods=['GET'])
def api_ping():
    """Health check endpoint"""
    api_key = request.args.get('api_key')
    
    # Validate API key
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM nodes WHERE api_key = ?', (api_key,))
    node = cursor.fetchone()
    conn.close()
    
    if not node:
        return jsonify({"error": "Invalid API key"}), 401
    
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()}), 200

@app.route('/api/execute', methods=['POST'])
def api_execute():
    """Execute LXC command"""
    api_key = request.args.get('api_key')
    
    # Validate API key
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM nodes WHERE api_key = ?', (api_key,))
    node = cursor.fetchone()
    conn.close()
    
    if not node:
        return jsonify({"error": "Invalid API key"}), 401
    
    try:
        data = request.get_json()
        if not data or 'command' not in data:
            return jsonify({"error": "Missing 'command' in JSON body"}), 400
        
        command = data['command']
        timeout = data.get('timeout', 120)
        
        # Execute command
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        return jsonify({
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }), 200
        
    except subprocess.TimeoutExpired:
        return jsonify({
            "returncode": 124,
            "stdout": "",
            "stderr": "Command timed out"
        }), 408
        
    except Exception as e:
        return jsonify({
            "returncode": 1,
            "stdout": "",
            "stderr": str(e)
        }), 500

@app.route('/api/get_host_stats', methods=['GET'])
def api_get_host_stats():
    """Get host statistics"""
    api_key = request.args.get('api_key')
    
    # Validate API key
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM nodes WHERE api_key = ?', (api_key,))
    node = cursor.fetchone()
    conn.close()
    
    if not node:
        return jsonify({"error": "Invalid API key"}), 401
    
    try:
        # Get CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Get RAM usage
        ram = psutil.virtual_memory()
        ram_percent = ram.percent
        ram_total = ram.total / (1024 ** 3)  # GB
        ram_used = ram.used / (1024 ** 3)    # GB
        
        # Get disk usage
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent
        disk_total = disk.total / (1024 ** 3)  # GB
        disk_used = disk.used / (1024 ** 3)    # GB
        
        # Get uptime
        uptime = str(datetime.now() - datetime.fromtimestamp(psutil.boot_time())).split('.')[0]
        
        # Get load average
        load_avg = psutil.getloadavg()
        
        return jsonify({
            "cpu": cpu_percent,
            "ram": ram_percent,
            "ram_total": round(ram_total, 2),
            "ram_used": round(ram_used, 2),
            "disk": disk_percent,
            "disk_total": round(disk_total, 2),
            "disk_used": round(disk_used, 2),
            "uptime": uptime,
            "load_avg": load_avg
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def run_flask():
    """Run Flask app in a separate thread"""
    app.run(host=HOST, port=PORT, debug=False, threaded=True, use_reloader=False)

# ========== MAIN ENTRY POINT ==========
def main():
    """Main entry point"""
    # Check if Discord token is provided
    if not DISCORD_TOKEN:
        logger.error("No Discord token provided. Set DISCORD_TOKEN environment variable.")
        sys.exit(1)
    
    # Create necessary directories
    os.makedirs('logs', exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)
    
    # Initialize database
    init_database()
    
    # Start Flask API in a separate thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    
    logger.info(f"Flask API started on {HOST}:{PORT}")
    
    # Run Discord bot
    try:
        bot.run(DISCORD_TOKEN)
    except Exception as e:
        logger.error(f"Failed to start bot: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()