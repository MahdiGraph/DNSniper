#!/usr/bin/env python3
"""
DNSniper CLI - Command Line Interface

Provides full DNSniper functionality through the command line using the same
business logic as the web interface. All operations use the controller layer
for consistent behavior and validation.
"""

import sys
import os
import asyncio
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List
import functools

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich.json import JSON

# Add the backend directory to the Python path
sys.path.insert(0, str(Path(__file__).parent))

from database import SessionLocal
from version import VERSION, APP_NAME
import controller

# Initialize Rich console for beautiful output
console = Console()

class ChoiceWithExamples(click.Choice):
    """Custom Choice class that provides helpful examples in error messages"""
    
    def __init__(self, choices, case_sensitive=True, examples=None):
        super().__init__(choices, case_sensitive)
        self.examples = examples or {}
    
    def convert(self, value, param, ctx):
        try:
            return super().convert(value, param, ctx)
        except click.BadParameter:
            # Show helpful error message with examples
            console.print(f"\n[red]Error: Invalid value '{value}' for {param.human_readable_name}[/red]")
            console.print(f"[yellow]Valid options:[/yellow] {', '.join(self.choices)}")
            
            # Show examples based on parameter name
            param_name = param.name if param else "parameter"
            if param_name in self.examples:
                console.print(f"[cyan]Example:[/cyan] {self.examples[param_name]}")
            elif 'list-type' in param_name or 'list_type' in param_name:
                console.print(f"[cyan]Example:[/cyan] dnsniper-cli domains add example.com --list-type blacklist")
            elif 'format' in param_name:
                console.print(f"[cyan]Example:[/cyan] dnsniper-cli domains list --format json")
            elif 'ip-version' in param_name or 'ip_version' in param_name:
                console.print(f"[cyan]Example:[/cyan] dnsniper-cli ips list --ip-version 4")
            elif 'source-type' in param_name or 'source_type' in param_name:
                console.print(f"[cyan]Example:[/cyan] dnsniper-cli domains list --source-type manual")
            
            # Exit with error
            sys.exit(1)

# Global database session context manager
class DatabaseSession:
    def __enter__(self):
        self.db = SessionLocal()
        return self.db
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.db.rollback()
        self.db.close()

def handle_async(func):
    """Decorator to handle async functions in Click commands"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return asyncio.run(func(*args, **kwargs))
    return wrapper

def format_table(data: List[dict], title: str = None) -> Table:
    """Create a Rich table from list of dictionaries"""
    if not data:
        return Table(title=title or "No data")
    
    table = Table(title=title, show_header=True, header_style="bold magenta")
    
    # Add columns based on first row
    for key in data[0].keys():
        table.add_column(str(key).replace('_', ' ').title())
    
    # Add rows
    for row in data:
        table.add_row(*[str(v) if v is not None else "-" for v in row.values()])
    
    return table

def format_datetime(dt):
    """Format datetime for display"""
    if dt is None:
        return "Never"
    if isinstance(dt, str):
        return dt
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def enhanced_error_handler(ctx, param, value):
    """Enhanced error handler for Click options with helpful examples"""
    def show_choice_examples(param_name, valid_choices):
        """Show examples for choice parameters"""
        console.print(f"\n[red]Error: Invalid value for {param_name}[/red]")
        console.print(f"[yellow]Valid options:[/yellow] {', '.join(valid_choices)}")
        
        # Add specific examples based on parameter type
        if 'list-type' in param_name:
            console.print(f"[cyan]Example:[/cyan] dnsniper-cli domains add example.com --list-type blacklist")
        elif 'format' in param_name:
            console.print(f"[cyan]Example:[/cyan] dnsniper-cli domains list --format json")
        elif 'ip-version' in param_name:
            console.print(f"[cyan]Example:[/cyan] dnsniper-cli ips list --ip-version 4")
        elif 'source-type' in param_name:
            console.print(f"[cyan]Example:[/cyan] dnsniper-cli domains list --source-type manual")
    
    return value

def handle_errors(func):
    """Decorator to handle common errors gracefully with helpful examples"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except click.BadParameter as e:
            console.print(f"[red]Error: {e}[/red]")
            
            # Provide helpful examples based on the error
            if "Invalid value" in str(e):
                if "list-type" in str(e):
                    console.print("[yellow]Valid list types:[/yellow] blacklist, whitelist")
                    console.print("[cyan]Example:[/cyan] dnsniper-cli domains add example.com --list-type blacklist")
                elif "format" in str(e):
                    console.print("[yellow]Valid formats:[/yellow] table, json, value")
                    console.print("[cyan]Example:[/cyan] dnsniper-cli domains list --format json")
                elif "ip-version" in str(e):
                    console.print("[yellow]Valid IP versions:[/yellow] 4, 6")
                    console.print("[cyan]Example:[/cyan] dnsniper-cli ips list --ip-version 4")
                elif "source-type" in str(e):
                    console.print("[yellow]Valid source types:[/yellow] manual, auto_update")
                    console.print("[cyan]Example:[/cyan] dnsniper-cli domains list --source-type manual")
            elif "Missing argument" in str(e):
                console.print("[yellow]Help:[/yellow] Use --help to see required arguments")
                console.print("[cyan]Example:[/cyan] dnsniper-cli domains get 1")
            
            sys.exit(1)
        except click.MissingParameter as e:
            console.print(f"[red]Error: {e}[/red]")
            console.print("[yellow]Help:[/yellow] Required parameters are missing")
            console.print("[cyan]Example:[/cyan] dnsniper-cli domains add example.com --list-type blacklist")
            sys.exit(1)
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            
            # Provide context-specific help
            error_str = str(e).lower()
            if "invalid ip" in error_str:
                console.print("[yellow]Help:[/yellow] Provide a valid IP address")
                console.print("[cyan]Examples:[/cyan]")
                console.print("  IPv4: dnsniper-cli ips add 192.168.1.1 --list-type blacklist")
                console.print("  IPv6: dnsniper-cli ips add 2001:db8::1 --list-type blacklist")
            elif "invalid range" in error_str or "cidr" in error_str:
                console.print("[yellow]Help:[/yellow] Provide a valid CIDR range")
                console.print("[cyan]Examples:[/cyan]")
                console.print("  IPv4: dnsniper-cli ip-ranges add 192.168.1.0/24 --list-type blacklist")
                console.print("  IPv6: dnsniper-cli ip-ranges add 2001:db8::/32 --list-type blacklist")
            elif "domain" in error_str:
                console.print("[yellow]Help:[/yellow] Provide a valid domain name")
                console.print("[cyan]Example:[/cyan] dnsniper-cli domains add example.com --list-type blacklist")
            
            sys.exit(1)
        except Exception as e:
            console.print(f"[red]Unexpected error: {e}[/red]")
            console.print("[yellow]Tip:[/yellow] Use 'dnsniper-cli --help' for usage information")
            sys.exit(1)
    return wrapper

# Main CLI group
@click.group()
@click.version_option(version=VERSION, prog_name=f"{APP_NAME} CLI")
def cli():
    f"""
    🛡️  {APP_NAME} CLI - Firewall Management Command Line Interface
    
    Manage domains, IPs, IP ranges, settings, and more through the command line.
    All operations use the same business logic as the web interface.
    
    \\b
    Quick Examples:
      {APP_NAME.lower()}-cli health                    # Check system health
      {APP_NAME.lower()}-cli domains list              # List all domains
      {APP_NAME.lower()}-cli domains add bad.com --list-type blacklist
      {APP_NAME.lower()}-cli ips add 1.2.3.4 --list-type blacklist
      {APP_NAME.lower()}-cli settings list             # Show all settings
    
    \\b
    Common Usage Patterns:
      {APP_NAME.lower()}-cli domains list --list-type blacklist --search evil
      {APP_NAME.lower()}-cli logs list --hours 12 --action block
      {APP_NAME.lower()}-cli sources trigger           # Manual update
    
    Use '{APP_NAME.lower()}-cli COMMAND --help' for detailed help on any command.
    """
    pass

# =============================================================================
# HEALTH & STATUS COMMANDS
# =============================================================================

def sync_health():
    """Check system health and database connectivity"""
    async def _health():
        with DatabaseSession() as db:
            result = await controller.get_health_check(db)
            
            # Create status panel
            status_text = f"[green]Status: {result['status']}[/green]\n"
            status_text += f"Database: {result['database']}\n"
            status_text += f"Timestamp: {result['timestamp']}\n\n"
            status_text += f"Statistics:\n"
            status_text += f"  Domains: {result['stats']['domains']}\n"
            status_text += f"  IPs: {result['stats']['ips']}\n"
            status_text += f"  IP Ranges: {result['stats']['ip_ranges']}"
            
            console.print(Panel(status_text, title="System Health", border_style="green"))
    
    try:
        asyncio.run(_health())
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        sys.exit(1)

def sync_dashboard():
    """Show comprehensive dashboard statistics"""
    async def _dashboard():
        with DatabaseSession() as db:
            stats = await controller.get_dashboard_statistics(db)
            
            # Create dashboard display
            console.print("\n[bold blue]DNSniper Dashboard[/bold blue]\n")
            
            # Totals
            totals_table = Table(title="Total Counts", show_header=True)
            totals_table.add_column("Type", style="cyan")
            totals_table.add_column("Count", style="green")
            
            for key, value in stats['totals'].items():
                totals_table.add_row(key.replace('_', ' ').title(), str(value))
            
            console.print(totals_table)
            console.print()
            
            # Lists breakdown
            lists_table = Table(title="List Types", show_header=True)
            lists_table.add_column("Type", style="cyan")
            lists_table.add_column("Blacklist", style="red")
            lists_table.add_column("Whitelist", style="green")
            
            lists_table.add_row("Domains", 
                               str(stats['lists']['blacklist']['domains']),
                               str(stats['lists']['whitelist']['domains']))
            lists_table.add_row("IPs", 
                               str(stats['lists']['blacklist']['ips']),
                               str(stats['lists']['whitelist']['ips']))
            lists_table.add_row("IP Ranges", 
                               str(stats['lists']['blacklist']['ip_ranges']),
                               str(stats['lists']['whitelist']['ip_ranges']))
            
            console.print(lists_table)
            console.print()
            
            # Auto-update status
            auto_update = stats['auto_update']
            status_color = "green" if auto_update['enabled'] and auto_update['is_running'] else "yellow"
            status_text = f"[{status_color}]Auto-Update Status[/{status_color}]\n"
            status_text += f"Enabled: {auto_update['enabled']}\n"
            status_text += f"Running: {auto_update['is_running']}\n"
            status_text += f"Active Sources: {auto_update['active_sources']}/{auto_update['total_sources']}"
            
            console.print(Panel(status_text, border_style=status_color))
    
    try:
        asyncio.run(_dashboard())
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        sys.exit(1)

# Create Click commands
health = click.command("health")(sync_health)
dashboard = click.command("dashboard")(sync_dashboard)

# Add commands to CLI group
cli.add_command(health)
cli.add_command(dashboard)

# =============================================================================
# DOMAIN COMMANDS
# =============================================================================

@cli.group()
def domains():
    """
    Manage domains (blacklist/whitelist)
    
    \b
    Examples:
      dnsniper-cli domains list                    # List all domains
      dnsniper-cli domains list --list-type blacklist
      dnsniper-cli domains add example.com --list-type blacklist
      dnsniper-cli domains get 1                   # Get domain details
      dnsniper-cli domains delete 1 --yes          # Delete without confirmation
    """
    pass

@domains.command("list")
@click.option("--list-type", type=ChoiceWithExamples(['blacklist', 'whitelist'], examples={'list-type': 'blacklist, whitelist'}), 
              help="Filter by list type (blacklist or whitelist)")
@click.option("--source-type", type=ChoiceWithExamples(['manual', 'auto_update'], examples={'source-type': 'manual, auto_update'}), 
              help="Filter by source type (manual or auto_update)")
@click.option("--search", help="Search domain names (partial match)")
@click.option("--page", default=1, help="Page number (default: 1)")
@click.option("--per-page", default=50, help="Items per page (default: 50)")
@click.option("--format", "output_format", type=ChoiceWithExamples(['table', 'json'], examples={'format': 'table, json'}), default='table', 
              help="Output format: table (default) or json")
@handle_async
@handle_errors
async def list_domains(list_type, source_type, search, page, per_page, output_format):
    """
    List domains with optional filtering
    
    \b
    Examples:
      dnsniper-cli domains list
      dnsniper-cli domains list --list-type blacklist
      dnsniper-cli domains list --search google --format json
      dnsniper-cli domains list --source-type manual --page 2
    """
    with DatabaseSession() as db:
        result = await controller.get_domains_list(
            db, list_type=list_type, source_type=source_type, 
            search=search, page=page, per_page=per_page
        )
        
        if output_format == 'json':
            console.print(JSON(json.dumps(result, indent=2, default=str)))
        else:
            if result['domains']:
                # Format domains for table display
                table_data = []
                for domain in result['domains']:
                    table_data.append({
                        'ID': domain['id'],
                        'Domain': domain['domain_name'],
                        'Type': domain['list_type'],
                        'Source': domain['source_type'],
                        'IPs': domain['ip_count'],
                        'CDN': '✓' if domain['is_cdn'] else '',
                        'Expires': domain['expires_in'] or 'Never',
                        'Notes': (domain['notes'][:30] + '...') if domain['notes'] and len(domain['notes']) > 30 else (domain['notes'] or '')
                    })
                
                table = format_table(table_data, f"Domains (Page {page}/{result['pages']}, Total: {result['total']})")
                console.print(table)
            else:
                console.print("[yellow]No domains found[/yellow]")
                if list_type or source_type or search:
                    console.print("[dim]Try adjusting your filters or use: dnsniper-cli domains list[/dim]")

@domains.command("get")
@click.argument("domain_id", type=int)
@click.option("--format", "output_format", type=ChoiceWithExamples(['table', 'json'], examples={'format': 'table, json'}), default='table', help="Output format")
@handle_async
@handle_errors
async def get_domain(domain_id, output_format):
    """Get detailed information about a specific domain"""
    with DatabaseSession() as db:
        domain = await controller.get_domain_by_id(db, domain_id)
        
        if output_format == 'json':
            console.print(JSON(json.dumps(domain, indent=2, default=str)))
        else:
            info_text = f"[bold]Domain: {domain['domain_name']}[/bold]\n\n"
            info_text += f"ID: {domain['id']}\n"
            info_text += f"List Type: {domain['list_type']}\n"
            info_text += f"Source: {domain['source_type']}\n"
            info_text += f"IP Count: {domain['ip_count']}\n"
            info_text += f"CDN: {'Yes' if domain['is_cdn'] else 'No'}\n"
            info_text += f"Created: {format_datetime(domain['created_at'])}\n"
            info_text += f"Updated: {format_datetime(domain['updated_at'])}\n"
            if domain['expires_in']:
                info_text += f"Expires: {domain['expires_in']}\n"
            if domain['notes']:
                info_text += f"\nNotes: {domain['notes']}"
            
            console.print(Panel(info_text, title="Domain Details", border_style="blue"))

@domains.command("add")
@click.argument("domain_name")
@click.option("--list-type", type=ChoiceWithExamples(['blacklist', 'whitelist'], examples={'list-type': 'blacklist, whitelist'}), required=True, 
              help="List type: blacklist or whitelist")
@click.option("--notes", help="Optional notes about this domain")
@handle_async
@handle_errors
async def add_domain(domain_name, list_type, notes):
    """
    Add a new domain to blacklist or whitelist
    
    \b
    Examples:
      dnsniper-cli domains add bad-site.com --list-type blacklist
      dnsniper-cli domains add trusted.com --list-type whitelist --notes "Trusted partner"
    """
    with DatabaseSession() as db:
        domain = await controller.create_domain(db, domain_name, list_type, notes)
        console.print(f"[green]✓[/green] Added domain '{domain_name}' to {list_type}")
        console.print(f"Domain ID: {domain['id']}")

@domains.command("update")
@click.argument("domain_id", type=int)
@click.option("--list-type", type=ChoiceWithExamples(['blacklist', 'whitelist'], examples={'list-type': 'blacklist, whitelist'}), help="New list type")
@click.option("--notes", help="New notes")
@handle_async
@handle_errors
async def update_domain(domain_id, list_type, notes):
    """Update an existing domain"""
    with DatabaseSession() as db:
        domain = await controller.update_domain(db, domain_id, list_type, notes)
        console.print(f"[green]✓[/green] Updated domain '{domain['domain_name']}'")

@domains.command("delete")
@click.argument("domain_id", type=int)
@click.option("--yes", is_flag=True, help="Skip confirmation")
@handle_async
@handle_errors
async def delete_domain(domain_id, yes):
    """Delete a domain"""
    with DatabaseSession() as db:
        # Get domain info first
        domain = await controller.get_domain_by_id(db, domain_id)
        
        if not yes:
            if not Confirm.ask(f"Delete domain '{domain['domain_name']}'?"):
                console.print("Cancelled")
                return
        
        result = await controller.delete_domain(db, domain_id)
        console.print(f"[green]✓[/green] {result['message']}")

@domains.command("resolve")
@click.argument("domain_id", type=int)
@handle_async
@handle_errors
async def resolve_domain(domain_id):
    """Manually resolve a domain to update IP mappings"""
    with DatabaseSession() as db:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("Resolving domain...", total=None)
            result = await controller.resolve_domain_manually(db, domain_id)
            progress.update(task, completed=True)
        
        console.print(f"[green]✓[/green] {result['message']}")
        console.print(f"IP Count: {result['ip_count']}")
        console.print(f"CDN: {'Yes' if result['is_cdn'] else 'No'}")
        
        if result['resolution']['ipv4'] or result['resolution']['ipv6']:
            console.print(f"\nResolved IPs:")
            for ip in result['resolution']['ipv4']:
                console.print(f"  IPv4: {ip}")
            for ip in result['resolution']['ipv6']:
                console.print(f"  IPv6: {ip}")

@domains.command("ips")
@click.argument("domain_id", type=int)
@click.option("--format", "output_format", type=ChoiceWithExamples(['table', 'json'], examples={'format': 'table, json'}), default='table', help="Output format")
@handle_async
@handle_errors
async def domain_ips(domain_id, output_format):
    """Show all IPs associated with a domain"""
    with DatabaseSession() as db:
        ips = await controller.get_domain_ips(db, domain_id)
        
        if output_format == 'json':
            console.print(JSON(json.dumps(ips, indent=2, default=str)))
        else:
            if ips:
                table_data = []
                for ip in ips:
                    table_data.append({
                        'ID': ip['id'],
                        'IP Address': ip['ip_address'],
                        'Version': f"IPv{ip['ip_version']}",
                        'Type': ip['list_type'],
                        'Source': ip['source_type'],
                        'Created': format_datetime(ip['created_at'])
                    })
                
                table = format_table(table_data, f"IPs for Domain ID {domain_id}")
                console.print(table)
            else:
                console.print("[yellow]No IPs found for this domain[/yellow]")

# =============================================================================
# IP COMMANDS
# =============================================================================

@cli.group()
def ips():
    """
    Manage IP addresses (blacklist/whitelist)
    
    \b
    Examples:
      dnsniper-cli ips list                        # List all IPs
      dnsniper-cli ips list --ip-version 4         # IPv4 only
      dnsniper-cli ips add 1.2.3.4 --list-type blacklist
      dnsniper-cli ips delete 1 --yes             # Delete without confirmation
    """
    pass

@ips.command("list")
@click.option("--list-type", type=ChoiceWithExamples(['blacklist', 'whitelist'], examples={'list-type': 'blacklist, whitelist'}), help="Filter by list type")
@click.option("--source-type", type=ChoiceWithExamples(['manual', 'auto_update'], examples={'source-type': 'manual, auto_update'}), help="Filter by source type")
@click.option("--ip-version", type=ChoiceWithExamples(['4', '6'], examples={'ip-version': '4, 6'}), help="Filter by IP version")
@click.option("--search", help="Search IP addresses")
@click.option("--page", default=1, help="Page number")
@click.option("--per-page", default=50, help="Items per page")
@click.option("--format", "output_format", type=ChoiceWithExamples(['table', 'json'], examples={'format': 'table, json'}), default='table', help="Output format")
@handle_async
@handle_errors
async def list_ips(list_type, source_type, ip_version, search, page, per_page, output_format):
    """List IP addresses with optional filtering"""
    ip_version_int = int(ip_version) if ip_version else None
    
    with DatabaseSession() as db:
        result = await controller.get_ips_list(
            db, list_type=list_type, source_type=source_type,
            ip_version=ip_version_int, search=search, page=page, per_page=per_page
        )
        
        if output_format == 'json':
            console.print(JSON(json.dumps(result, indent=2, default=str)))
        else:
            if result['ips']:
                table_data = []
                for ip in result['ips']:
                    table_data.append({
                        'ID': ip['id'],
                        'IP Address': ip['ip_address'],
                        'Version': f"IPv{ip['ip_version']}",
                        'Type': ip['list_type'],
                        'Source': ip['source_type'],
                        'Domain': ip['domain_name'] or '-',
                        'Expires': ip['expires_in'] or 'Never',
                        'Notes': (ip['notes'][:20] + '...') if ip['notes'] and len(ip['notes']) > 20 else (ip['notes'] or '')
                    })
                
                table = format_table(table_data, f"IP Addresses (Page {page}/{result['pages']}, Total: {result['total']})")
                console.print(table)
            else:
                console.print("[yellow]No IP addresses found[/yellow]")

@ips.command("add")
@click.argument("ip_address")
@click.option("--list-type", type=ChoiceWithExamples(['blacklist', 'whitelist'], examples={'list-type': 'blacklist, whitelist'}), required=True, 
              help="List type: blacklist or whitelist")
@click.option("--notes", help="Optional notes about this IP")
@handle_async
@handle_errors
async def add_ip(ip_address, list_type, notes):
    """
    Add a new IP address to blacklist or whitelist
    
    \b
    Examples:
      dnsniper-cli ips add 192.168.1.100 --list-type blacklist
      dnsniper-cli ips add 2001:db8::1 --list-type whitelist --notes "Server IP"
    """
    with DatabaseSession() as db:
        ip = await controller.create_ip(db, ip_address, list_type, notes)
        console.print(f"[green]✓[/green] Added IP '{ip_address}' to {list_type}")
        console.print(f"IP ID: {ip['id']}")

@ips.command("update")
@click.argument("ip_id", type=int)
@click.option("--list-type", type=ChoiceWithExamples(['blacklist', 'whitelist'], examples={'list-type': 'blacklist, whitelist'}), help="New list type")
@click.option("--notes", help="New notes")
@handle_async
@handle_errors
async def update_ip(ip_id, list_type, notes):
    """Update an existing IP address"""
    with DatabaseSession() as db:
        ip = await controller.update_ip(db, ip_id, list_type, notes)
        console.print(f"[green]✓[/green] Updated IP '{ip['ip_address']}'")

@ips.command("delete")
@click.argument("ip_id", type=int)
@click.option("--yes", is_flag=True, help="Skip confirmation")
@handle_async
@handle_errors
async def delete_ip(ip_id, yes):
    """Delete an IP address"""
    with DatabaseSession() as db:
        # Get IP list first to show in confirmation
        ips_result = await controller.get_ips_list(db, page=1, per_page=1000)
        ip_info = next((ip for ip in ips_result['ips'] if ip['id'] == ip_id), None)
        
        if not ip_info:
            console.print(f"[red]IP ID {ip_id} not found[/red]")
            return
        
        if not yes:
            if not Confirm.ask(f"Delete IP '{ip_info['ip_address']}'?"):
                console.print("Cancelled")
                return
        
        result = await controller.delete_ip(db, ip_id)
        console.print(f"[green]✓[/green] {result['message']}")

# =============================================================================
# IP RANGE COMMANDS
# =============================================================================

@cli.group()
def ip_ranges():
    """
    Manage IP ranges/CIDR blocks (blacklist/whitelist)
    
    \b
    Examples:
      dnsniper-cli ip-ranges list                 # List all ranges
      dnsniper-cli ip-ranges add 192.168.1.0/24 --list-type blacklist
      dnsniper-cli ip-ranges add 10.0.0.0/8 --list-type whitelist
    """
    pass

@ip_ranges.command("list")
@click.option("--list-type", type=ChoiceWithExamples(['blacklist', 'whitelist'], examples={'list-type': 'blacklist, whitelist'}), help="Filter by list type")
@click.option("--source-type", type=ChoiceWithExamples(['manual', 'auto_update'], examples={'source-type': 'manual, auto_update'}), help="Filter by source type")
@click.option("--ip-version", type=ChoiceWithExamples(['4', '6'], examples={'ip-version': '4, 6'}), help="Filter by IP version")
@click.option("--search", help="Search IP ranges")
@click.option("--page", default=1, help="Page number")
@click.option("--per-page", default=50, help="Items per page")
@click.option("--format", "output_format", type=ChoiceWithExamples(['table', 'json'], examples={'format': 'table, json'}), default='table', help="Output format")
@handle_async
@handle_errors
async def list_ip_ranges(list_type, source_type, ip_version, search, page, per_page, output_format):
    """List IP ranges with optional filtering"""
    ip_version_int = int(ip_version) if ip_version else None
    
    with DatabaseSession() as db:
        result = await controller.get_ip_ranges_list(
            db, list_type=list_type, source_type=source_type,
            ip_version=ip_version_int, search=search, page=page, per_page=per_page
        )
        
        if output_format == 'json':
            console.print(JSON(json.dumps(result, indent=2, default=str)))
        else:
            if result['ip_ranges']:
                table_data = []
                for ip_range in result['ip_ranges']:
                    table_data.append({
                        'ID': ip_range['id'],
                        'IP Range': ip_range['ip_range'],
                        'Version': f"IPv{ip_range['ip_version']}",
                        'Type': ip_range['list_type'],
                        'Source': ip_range['source_type'],
                        'Expires': ip_range['expires_in'] or 'Never',
                        'Notes': (ip_range['notes'][:20] + '...') if ip_range['notes'] and len(ip_range['notes']) > 20 else (ip_range['notes'] or '')
                    })
                
                table = format_table(table_data, f"IP Ranges (Page {page}/{result['pages']}, Total: {result['total']})")
                console.print(table)
            else:
                console.print("[yellow]No IP ranges found[/yellow]")

@ip_ranges.command("add")
@click.argument("ip_range")
@click.option("--list-type", type=ChoiceWithExamples(['blacklist', 'whitelist'], examples={'list-type': 'blacklist, whitelist'}), required=True, 
              help="List type: blacklist or whitelist")
@click.option("--notes", help="Optional notes about this IP range")
@handle_async
@handle_errors
async def add_ip_range(ip_range, list_type, notes):
    """
    Add a new IP range/CIDR block to blacklist or whitelist
    
    \b
    Examples:
      dnsniper-cli ip-ranges add 192.168.1.0/24 --list-type blacklist
      dnsniper-cli ip-ranges add 2001:db8::/32 --list-type whitelist --notes "IPv6 range"
    """
    with DatabaseSession() as db:
        range_obj = await controller.create_ip_range(db, ip_range, list_type, notes)
        console.print(f"[green]✓[/green] Added IP range '{ip_range}' to {list_type}")
        console.print(f"Range ID: {range_obj['id']}")

@ip_ranges.command("update")
@click.argument("range_id", type=int)
@click.option("--list-type", type=ChoiceWithExamples(['blacklist', 'whitelist'], examples={'list-type': 'blacklist, whitelist'}), help="New list type")
@click.option("--notes", help="New notes")
@handle_async
@handle_errors
async def update_ip_range(range_id, list_type, notes):
    """Update an existing IP range"""
    with DatabaseSession() as db:
        ip_range = await controller.update_ip_range(db, range_id, list_type, notes)
        console.print(f"[green]✓[/green] Updated IP range '{ip_range['ip_range']}'")

@ip_ranges.command("delete")
@click.argument("range_id", type=int)
@click.option("--yes", is_flag=True, help="Skip confirmation")
@handle_async
@handle_errors
async def delete_ip_range(range_id, yes):
    """Delete an IP range"""
    with DatabaseSession() as db:
        # Get range info first
        ip_range = await controller.get_ip_range_by_id(db, range_id)
        
        if not yes:
            if not Confirm.ask(f"Delete IP range '{ip_range['ip_range']}'?"):
                console.print("Cancelled")
                return
        
        result = await controller.delete_ip_range(db, range_id)
        console.print(f"[green]✓[/green] {result['message']}")

# =============================================================================
# SETTINGS COMMANDS
# =============================================================================

@cli.group()
def settings():
    """
    Manage DNSniper settings and configuration
    
    \b
    Examples:
      dnsniper-cli settings list                  # Show all settings
      dnsniper-cli settings get auto_update_enabled
      dnsniper-cli settings set auto_update_enabled true
      dnsniper-cli settings firewall-status       # Check firewall
    """
    pass

@settings.command("list")
@click.option("--format", "output_format", type=ChoiceWithExamples(['table', 'json'], examples={'format': 'table, json'}), default='table', help="Output format")
@handle_async
@handle_errors
async def list_settings(output_format):
    """List all settings"""
    with DatabaseSession() as db:
        settings_dict = await controller.get_all_settings(db)
        
        if output_format == 'json':
            console.print(JSON(json.dumps(settings_dict, indent=2, default=str)))
        else:
            table_data = []
            for key, value in settings_dict.items():
                # Format value for display
                if isinstance(value, bool):
                    display_value = "✓" if value else "✗"
                elif isinstance(value, list):
                    display_value = f"[{len(value)} items]"
                else:
                    display_value = str(value)
                    if len(display_value) > 50:
                        display_value = display_value[:47] + "..."
                
                table_data.append({
                    'Setting': key.replace('_', ' ').title(),
                    'Value': display_value,
                    'Key': key
                })
            
            table = format_table(table_data, "DNSniper Settings")
            console.print(table)

@settings.command("get")
@click.argument("key")
@click.option("--format", "output_format", type=ChoiceWithExamples(['value', 'json'], examples={'format': 'value, json'}), default='value', help="Output format")
@handle_async
@handle_errors
async def get_setting(key, output_format):
    """Get a specific setting value"""
    with DatabaseSession() as db:
        setting = await controller.get_setting_by_key(db, key)
        
        if output_format == 'json':
            console.print(JSON(json.dumps(setting, indent=2, default=str)))
        else:
            console.print(setting['value'])

@settings.command("set")
@click.argument("key")
@click.argument("value")
@handle_async
@handle_errors
async def set_setting(key, value):
    """Set a setting value"""
    with DatabaseSession() as db:
        # Try to parse JSON for complex values
        try:
            if value.lower() in ('true', 'false'):
                parsed_value = value.lower() == 'true'
            elif value.isdigit():
                parsed_value = int(value)
            elif '.' in value and value.replace('.', '').isdigit():
                parsed_value = float(value)
            elif value.startswith('[') and value.endswith(']'):
                parsed_value = json.loads(value)
            else:
                parsed_value = value
        except:
            parsed_value = value
        
        result = await controller.update_setting(db, key, parsed_value)
        console.print(f"[green]✓[/green] {result['message']}")
        
        if result.get('ssl_restart_required'):
            console.print("[yellow]⚠ SSL restart required - please restart the server[/yellow]")
        if result.get('scheduler_notified'):
            console.print("[blue]ℹ Scheduler notified of changes[/blue]")

@settings.command("firewall-status")
@handle_async
@handle_errors
async def firewall_status():
    """Show firewall status"""
    status = await controller.get_firewall_status()
    
    status_text = "[bold]Firewall Status[/bold]\n\n"
    
    chains = status.get('chains_exist', {})
    status_text += f"IPv4 Chains: {'✓' if chains.get('ipv4') else '✗'}\n"
    status_text += f"IPv6 Chains: {'✓' if chains.get('ipv6') else '✗'}\n"
    
    console.print(Panel(status_text, border_style="blue"))

@settings.command("firewall-rebuild")
@click.option("--yes", is_flag=True, help="Skip confirmation")
@handle_async
@handle_errors
async def firewall_rebuild(yes):
    """Rebuild firewall rules from database"""
    if not yes:
        if not Confirm.ask("Rebuild all firewall rules from database?"):
            console.print("Cancelled")
            return
    
    with DatabaseSession() as db:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("Rebuilding firewall rules...", total=None)
            result = await controller.rebuild_firewall_rules(db)
            progress.update(task, completed=True)
        
        console.print(f"[green]✓[/green] {result['message']}")

@settings.command("firewall-clear")
@click.option("--yes", is_flag=True, help="Skip confirmation")
@handle_async
@handle_errors
async def firewall_clear(yes):
    """Clear all DNSniper firewall rules"""
    if not yes:
        if not Confirm.ask("Clear ALL DNSniper firewall rules?", default=False):
            console.print("Cancelled")
            return
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        task = progress.add_task("Clearing firewall rules...", total=None)
        result = await controller.clear_firewall_rules()
        progress.update(task, completed=True)
    
    console.print(f"[green]✓[/green] {result['message']}")

# =============================================================================
# LOG COMMANDS
# =============================================================================

@cli.group()
def logs():
    """
    View and manage system logs
    
    \b
    Examples:
      dnsniper-cli logs list                      # Recent logs
      dnsniper-cli logs list --action block --hours 12
      dnsniper-cli logs stats                     # Statistics
      dnsniper-cli logs cleanup --days 30 --yes   # Clean old logs
    """
    pass

@logs.command("list")
@click.option("--action", help="Filter by action type")
@click.option("--rule-type", help="Filter by rule type")
@click.option("--ip-address", help="Filter by IP address")
@click.option("--domain-name", help="Filter by domain name")
@click.option("--hours", default=24, help="Hours of history to fetch")
@click.option("--page", default=1, help="Page number")
@click.option("--per-page", default=50, help="Items per page")
@click.option("--format", "output_format", type=ChoiceWithExamples(['table', 'json'], examples={'format': 'table, json'}), default='table', help="Output format")
@handle_async
@handle_errors
async def list_logs(action, rule_type, ip_address, domain_name, hours, page, per_page, output_format):
    """List system logs with filtering"""
    with DatabaseSession() as db:
        result = await controller.get_logs_list(
            db, action=action, rule_type=rule_type, ip_address=ip_address,
            domain_name=domain_name, hours=hours, page=page, per_page=per_page
        )
        
        if output_format == 'json':
            console.print(JSON(json.dumps(result, indent=2, default=str)))
        else:
            if result['logs']:
                table_data = []
                for log in result['logs']:
                    table_data.append({
                        'ID': log['id'],
                        'Time': format_datetime(log['created_at']),
                        'Action': log['action'] or '-',
                        'Type': log['rule_type'] or '-',
                        'IP': log['ip_address'] or '-',
                        'Domain': log['domain_name'] or '-',
                        'Message': (log['message'][:50] + '...') if len(log['message']) > 50 else log['message']
                    })
                
                table = format_table(table_data, f"System Logs (Page {page}/{result['pages']}, Total: {result['total']})")
                console.print(table)
            else:
                console.print("[yellow]No logs found[/yellow]")

@logs.command("stats")
@click.option("--hours", default=24, help="Hours of statistics to calculate")
@handle_async
@handle_errors
async def log_stats(hours):
    """Show log statistics"""
    with DatabaseSession() as db:
        stats = await controller.get_log_statistics(db, hours)
        
        console.print(f"\n[bold blue]Log Statistics (Last {hours} hours)[/bold blue]\n")
        
        # General stats
        general_table = Table(title="General Statistics")
        general_table.add_column("Metric", style="cyan")
        general_table.add_column("Count", style="green")
        
        general_table.add_row("Total Logs", str(stats['total_logs']))
        general_table.add_row(f"Recent Logs ({hours}h)", str(stats['recent_logs_24h']))
        general_table.add_row("Recent Blocks", str(stats['recent_blocks']))
        general_table.add_row("Recent Allows", str(stats['recent_allows']))
        
        console.print(general_table)
        console.print()
        
        # Actions breakdown
        if any(stats['logs_by_action'].values()):
            actions_table = Table(title="Actions Breakdown")
            actions_table.add_column("Action", style="cyan")
            actions_table.add_column("Count", style="green")
            
            for action, count in stats['logs_by_action'].items():
                if count > 0:
                    actions_table.add_row(action.title(), str(count))
            
            console.print(actions_table)

@logs.command("cleanup")
@click.option("--days", type=int, help="Delete logs older than X days")
@click.option("--keep-count", type=int, help="Keep only X most recent logs")
@click.option("--yes", is_flag=True, help="Skip confirmation")
@handle_async
@handle_errors
async def cleanup_logs(days, keep_count, yes):
    """
    Clean up old logs
    
    \b
    Examples:
      dnsniper-cli logs cleanup --days 30         # Delete logs older than 30 days
      dnsniper-cli logs cleanup --keep-count 1000 # Keep only 1000 recent logs
      dnsniper-cli logs cleanup --days 7 --yes    # Delete without confirmation
    """
    if not days and not keep_count:
        console.print("[red]Error: Must specify either --days or --keep-count[/red]")
        console.print("[yellow]Examples:[/yellow]")
        console.print("  dnsniper-cli logs cleanup --days 30")
        console.print("  dnsniper-cli logs cleanup --keep-count 1000")
        return
    
    if not yes:
        if days:
            if not Confirm.ask(f"Delete all logs older than {days} days?"):
                console.print("Cancelled")
                return
        else:
            if not Confirm.ask(f"Keep only the {keep_count} most recent logs?"):
                console.print("Cancelled")
                return
    
    with DatabaseSession() as db:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("Cleaning up logs...", total=None)
            result = await controller.cleanup_old_logs(db, days, keep_count)
            progress.update(task, completed=True)
        
        console.print(f"[green]✓[/green] {result['message']}")

# =============================================================================
# AUTO-UPDATE SOURCES COMMANDS
# =============================================================================

@cli.group()
def sources():
    """
    Manage auto-update sources
    
    \b
    Examples:
      dnsniper-cli sources list                   # List all sources
      dnsniper-cli sources status                 # Update status
      dnsniper-cli sources add "Malware List" "https://example.com/list.txt"
      dnsniper-cli sources trigger               # Manual update
    """
    pass

@sources.command("list")
@click.option("--format", "output_format", type=ChoiceWithExamples(['table', 'json'], examples={'format': 'table, json'}), default='table', help="Output format")
@handle_async
@handle_errors
async def list_sources(output_format):
    """List all auto-update sources"""
    with DatabaseSession() as db:
        sources_list = await controller.get_auto_update_sources_list(db)
        
        if output_format == 'json':
            console.print(JSON(json.dumps([{
                'id': s.id, 'name': s.name, 'url': s.url, 'is_active': s.is_active,
                'list_type': s.list_type, 'last_update': s.last_update,
                'update_count': s.update_count, 'last_error': s.last_error
            } for s in sources_list], indent=2, default=str)))
        else:
            if sources_list:
                table_data = []
                for source in sources_list:
                    table_data.append({
                        'ID': source.id,
                        'Name': source.name,
                        'URL': source.url[:40] + '...' if len(source.url) > 40 else source.url,
                        'Type': source.list_type,
                        'Active': '✓' if source.is_active else '✗',
                        'Updates': source.update_count,
                        'Last Update': format_datetime(source.last_update),
                        'Error': '✓' if source.last_error else ''
                    })
                
                table = format_table(table_data, "Auto-Update Sources")
                console.print(table)
            else:
                console.print("[yellow]No auto-update sources found[/yellow]")

@sources.command("status")
@handle_async
@handle_errors
async def sources_status():
    """Show auto-update status"""
    with DatabaseSession() as db:
        status = await controller.get_auto_update_status(db)
        
        status_text = f"[bold]Auto-Update Status[/bold]\n\n"
        status_text += f"Enabled: {'✓' if status['enabled'] else '✗'}\n"
        status_text += f"Running: {'✓' if status['is_running'] else '✗'}\n"
        status_text += f"Active Sources: {status['active_sources']}/{status['total_sources']}\n"
        status_text += f"Interval: {status['interval']} seconds\n"
        
        if status['start_time']:
            status_text += f"Started: {format_datetime(status['start_time'])}\n"
        if status['thread_id']:
            status_text += f"Thread ID: {status['thread_id']}\n"
        
        color = "green" if status['enabled'] and status['is_running'] else "yellow"
        console.print(Panel(status_text, border_style=color))

@sources.command("add")
@click.argument("name")
@click.argument("url")
@click.option("--list-type", type=ChoiceWithExamples(['blacklist', 'whitelist'], examples={'list-type': 'blacklist, whitelist'}), default='blacklist', help="List type")
@click.option("--active/--inactive", default=True, help="Whether source is active")
@handle_async
@handle_errors
async def add_source(name, url, list_type, active):
    """Add a new auto-update source"""
    with DatabaseSession() as db:
        source = await controller.create_auto_update_source(db, name, url, active, list_type)
        console.print(f"[green]✓[/green] Added auto-update source '{name}'")
        console.print(f"Source ID: {source.id}")

@sources.command("update")
@click.argument("source_id", type=int)
@click.option("--name", help="New name")
@click.option("--url", help="New URL")
@click.option("--list-type", type=ChoiceWithExamples(['blacklist', 'whitelist'], examples={'list-type': 'blacklist, whitelist'}), help="New list type")
@click.option("--active/--inactive", help="Set active status")
@handle_async
@handle_errors
async def update_source(source_id, name, url, list_type, active):
    """Update an existing auto-update source"""
    with DatabaseSession() as db:
        source = await controller.update_auto_update_source(db, source_id, name, url, active, list_type)
        console.print(f"[green]✓[/green] Updated auto-update source '{source.name}'")

@sources.command("delete")
@click.argument("source_id", type=int)
@click.option("--yes", is_flag=True, help="Skip confirmation")
@handle_async
@handle_errors
async def delete_source(source_id, yes):
    """Delete an auto-update source"""
    with DatabaseSession() as db:
        # Get source info first
        source = await controller.get_auto_update_source_by_id(db, source_id)
        
        if not yes:
            if not Confirm.ask(f"Delete auto-update source '{source.name}'?"):
                console.print("Cancelled")
                return
        
        result = await controller.delete_auto_update_source(db, source_id)
        console.print(f"[green]✓[/green] {result['message']}")

@sources.command("trigger")
@handle_async
@handle_errors
async def trigger_update():
    """Manually trigger an auto-update cycle"""
    with DatabaseSession() as db:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("Triggering auto-update...", total=None)
            result = await controller.trigger_auto_update(db)
            progress.update(task, completed=True)
        
        console.print(f"[green]✓[/green] {result['message']}")
        if result.get('thread_id'):
            console.print(f"Thread ID: {result['thread_id']}")

@sources.command("stop")
@handle_async
@handle_errors
async def stop_update():
    """Stop the currently running auto-update cycle"""
    with DatabaseSession() as db:
        result = await controller.stop_auto_update(db)
        console.print(f"[green]✓[/green] {result['message']}")

# =============================================================================
# DATA MANAGEMENT COMMANDS
# =============================================================================

@cli.command("clear-all")
@click.option("--yes", is_flag=True, help="Skip confirmation")
@handle_async
@handle_errors
async def clear_all(yes):
    """
    Clear all domains, IPs, and IP ranges from the database
    
    ⚠️  WARNING: This action cannot be undone!
    
    \b
    Example:
      dnsniper-cli clear-all --yes    # Skip confirmation prompts
    """
    if not yes:
        console.print("[red]⚠ WARNING: This will delete ALL domains, IPs, and IP ranges![/red]")
        if not Confirm.ask("Are you sure you want to continue?", default=False):
            console.print("Cancelled")
            return
        if not Confirm.ask("This action cannot be undone. Continue?", default=False):
            console.print("Cancelled")
            return
    
    with DatabaseSession() as db:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("Clearing all data...", total=None)
            result = await controller.clear_all_database_data(db)
            progress.update(task, completed=True)
        
        console.print(f"[green]✓[/green] {result['message']}")
        console.print(f"Cleared: {result['cleared']['total']} total items")
        console.print(f"  Domains: {result['cleared']['domains']}")
        console.print(f"  IPs: {result['cleared']['ips']}")
        console.print(f"  IP Ranges: {result['cleared']['ip_ranges']}")

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

# Ensure commands are properly registered
if 'health' not in cli.commands:
    cli.add_command(health)
if 'dashboard' not in cli.commands:
    cli.add_command(dashboard)

if __name__ == "__main__":
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        console.print("[dim]Use 'dnsniper-cli --help' for usage information[/dim]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Unexpected error: {e}[/red]")
        console.print("[yellow]Tip:[/yellow] Use 'dnsniper-cli --help' for usage information")
        sys.exit(1) 