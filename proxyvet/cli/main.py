import typer
import asyncio
import os
import httpx
import ipaddress
from typing import Optional
from proxyvet.core.config import get_settings
from proxyvet.core.cache import CacheManager
from proxyvet.core.engine import VerdictEngine
from proxyvet.core.checkers.maxmind import MaxMindChecker
from proxyvet.core.checkers.ip2proxy import IP2ProxyChecker
from proxyvet.core.checkers.dnsbl import DNSBLChecker
from proxyvet.core.checkers.abuseipdb import AbuseIPDBChecker
from proxyvet.core.checkers.proxycheck import ProxyCheckChecker
from proxyvet.core.checkers.stopforumspam import StopForumSpamChecker

app = typer.Typer(help="ProxyVet - IP Quality Vetting Tool")

def get_engine(client: Optional[httpx.AsyncClient] = None) -> VerdictEngine:
    settings = get_settings()
    cache_mgr = CacheManager(settings.sqlite_db_path)

    checkers = [
        MaxMindChecker(settings.maxmind_db_path),
        IP2ProxyChecker(settings.ip2proxy_db_path),
        DNSBLChecker(),
        AbuseIPDBChecker(settings.abuseipdb_api_key, client=client),
        ProxyCheckChecker(settings.proxycheck_api_key, client=client),
        StopForumSpamChecker(client=client)
    ]
    return VerdictEngine(settings, cache_mgr, checkers)

def format_single_result_table(ip: str, verdict: str, score: float, reasons: list[str]) -> str:
    rows = [
        ("IP", ip),
        ("Verdict", verdict),
        ("Composite Score", f"{score:.1f}/100.0"),
    ]
    # Handle reasons
    if not reasons:
        rows.append(("Reasons", "None"))
    else:
        rows.append(("Reasons", f"- {reasons[0]}"))
        for r in reasons[1:]:
            rows.append(("", f"- {r}"))
            
    # Calculate widths
    col1_w = max(len(r[0]) for r in rows) + 2
    col2_w = max(len(r[1]) for r in rows) + 2
    
    # Border line
    border = f"+{'-' * col1_w}+{'-' * col2_w}+"
    
    lines = [border]
    # Header
    lines.append(f"| {'Field':<{col1_w-2}} | {'Value':<{col2_w-2}} |")
    lines.append(border)
    for field, val in rows:
        lines.append(f"| {field:<{col1_w-2}} | {val:<{col2_w-2}} |")
    lines.append(border)
    return "\n".join(lines)

@app.command()
def check(
    ip: str,
    force_refresh: bool = typer.Option(False, "--force", "-f", help="Bypass cache"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON")
):
    """Vet a single IP address."""
    try:
        ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        typer.echo("Error: Invalid IP address format.", err=True)
        raise typer.Exit(code=1)

    settings = get_settings()
    cache_mgr = CacheManager(settings.sqlite_db_path)
    cache_mgr.init_db()

    async def run_check():
        async with httpx.AsyncClient(timeout=10.0) as client:
            engine = get_engine(client=client)
            try:
                return await engine.vet_ip(ip, force_refresh=force_refresh)
            finally:
                for checker in engine.checkers:
                    if hasattr(checker, "close"):
                        checker.close()

    result = asyncio.run(run_check())
    
    if json_output:
        typer.echo(result.model_dump_json())
    else:
        table_str = format_single_result_table(
            ip=result.ip,
            verdict=result.verdict.value,
            score=result.composite_score,
            reasons=result.reasons
        )
        typer.echo(table_str)

        if result.drift_detected:
            typer.echo(f"\n[WARNING] Drift detected! Previous: {result.previous_verdict.value} ({result.previous_score:.1f})")

@app.command()
def batch(
    file_path: str = typer.Argument(..., help="Path to file containing IPs (one per line)"),
    force_refresh: bool = typer.Option(False, "--force", "-f", help="Bypass cache"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON")
):
    """Vet a batch of IPs from a file."""
    settings = get_settings()
    cache_mgr = CacheManager(settings.sqlite_db_path)
    cache_mgr.init_db()

    if not os.path.exists(file_path):
        typer.echo(f"Error: File {file_path} not found.", err=True)
        raise typer.Exit(code=1)

    with open(file_path) as f:
        ips = [line.strip() for line in f if line.strip()]

    if not ips:
        typer.echo("Error: Validation failed. Batch file contains no IPs or only empty lines.", err=True)
        raise typer.Exit(code=1)

    for ip in ips:
        try:
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            typer.echo(f"Error: Invalid IP address format: {ip}", err=True)
            raise typer.Exit(code=1)

    if not json_output:
        typer.echo(f"Vetting {len(ips)} IPs...")
    
    async def run_batch():
        async with httpx.AsyncClient(timeout=10.0) as client:
            engine = get_engine(client=client)
            try:
                tasks = [engine.vet_ip(ip, force_refresh=force_refresh) for ip in ips]
                return await asyncio.gather(*tasks)
            finally:
                for checker in engine.checkers:
                    if hasattr(checker, "close"):
                        checker.close()

    results = asyncio.run(run_batch())
    
    if json_output:
        import json
        json_list = [json.loads(res.model_dump_json()) for res in results]
        typer.echo(json.dumps(json_list))
    else:
        typer.echo("\nBatch Results Summary:")
        typer.echo(f"{'IP':<16} | {'Verdict':<8} | {'Score':<5}")
        typer.echo("-" * 35)
        for res in results:
            typer.echo(f"{res.ip:<16} | {res.verdict.value:<8} | {res.composite_score:>5.1f}")

if __name__ == "__main__":
    app()
