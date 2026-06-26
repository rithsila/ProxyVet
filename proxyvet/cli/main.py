import typer
import asyncio
import os
from typing import Optional
from proxyvet.core.config import get_settings
from proxyvet.core.cache import CacheManager
from proxyvet.core.engine import VerdictEngine
from proxyvet.core.checkers.maxmind import MaxMindChecker
from proxyvet.core.checkers.ip2proxy import IP2ProxyChecker
from proxyvet.core.checkers.dnsbl import DNSBLChecker
from proxyvet.core.checkers.abuseipdb import AbuseIPDBChecker
from proxyvet.core.checkers.proxycheck import ProxyCheckChecker

app = typer.Typer(help="ProxyVet - IP Quality Vetting Tool")

def get_engine() -> VerdictEngine:
    settings = get_settings()
    cache_mgr = CacheManager(settings.sqlite_db_path)
    cache_mgr.init_db()

    checkers = [
        MaxMindChecker(settings.maxmind_db_path),
        IP2ProxyChecker(settings.ip2proxy_db_path),
        DNSBLChecker(),
        AbuseIPDBChecker(settings.abuseipdb_api_key),
        ProxyCheckChecker(settings.proxycheck_api_key)
    ]
    return VerdictEngine(settings, cache_mgr, checkers)

@app.command()
def check(
    ip: str,
    force_refresh: bool = typer.Option(False, "--force", "-f", help="Bypass cache")
):
    """Vet a single IP address."""
    engine = get_engine()
    result = asyncio.run(engine.vet_ip(ip, force_refresh=force_refresh))
    
    typer.echo(f"=== ProxyVet Verdict for {ip} ===")
    typer.echo(f"Verdict:         {result.verdict.value}")
    typer.echo(f"Composite Score: {result.composite_score:.1f}/100.0")
    typer.echo("Reasons:")
    for r in result.reasons:
        typer.echo(f" - {r}")

    if result.drift_detected:
        typer.echo(f"\n[WARNING] Drift detected! Previous: {result.previous_verdict.value} ({result.previous_score:.1f})")

@app.command()
def batch(
    file_path: str = typer.Argument(..., help="Path to file containing IPs (one per line)"),
    force_refresh: bool = typer.Option(False, "--force", "-f", help="Bypass cache")
):
    """Vet a batch of IPs from a file."""
    if not os.path.exists(file_path):
        typer.echo(f"Error: File {file_path} not found.", err=True)
        raise typer.Exit(code=1)

    with open(file_path) as f:
        ips = [line.strip() for line in f if line.strip()]

    engine = get_engine()
    typer.echo(f"Vetting {len(ips)} IPs...")
    
    async def run_batch():
        tasks = [engine.vet_ip(ip, force_refresh=force_refresh) for ip in ips]
        return await asyncio.gather(*tasks)

    results = asyncio.run(run_batch())
    
    typer.echo("\nBatch Results Summary:")
    typer.echo(f"{'IP':<16} | {'Verdict':<8} | {'Score':<5}")
    typer.echo("-" * 35)
    for res in results:
        typer.echo(f"{res.ip:<16} | {res.verdict.value:<8} | {res.composite_score:>5.1f}")

if __name__ == "__main__":
    app()
