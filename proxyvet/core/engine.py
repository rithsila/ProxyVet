import asyncio
from datetime import datetime, timezone
from typing import List
from proxyvet.core.models import Verdict, VerdictResult, IPSignalData, ASNType
from proxyvet.core.cache import CacheManager
from proxyvet.core.config import Settings
from proxyvet.core.checkers.base import BaseChecker

class VerdictEngine:
    def __init__(self, settings: Settings, cache_mgr: CacheManager, checkers: List[BaseChecker]):
        self.settings = settings
        self.cache_mgr = cache_mgr
        self.checkers = checkers

    def evaluate_signals(self, ip: str, signals: List[IPSignalData]) -> VerdictResult:
        reasons = []
        is_burned = False
        
        # 1. Evaluate Hard Gates
        tor_hit = any(sig.is_tor is True for sig in signals)
        if tor_hit:
            is_burned = True
            reasons.append("Tor exit node detected")

        proxy_vpn_sources = [sig.source for sig in signals if sig.is_proxy is True or sig.is_vpn is True]
        if len(proxy_vpn_sources) >= 2:
            is_burned = True
            reasons.append(f"Flagged as proxy/VPN by multiple sources: {', '.join(proxy_vpn_sources)}")

        dnsbl_hits = sum(sig.dnsbl_hits for sig in signals if sig.dnsbl_hits and sig.dnsbl_hits > 0)
        if dnsbl_hits >= 1:
            is_burned = True
            reasons.append(f"Listed on {dnsbl_hits} spam blocklist(s)")

        for sig in signals:
            if sig.abuse_score is not None and sig.abuse_score >= 90:
                is_burned = True
                reasons.append(f"Severe abuse score of {sig.abuse_score}% from {sig.source}")

        if is_burned:
            return VerdictResult(
                ip=ip,
                verdict=Verdict.BURNED,
                composite_score=100.0,
                reasons=reasons,
                signals=signals,
                checked_at=datetime.now(timezone.utc)
            )

        # 2. Evaluate Soft Score
        score = 0.0
        asn_types = [sig.asn_type for sig in signals if sig.asn_type != ASNType.UNKNOWN]
        
        if ASNType.DATACENTER in asn_types:
            score += 50.0
            reasons.append("Datacenter ASN detected (+50)")
        elif ASNType.BUSINESS in asn_types:
            score += 15.0
            reasons.append("Business ASN detected (+15)")
        elif ASNType.MOBILE in asn_types:
            score -= 10.0
            reasons.append("Mobile ASN trust bonus (-10)")

        # Single source proxy/VPN flag
        if len(proxy_vpn_sources) == 1:
            score += 30.0
            reasons.append(f"Suspicious: flagged as proxy/VPN by a single source ({proxy_vpn_sources[0]}) (+30)")

        # Abuse score contribution
        abuse_scores = [sig.abuse_score for sig in signals if sig.abuse_score is not None]
        if abuse_scores:
            max_abuse = max(abuse_scores)
            abuse_contrib = 0.4 * max_abuse
            if abuse_contrib > 0:
                score += abuse_contrib
                reasons.append(f"Abuse reputation contribution (+{abuse_contrib:.1f})")

        # Disagreement penalty
        if len(set(asn_types)) > 1:
            score += 10.0
            reasons.append("Source ASN classification mismatch (+10)")

        composite_score = max(0.0, min(100.0, score))
        
        if composite_score >= 60.0:
            verdict = Verdict.BURNED
        elif composite_score > 25.0:
            verdict = Verdict.CAUTION
        else:
            verdict = Verdict.CLEAN

        if not reasons:
            reasons.append("No suspicious flags raised")

        return VerdictResult(
            ip=ip,
            verdict=verdict,
            composite_score=composite_score,
            reasons=reasons,
            signals=signals,
            checked_at=datetime.now(timezone.utc)
        )

    async def vet_ip(self, ip: str, force_refresh: bool = False) -> VerdictResult:
        # Step A: Collect Signals (Check cache first unless forced)
        async def get_signal(checker: BaseChecker) -> IPSignalData:
            if not force_refresh:
                cached = self.cache_mgr.get_cached_signal(ip, checker.name, checker.cache_ttl_hours)
                if cached:
                    return cached
            fresh = await checker.check(ip)
            self.cache_mgr.save_cached_signal(fresh)
            return fresh

        tasks = [get_signal(c) for c in self.checkers]
        signals = list(await asyncio.gather(*tasks))

        # Step B: Evaluate Verdict
        result = self.evaluate_signals(ip, signals)

        # Step C: Load History & Check Drift
        history = self.cache_mgr.get_history(ip)
        if history:
            prev = history[0]
            result.previous_verdict = Verdict(prev["verdict"])
            result.previous_score = prev["composite_score"]
            if result.previous_verdict != result.verdict:
                result.drift_detected = True

        # Step D: Save History
        self.cache_mgr.save_history(result)
        return result
