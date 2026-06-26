"""
VEX Risk Scorer — Phase 6

Aggregates all TriageResult objects into a single firmware risk score (0-100).

Formula:
  score = sigmoid( Σ (cvss/10 × epss_weight × kev_mult × vex_weight) / n_affected )

  epss_weight = 1 + min(epss * 10, 4)   → scales 0.01→1.1x, 0.5→6x, 1.0→6x
  kev_mult    = 2.0 for KEV, else 1.0
  vex_weight  = affected=1.0, under_investigation=0.5, fixed=0.1, not_affected=0

Thresholds:
  90-100  CRITICAL
  70-89   HIGH
  40-69   MEDIUM
  10-39   LOW
  0-9     MINIMAL
"""

import math
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .triage_engine import (
    TriageResult, AFFECTED, NOT_AFFECTED, FIXED, UNDER_INVESTIGATION
)

logger = logging.getLogger(__name__)

VEX_WEIGHTS = {
    AFFECTED:            1.00,
    UNDER_INVESTIGATION: 0.50,
    FIXED:               0.10,
    NOT_AFFECTED:        0.00,
}

KEV_MULTIPLIER = 2.0

SCORE_LABELS = [
    (90, "CRITICAL"),
    (70, "HIGH"),
    (40, "MEDIUM"),
    (10, "LOW"),
    (0,  "MINIMAL"),
]


@dataclass
class RiskScore:
    score:              float
    label:              str
    total_findings:     int
    affected_count:     int
    not_affected_count: int
    fixed_count:        int
    under_inv_count:    int
    kev_count:          int
    critical_cvss:      int
    high_cvss:          int
    medium_cvss:        int
    low_cvss:           int
    top_risks:          List[Dict] = field(default_factory=list)
    score_breakdown:    Dict       = field(default_factory=dict)


def calculate_risk_score(
    triage_results: List[TriageResult],
    total_cves:     int = 0,
) -> RiskScore:
    if not triage_results:
        return RiskScore(
            score=0.0, label="MINIMAL", total_findings=0,
            affected_count=0, not_affected_count=0, fixed_count=0,
            under_inv_count=0, kev_count=0,
            critical_cvss=0, high_cvss=0, medium_cvss=0, low_cvss=0,
        )

    affected_count     = sum(1 for r in triage_results if r.vex_status == AFFECTED)
    not_affected_count = sum(1 for r in triage_results if r.vex_status == NOT_AFFECTED)
    fixed_count        = sum(1 for r in triage_results if r.vex_status == FIXED)
    under_inv_count    = sum(1 for r in triage_results if r.vex_status == UNDER_INVESTIGATION)
    kev_count          = sum(1 for r in triage_results if r.is_kev and r.vex_status == AFFECTED)

    critical_cvss = high_cvss = medium_cvss = low_cvss = 0
    weighted_sum  = 0.0
    contributing  = 0

    for r in triage_results:
        vex_w = VEX_WEIGHTS.get(r.vex_status, 0.0)
        if vex_w == 0.0:
            continue

        # Use actual CVSS score from triage result (stored since the fix)
        cvss = (r.cvss_score or 0.0)
        cvss_norm = cvss / 10.0   # 0-1

        # EPSS weight — low probability still counts but is dampened
        epss = (r.epss_score or 0.0)
        epss_weight = 1.0 + min(epss * 8.0, 4.0)   # 0.0→1.0x, 0.5→5x

        kev_mult = KEV_MULTIPLIER if r.is_kev else 1.0
        contribution = cvss_norm * epss_weight * kev_mult * vex_w
        weighted_sum += contribution
        contributing += 1

        # CVSS buckets (affected only)
        if r.vex_status == AFFECTED:
            exp = r.exploitability
            if exp == "critical":   critical_cvss += 1
            elif exp == "high":     high_cvss     += 1
            elif exp == "medium":   medium_cvss   += 1
            else:                   low_cvss      += 1

    # Average contribution per finding, then scale to 0-100
    avg_contrib = weighted_sum / contributing if contributing else 0.0
    # avg_contrib theoretical max ≈ 1.0 * 5.0 * 2.0 * 1.0 = 10.0 (cvss=10, epss=0.5, KEV)
    # We want avg ≈ 0.5 → score ≈ 70 (HIGH) — calibrated sigmoid
    normalized = avg_contrib / 10.0   # 0-1
    score = _sigmoid_scale(normalized)

    # Hard boosts that cannot be softened by averaging
    if critical_cvss >= 5:
        score = max(score, 65.0)   # ≥5 CRITICAL CVEs → at least MEDIUM
    if critical_cvss >= 10:
        score = max(score, 75.0)   # ≥10 CRITICAL → HIGH
    if kev_count > 0:
        score = max(score, 70.0)   # any KEV → at least HIGH

    # Soft per-finding boosts
    score = min(100.0, score + critical_cvss * 0.8 + kev_count * 2.0)
    score = round(score, 1)
    label = _score_to_label(score)

    # Top 5 risks (KEV first, then CVSS desc)
    affected_sorted = sorted(
        [r for r in triage_results if r.vex_status == AFFECTED],
        key=lambda r: (r.is_kev, r.cvss_score or 0, r.epss_score or 0),
        reverse=True,
    )
    top_risks = [
        {
            "cve_id":        r.cve_id,
            "component":     r.component,
            "version":       r.version,
            "exploitability":r.exploitability,
            "cvss_score":    r.cvss_score,
            "epss_score":    round(r.epss_score, 4),
            "is_kev":        r.is_kev,
            "confidence":    round(r.confidence, 2),
            "remediation":   r.remediation,
        }
        for r in affected_sorted[:5]
    ]

    return RiskScore(
        score=score, label=label,
        total_findings=len(triage_results),
        affected_count=affected_count,
        not_affected_count=not_affected_count,
        fixed_count=fixed_count,
        under_inv_count=under_inv_count,
        kev_count=kev_count,
        critical_cvss=critical_cvss,
        high_cvss=high_cvss,
        medium_cvss=medium_cvss,
        low_cvss=low_cvss,
        top_risks=top_risks,
        score_breakdown={
            "affected":            affected_count,
            "not_affected":        not_affected_count,
            "fixed":               fixed_count,
            "under_investigation": under_inv_count,
            "weighted_sum":        round(weighted_sum, 3),
            "avg_contribution":    round(avg_contrib, 4),
            "normalized":          round(normalized, 4),
        },
    )


def _sigmoid_scale(x: float) -> float:
    """Maps [0,1] → [0,95]. x=0.05 → ~30, x=0.15 → ~65, x=0.30 → ~85."""
    if x <= 0:
        return 0.0
    return 95.0 / (1.0 + math.exp(-14.0 * (x - 0.12)))


def _score_to_label(score: float) -> str:
    for threshold, label in SCORE_LABELS:
        if score >= threshold:
            return label
    return "MINIMAL"
