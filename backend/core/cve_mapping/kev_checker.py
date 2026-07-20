"""
KEV (Known Exploited Vulnerabilities) checker for CVE mapping.
Downloads and caches the CISA KEV catalog.
"""
import json
import os
import time
import requests
from pathlib import Path
from typing import Set
import logging

logger = logging.getLogger(__name__)

# KEV data locations
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_PATH = Path("/mnt/d/Uni Work/FYP 2 IOT/IIFVDCAS-main/IIFVDCAS-main/data/kev_cache.json")
KEV_CACHE_TTL = 86400  # 24 hours in seconds

# In-memory cache for KEV IDs
_kev_cache: Set[str] = set()
_cache_timestamp: float = 0


def load_kev_catalog() -> Set[str]:
    """
    Load the KEV catalog from cache if fresh, otherwise download from CISA.

    Returns:
        Set of CVE IDs that are known to be exploited in the wild.
    """
    global _kev_cache, _cache_timestamp

    current_time = time.time()

    # Return cached data if still fresh
    if _kev_cache and (current_time - _cache_timestamp) < KEV_CACHE_TTL:
        logger.debug(f"Returning KEV cache from memory ({len(_kev_cache)} entries)")
        return _kev_cache

    # Try to load from disk cache
    if KEV_CACHE_PATH.exists():
        try:
            with open(KEV_CACHE_PATH, 'r') as f:
                cache_data = json.load(f)
                cached_kevs = set(cache_data.get('kev_ids', []))
                cached_timestamp = cache_data.get('timestamp', 0)

                # Check if disk cache is fresh
                if (current_time - cached_timestamp) < KEV_CACHE_TTL:
                    _kev_cache = cached_kevs
                    _cache_timestamp = cached_timestamp
                    logger.info(f"Loaded KEV cache from disk ({len(_kev_cache)} entries)")
                    return _kev_cache
                else:
                    logger.info("Disk KEV cache expired, will download fresh")
        except Exception as e:
            logger.warning(f"Failed to load KEV cache from disk: {e}")

    # Download fresh KEV data from CISA
    try:
        logger.info("Downloading KEV catalog from CISA...")
        response = requests.get(KEV_URL, timeout=30)
        response.raise_for_status()

        data = response.json()
        vulnerabilities = data.get('vulnerabilities', [])

        kev_ids = set()
        for vuln in vulnerabilities:
            cve_id = vuln.get('cveID', '').strip().upper()
            if cve_id:
                kev_ids.add(cve_id)

        # Update caches
        _kev_cache = kev_ids
        _cache_timestamp = current_time

        # Save to disk cache
        cache_data = {
            'kev_ids': list(_kev_cache),
            'timestamp': _cache_timestamp
        }
        KEV_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(KEV_CACHE_PATH, 'w') as f:
            json.dump(cache_data, f, indent=2)

        logger.info(f"Downloaded and cached {len(_kev_cache)} KEV entries from CISA")
        return _kev_cache

    except Exception as e:
        logger.error(f"Failed to download KEV catalog from CISA: {e}")
        # If download fails, return existing cache (even if expired) as fallback
        if _kev_cache:
            logger.warning(f"Returning stale KEV cache ({len(_kev_cache)} entries) due to download failure")
            return _kev_cache
        # No cache available, return empty set
        return set()


def is_kev(cve_id: str) -> bool:
    """
    Check if a given CVE ID is in the KEV catalog.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228")

    Returns:
        True if the CVE is known to be exploited, False otherwise.
    """
    if not cve_id:
        return False

    kev_set = load_kev_catalog()
    normalized_id = cve_id.strip().upper()
    return normalized_id in kev_set


def clear_cache():
    """Clear the KEV cache from memory and disk."""
    global _kev_cache, _cache_timestamp
    _kev_cache.clear()
    _cache_timestamp = 0

    if KEV_CACHE_PATH.exists():
        KEV_CACHE_PATH.unlink()

    logger.info("KEV cache cleared")


if __name__ == "__main__":
    # Simple test
    logging.basicConfig(level=logging.INFO)

    kev_set = load_kev_catalog()
    print(f"Loaded {len(kev_set)} KEV entries")

    # Test with a known KEV (if any in cache)
    # We'll test with a non-existent CVE first
    test_cve = "CVE-9999-9999"
    print(f"Is {test_cve} in KEV? {is_kev(test_cve)}")

    # Test with a known KEV example (as of 2024, CVE-2023-XXXX might be in KEV)
    # We'll just show that the function works