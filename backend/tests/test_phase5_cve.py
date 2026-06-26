"""
Tests for Phase 5 CVE mapping functionality.
"""
import pytest
import json
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

from backend.core.cve_mapping.nvd_lookup import lookup_cve_by_cpe, lookup_cve_by_product
from backend.core.cve_mapping.epss_scorer import get_epss_score
from backend.core.cve_mapping.kev_checker import is_kev
from backend.core.cve_mapping.cve_aggregator import run_cve_mapping, CVEFinding


class TestNVDLookup:
    """Test NVD lookup functionality."""

    def test_lookup_cve_by_cpe_invalid_format(self):
        """Test that invalid CPE formats return empty list."""
        assert lookup_cve_by_cpe("") == []
        assert lookup_cve_by_cpe("invalid") == []
        assert lookup_cve_by_cpe("cpe:") == []

    @patch('backend.core.cve_mapping.nvd_lookup._load_nvd_file')
    def test_lookup_cve_by_cpe_no_matches(self, mock_load):
        """Test CPE lookup with no matching CVEs."""
        mock_load.return_value = []  # No NVD data
        result = lookup_cve_by_cpe("cpe:2.3:a:test:product:1.0:*:*:*:*:*:*:*")
        assert result == []

    @patch('backend.core.cve_mapping.nvd_lookup._load_nvd_file')
    def test_lookup_cve_by_cpe_with_matches(self, mock_load):
        """Test CPE lookup with matching CVEs."""
        # Mock NVD data with one matching CVE
        mock_load.return_value = [{
            'cve': {
                'CVE_data_meta': {'ID': 'CVE-2023-1234'},
                'description': {'description_data': [{'value': 'Test vulnerability'}]}
            },
            'configurations': {
                'nodes': [{
                    'cpeMatch': [{
                        'criteria': 'cpe:2.3:a:test:product:1.0:*:*:*:*:*:*:*',
                        'matchCriteriaId': 'MATCH-123'
                    }]
                }]
            },
            'impact': {
                'baseMetricV3': {
                    'cvssV3': {
                        'baseScore': 9.8,
                        'baseSeverity': 'CRITICAL',
                        'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    }
                }
            },
            'publishedDate': '2023-01-01T00:00:00.000'
        }]

        result = lookup_cve_by_cpe("cpe:2.3:a:test:product:1.0:*:*:*:*:*:*:*")
        # The function searches multiple years (2021-2026), so we get 6 identical results
        assert len(result) == 6
        assert result[0]['cve_id'] == 'CVE-2023-1234'
        assert result[0]['cvss_score'] == 9.8
        assert result[0]['cvss_severity'] == 'CRITICAL'

    def test_lookup_cve_by_product_empty_name(self):
        """Test product lookup with empty name."""
        assert lookup_cve_by_product("", "1.0") == []

    @patch('backend.core.cve_mapping.nvd_lookup.requests.get')
    def test_lookup_cve_by_product_api_success(self, mock_get):
        """Test successful product lookup via NVD API."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'vulnerabilities': [{
                'cve': {
                    'id': 'CVE-2023-5678',
                    'descriptions': [{'lang': 'en', 'value': 'Another test vuln'}],
                    'metrics': {
                        'cvssMetricV31': [{
                            'cvssData': {
                                'baseScore': 7.5,
                                'baseSeverity': 'HIGH',
                                'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
                            }
                        }]
                    },
                    'weaknesses': [{
                        'description': [{'lang': 'en', 'value': 'CWE-79'}]
                    }],
                    'published': '2023-06-01T00:00:00.000'
                }
            }]
        }
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        result = lookup_cve_by_product("testvendor", "1.0")
        assert len(result) == 1
        assert result[0]['cve_id'] == 'CVE-2023-5678'
        assert result[0]['cvss_score'] == 7.5
        assert result[0]['cvss_severity'] == 'HIGH'
        assert result[0]['cwe_ids'] == ['CWE-79']


class TestEPSSScorer:
    """Test EPSS scorer functionality."""

    def test_get_epss_score_empty_input(self):
        """Test EPSS score for empty/invalid input."""
        assert get_epss_score("") == 0.0
        assert get_epss_score(None) == 0.0

    @patch('backend.core.cve_mapping.epss_scorer.load_epss_db')
    def test_get_epss_score_found(self, mock_load):
        """Test EPSS score retrieval for known CVE."""
        mock_load.return_value = {'CVE-2021-44228': 0.97556}
        score = get_epss_score('CVE-2021-44228')
        assert score == 0.97556

    @patch('backend.core.cve_mapping.epss_scorer.load_epss_db')
    def test_get_epss_score_not_found(self, mock_load):
        """Test EPSS score for unknown CVE."""
        mock_load.return_value = {'CVE-2021-44228': 0.97556}
        score = get_epss_score('CVE-9999-9999')
        assert score == 0.0


class TestKEVChecker:
    """Test KEV checker functionality."""

    def test_is_kev_empty_input(self):
        """Test KEV check for empty/invalid input."""
        assert is_kev("") == False
        assert is_kev(None) == False

    @patch('backend.core.cve_mapping.kev_checker.load_kev_catalog')
    def test_is_kev_found(self, mock_load):
        """Test KEV check for known exploited CVE."""
        mock_load.return_value = {'CVE-2021-44228', 'CVE-2022-22965'}
        assert is_kev('CVE-2021-44228') == True
        assert is_kev('CVE-2022-22965') == True

    @patch('backend.core.cve_mapping.kev_checker.load_kev_catalog')
    def test_is_kev_not_found(self, mock_load):
        """Test KEV check for unknown CVE."""
        mock_load.return_value = {'CVE-2021-44228'}
        assert is_kev('CVE-9999-9999') == False


class TestCVEAggregator:
    """Test CVE aggregator functionality."""

    def test_count_by_severity(self):
        """Test severity counting helper."""
        findings = [
            CVEFinding(
                cve_id='CVE-1', component='test', version='1.0', cpe='test',
                cvss_score=9.0, cvss_severity='CRITICAL', cvss_vector='test',
                epss_score=0.5, is_kev=False, cwe_ids=[], published='2023-01-01',
                description='test'
            ),
            CVEFinding(
                cve_id='CVE-2', component='test', version='1.0', cpe='test',
                cvss_score=5.0, cvss_severity='MEDIUM', cvss_vector='test',
                epss_score=0.3, is_kev=False, cwe_ids=[], published='2023-01-01',
                description='test'
            ),
            CVEFinding(
                cve_id='CVE-3', component='test', version='1.0', cpe='test',
                cvss_score=7.0, cvss_severity='HIGH', cvss_vector='test',
                epss_score=0.8, is_kev=True, cwe_ids=[], published='2023-01-01',
                description='test'
            )
        ]

        from backend.core.cve_mapping.cve_aggregator import _count_by_severity
        assert _count_by_severity(findings, 'CRITICAL') == 1
        assert _count_by_severity(findings, 'HIGH') == 1
        assert _count_by_severity(findings, 'MEDIUM') == 1
        assert _count_by_severity(findings, 'LOW') == 0

    @patch('backend.core.cve_mapping.cve_aggregator._load_sbom_data')
    @patch('backend.core.cve_mapping.cve_aggregator.lookup_cve_by_cpe')
    @patch('backend.core.cve_mapping.cve_aggregator.get_epss_score')
    @patch('backend.core.cve_mapping.cve_aggregator.is_kev')
    def test_run_cve_mapping_complete_flow(
        self, mock_is_kev, mock_epss, mock_lookup, mock_sbom
    ):
        """Test complete CVE mapping flow with mocked dependencies."""
        # Mock SBOM data
        mock_sbom.return_value = {
            'components': [{
                'name': 'log4j',
                'version': '2.14.1',
                'cpe': 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'
            }]
        }

        # Mock NVD lookup to return one CVE
        mock_lookup.return_value = [{
            'cve_id': 'CVE-2021-44228',
            'description': 'Log4Shell vulnerability',
            'cvss_score': 10.0,
            'cvss_severity': 'CRITICAL',
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'cwe_ids': ['CWE-502'],
            'published': '2021-12-10'
        }]

        # Mock EPSS score
        mock_epss.return_value = 0.97

        # Mock KEV check
        mock_is_kev.return_value = True

        # Run the mapping
        result = run_cve_mapping(
            sbom_job_id='test_sbom_123',
            job_id='test_cve_456'
        )

        # Assertions
        assert result.total_cves == 1
        assert result.critical_count == 1
        assert result.kev_count == 1
        assert len(result.findings) == 1

        finding = result.findings[0]
        assert finding.cve_id == 'CVE-2021-44228'
        assert finding.component == 'log4j'
        assert finding.version == '2.14.1'
        assert finding.cvss_score == 10.0
        assert finding.cvss_severity == 'CRITICAL'
        assert finding.epss_score == 0.97
        assert finding.is_kev == True
        assert finding.cwe_ids == ['CWE-502']

    @patch('backend.core.cve_mapping.cve_aggregator._load_sbom_data')
    def test_run_cve_mapping_no_sbom_data(self, mock_sbom):
        """Test CVE mapping when SBOM data cannot be loaded."""
        mock_sbom.return_value = None

        result = run_cve_mapping(
            sbom_job_id='nonexistent_job',
            job_id='test_job'
        )

        # Should return empty result on failure
        assert result.total_cves == 0
        assert len(result.findings) == 0
        assert result.job_id == 'test_job'


if __name__ == "__main__":
    pytest.main([__file__, "-v"])