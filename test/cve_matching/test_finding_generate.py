from app.cve_matching.finding_generate import build_finding


def test_build_finding():
    """Verify CVSS and evidence fields when building a virtual-match CVE finding.

    Returns:
        None: No return value.
    """
    software = {
        "service": {
            "host": "192.168.56.12",
            "port": 80,
            "protocol": "tcp",
            "source": "SERVICE_FINGERPRINT",
            "banner": "Apache/2.4.52"
        },
        "product": "http_server",
        "version": "2.4.52",
        "cpe_resolution": "VIRTUAL_MATCH",
        "virtual_match_string": (
            "cpe:2.3:a:apache:http_server:"
            "*:*:*:*:*:*:*:*"
        )
    }

    cve = {
        "id": "CVE-2024-99999",
        "metrics": {
            "cvssMetricV31": [{
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {
                    "version": "3.1",
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                    "vectorString": (
                        "CVSS:3.1/AV:N/AC:L/PR:N/"
                        "UI:N/S:U/C:H/I:H/A:H"
                    )
                }
            }]
        }
    }

    finding = build_finding(
        software=software,
        cpe_name=(
            "cpe:2.3:a:apache:http_server:"
            "2.4.52:*:*:*:*:*:*:*"
        ),
        cve=cve,
        status="POTENTIAL"
    )

    assert finding["host"] == "192.168.56.12"
    assert finding["cve_id"] == "CVE-2024-99999"
    assert finding["cvss_score"] == 9.8
    assert finding["severity"] == "CRITICAL"
    assert finding["status"] == "POTENTIAL"

    assert finding["evidence"]["cvss"]["version"] == "3.1"
    assert finding["evidence"]["patch_status"] == "UNKNOWN"
    assert finding["evidence"]["official_cpe_name"] is None