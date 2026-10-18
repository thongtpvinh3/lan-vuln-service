from app.cve_matching.extractor import extract_software
from app.cve_matching.normalize import normalize


def test_platform_input():
    """Assert that the snapshot-only fixture yields two normalized Apache software records.

    Returns:
        None: No return value.
    """
    request = {
        "data": {
            "inputs": {
                "devices": [],
                "snapshots": [
                    {
                        "ip": "192.168.56.12",
                        "source": "banner",
                        "raw_config": (
                            '{"Content-Type":"text/html",'
                            '"Server":"Apache/2.4.52 (Ubuntu)",'
                            '"httpStatus":"200"}'
                        )
                    },
                    {
                        "ip": "192.168.56.101",
                        "source": "banner",
                        "raw_config": (
                            '{"Server":"Apache/2.4.52 (Ubuntu)"}'
                        )
                    }
                ]
            }
        }
    }

    services = extract_software(request)
    assert len(services) == 2
    normalized = [normalize(s) for s in services]

    assert all(s is not None for s in normalized)
    assert all(s["vendor"] == "apache" for s in normalized)
    assert all(s["product"] == "http_server" for s in normalized)
    assert all(s["version"] == "2.4.52" for s in normalized)