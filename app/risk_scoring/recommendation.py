"""Gen recommend cho những lỗi tìm được"""
import logging

logger = logging.getLogger(__name__)

MISCONFIG_RECOMMENDATIONS = {
    "TELNET_ENABLED": "Disable Telnet and use SSH instead.",
    "SNMP_PUBLIC": "Change the default SNMP community and use SNMPv3.",
    "HTTP_ADMIN_ENABLED": "Use HTTPS for the administration interface.",
    "UPNP_ENABLED": "Disable UPnP if it is not required.",
    "SMB_SIGNING_DISABLED": "Enable SMB signing."
}

DEFAULT_CVE_RECOMMENDATION = "Update affected software or firmware to a secure version."
DEFAULT_MISCONFIG_RECOMMENDATION = "Review and harden the insecure configuration."


def recommend(findings: list[dict]) -> list[str]:
    recommendations = []

    for finding in findings:
        finding_type = str(finding.get("type") or "").upper()

        # Tạo khuyến nghị dựa trên loại lỗ hổng
        if finding_type == "CVE":
            recommendation = DEFAULT_CVE_RECOMMENDATION
        elif finding_type == "MISCONFIG":
            rule_id = str(finding.get("external_rule_id") or "").strip().upper()
            recommendation = MISCONFIG_RECOMMENDATIONS.get(rule_id, DEFAULT_MISCONFIG_RECOMMENDATION)

        else:
            logger.warning("Unsupported finding type: %s", finding_type)
            continue

        # Không thêm khuyến nghị đã tồn tại
        if recommendation not in recommendations:
            recommendations.append(recommendation)

    logger.info("Generated %d recommendations from %d findings", len(recommendations), len(findings))
    return recommendations
