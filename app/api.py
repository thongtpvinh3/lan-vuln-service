import os
import logging

from flask import Flask, jsonify

from app.common.database import db
from app.cve_matching.repository import get_findings

app = Flask(__name__)
logger = logging.getLogger(__name__)


@app.get("/health")
def health():
    """Check database connectivity for the health endpoint.

    Returns:
        flask.Response | tuple[flask.Response, int]: JSON health status; includes HTTP
            503 when the database check fails.
    """
    try:
        db.ping()
        return jsonify({
            "service": "vulnerability-service",
            "status": "UP",
            "database": "UP"
        })

    except Exception:
        logger.exception("Database health check failed")
        return jsonify({
            "service": "vulnerability-service",
            "status": "DOWN",
            "database": "DOWN"
        }), 503


@app.get("/api/v1/findings/<scan_id>")
def findings(scan_id):
    """Load the CVE findings exposed by the scan findings endpoint.

    Args:
        scan_id (str): Identifier of the scan whose records are being processed.

    Returns:
        flask.Response | tuple[flask.Response, int]: JSON findings and count, or an
            error response with HTTP 500.
    """
    try:
        results = get_findings(scan_id)
        return jsonify({
            "scan_id": scan_id,
            "total": len(results),
            "findings": results
        })

    except Exception:
        logger.exception("Failed to load findings: scan=%s", scan_id)
        return jsonify({
            "error": "DATABASE_ERROR",
            "message": "Cannot load findings"
        }), 500


if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("FLASK_PORT", "8082"))
    )
