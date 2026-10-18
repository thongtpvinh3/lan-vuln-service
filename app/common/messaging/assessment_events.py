from typing import Any

from app.common.messaging import (bus, BaseEvent, EventKeys)


def publish_step_completed(
        request: dict,
        step: str,
        result: dict[str, Any] | None = None,
        *,
        seq: int = 1,
        duration_ms: int = 0,
        warnings: list | None = None
):
    """Publish a successful step report, adding Platform fields to CVE findings.

    Args:
        request (dict): Assessment envelope containing scan_id and
            data.stage_run_id/inputs.
        step (str): Name of the completed assessment step.
        result (dict[str, Any] | None): Step output; None becomes an empty dictionary.
        seq (int): Step report sequence number; defaults to 1.
        duration_ms (int): Step execution time in milliseconds; defaults to 0.
        warnings (list | None): Report warnings; None becomes an empty list.

    Returns:
        None: No return value.
    """
    data = request["data"]
    stage_run_id = data["stage_run_id"]

    result = dict(result) if result is not None else {}
    if step == "cve_matching" and "findings" in result:
        result["findings"] = [
            {
                **finding,
                "ip": finding.get("ip") or finding["host"],
                "reference_url": finding.get("reference_url") or finding["evidence"]["reference"]
            }
            for finding in result["findings"]
        ]

    event = BaseEvent(
        event=EventKeys.STEP_COMPLETED,
        scan_id=request["scan_id"],
        data={
            "stage_run_id": stage_run_id,
            "step": step,
            "seq": seq,
            "status": "success",
            "duration_ms": duration_ms,
            "result": result,
            "warnings": warnings if warnings is not None else [],
            "error": None
        }
    )
    bus.publish(EventKeys.STEP_COMPLETED, event)


def publish_step_failed(request: dict, step: str, error: Exception):
    """Publish a failed step report with an error message truncated to 500 characters.

    Args:
        request (dict): Assessment envelope containing scan_id and
            data.stage_run_id/inputs.
        step (str): Name of the failed assessment step.
        error (Exception): Failure whose message is included in the report.

    Returns:
        None: No return value.
    """
    event = BaseEvent(
        event=EventKeys.STEP_FAILED,
        scan_id=request["scan_id"],
        data={
            "stage_run_id": request["data"]["stage_run_id"],
            "step": step,
            "status": "failed",
            "error": str(error)[:500]
        }
    )
    bus.publish(EventKeys.STEP_FAILED, event)


def publish_stage_completed(request: dict):
    """Publish a successful terminal report for an assessment stage.

    Args:
        request (dict): Assessment envelope containing scan_id and
            data.stage_run_id/inputs.

    Returns:
        None: No return value.
    """
    event = BaseEvent(
        event=EventKeys.STAGE_COMPLETED,
        scan_id=request["scan_id"],
        data={"stage_run_id": request["data"]["stage_run_id"], "status": "success"}
    )
    bus.publish(EventKeys.STAGE_COMPLETED, event)
