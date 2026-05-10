from pathlib import Path


def apply_update(context):
    logger = context["logger"]
    record_event = context["record_event"]
    leak_file = Path(context["leak_file"])
    leak_file.parent.mkdir(parents=True, exist_ok=True)
    leak_file.write_text("SIMULATED CREDENTIAL LEAK", encoding="utf-8")
    logger.warning("Security warning: simulated compromised update executed")
    record_event(
        "alert",
        "critical",
        "SIMULATED CREDENTIAL LEAK written to runtime file",
        {"module": "compromised_update", "leak_file": str(leak_file)},
    )
