def apply_update(context):
    logger = context["logger"]
    record_event = context["record_event"]

    logger.info("Safe update executed successfully")
    record_event(
        "update_applied",
        "low",
        "Safe update applied",
        {"module": "safe_update", "behavior": "benign"},
    )
