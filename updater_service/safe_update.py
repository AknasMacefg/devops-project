def apply_update(context):
    logger = context["logger"]
    record_event = context["record_event"]

    logger.info("Безопасное обновление выполнено успешно")
    record_event(
        "update_applied",
        "low",
        "Безопасное обновление применено",
        {"module": "safe_update", "behavior": "benign"},
    )
