from pathlib import Path


def apply_update(context):
    logger = context["logger"]
    record_event = context["record_event"]
    leak_file = Path(context["leak_file"])
    leak_file.parent.mkdir(parents=True, exist_ok=True)
    leak_file.write_text("ИМИТИРОВАННАЯ УТЕЧКА УЧЁТНЫХ ДАННЫХ", encoding="utf-8")
    logger.warning("Предупреждение безопасности: выполнено имитированное скомпрометированное обновление")
    record_event(
        "alert",
        "critical",
        "Имитированная утечка учётных данных записана во временный файл",
        {"module": "bad_code", "leak_file": str(leak_file)},
    )
