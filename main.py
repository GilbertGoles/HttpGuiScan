import logging
import os
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates
import uvicorn

from reporter import generate_html_report
from scanner import NetworkScanner

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.FileHandler("scanner.log", encoding="utf-8"), logging.StreamHandler()],
)

logger = logging.getLogger("network_scanner.main")
logger.info("Запуск главного сервера NetScan ядра...")

app = FastAPI(title="Network Scanner Core")

# Привязка путей к текущей папке скрипта
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

CURRENT_SCAN = {
    "hosts": [],
    "summary": {"total": 0, "windows": 0, "linux": 0, "printer": 0, "other": 0},
    "target": "192.168.1.0/24",
}

try:
    scanner = NetworkScanner()
except Exception as e:
    logger.critical(f"Критический сбой инициализации подсистем: {e}")
    scanner = None


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    logger.info("Клиент подключился к Web UI панели управления.")
    # ИСПРАВЛЕНО: Объект request передан первым позиционным аргументом,
    # как этого требует новая версия FastAPI/Starlette.
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "scan_data": CURRENT_SCAN,
            "target": CURRENT_SCAN["target"],
        }
    )


@app.post("/scan")
async def do_scan(target: str = Form(...), mode: str = Form(...)):
    global CURRENT_SCAN
    logger.info(f"Получен HTTP POST запрос на сканирование подсети: {target} [Режим: {mode}]")

    if not scanner:
        logger.error("Запрос отклонен: инициализация Nmap не была выполнена.")
        return {"error": "Сканер недоступен. Проверьте установку Nmap в системе."}

    result = scanner.scan(target, mode)

    if "error" not in result:
        CURRENT_SCAN["hosts"] = result["hosts"]
        CURRENT_SCAN["summary"] = result["summary"]
        CURRENT_SCAN["target"] = target
        logger.info(f"Данные текущей сессии сканирования для {target} успешно обновлены.")
    else:
        logger.warning(f"Сканирование завершилось ошибкой для цели {target}.")

    return result


@app.get("/export/html")
async def export_html():
    logger.info(f"Получен запрос на выгрузку HTML-отчета по текущей сессии ({CURRENT_SCAN['target']}).")
    report_content = generate_html_report(CURRENT_SCAN, CURRENT_SCAN["target"])
    return Response(
        content=report_content,
        media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename=scan_report_{CURRENT_SCAN['target'].replace('/', '_')}.html"},
    )


@app.get("/logs")
async def get_logs():
    try:
        with open(os.path.join(BASE_DIR, "scanner.log"), "r", encoding="utf-8") as f:
            lines = f.readlines()
            return {"logs": lines[-50:]}
    except Exception as e:
        return {"logs": [f"Не удалось прочитать файл логов: {e}"]}


if __name__ == "__main__":
    uvicorn.run("main.py:app", host="127.0.0.1", port=8000, reload=True)
