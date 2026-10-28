import logging
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor
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
logger.info("Запуск асинхронного сервера NetScan ядра...")

app = FastAPI(title="Network Scanner Core")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# Пул потоков для изоляции блокирующих вызовов Nmap
executor = ThreadPoolExecutor(max_workers=3)

CURRENT_SCAN = {
    "hosts": [],
    "summary": {"total": 0, "windows": 0, "linux": 0, "printer": 0, "other": 0},
    "target": "192.168.1.0/24",
    "status": "idle"  # Статус для UI: idle / scanning
}

try:
    scanner = NetworkScanner()
except Exception as e:
    logger.critical(f"Критический сбой инициализации подсистем: {e}")
    scanner = None


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
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
    logger.info(f"Получен запрос на сканирование подсети: {target} [Режим: {mode}]")

    if not scanner:
        logger.error("Запрос отклонен: сканер недоступен.")
        return {"error": "Сканер недоступен. Проверьте установку Nmap."}
        
    if CURRENT_SCAN["status"] == "scanning":
        logger.warning("Сканирование уже выполняется. Повторный запрос отклонен.")
        return {"error": "Сканирование уже запущено. Пожалуйста, подождите."}

    CURRENT_SCAN["status"] = "scanning"
    CURRENT_SCAN["target"] = target

    try:
        # ИСПРАВЛЕНО: Запуск блокирующего метода Nmap в фоновом потоке. 
        # Event Loop FastAPI остается свободным!
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(executor, scanner.scan, target, mode)

        if "error" not in result:
            CURRENT_SCAN["hosts"] = result["hosts"]
            CURRENT_SCAN["summary"] = result["summary"]
            logger.info(f"Данные сессии сканирования для {target} успешно обновлены.")
        else:
            logger.warning(f"Фоновое сканирование вернуло ошибку.")
        
        return result

    except Exception as e:
        logger.error(f"Ошибка в процессе асинхронного выполнения: {e}", exc_info=True)
        return {"error": str(e)}
        
    finally:
        CURRENT_SCAN["status"] = "idle"


@app.get("/status")
async def get_status():
    """Эндпоинт для проверки текущего состояния сканера (чтобы UI знал, идет ли процесс)"""
    return {"status": CURRENT_SCAN["status"]}


@app.get("/export/html")
async def export_html():
    logger.info(f"Запрос на выгрузку HTML-отчета для {CURRENT_SCAN['target']}.")
    report_content = generate_html_report(CURRENT_SCAN, CURRENT_SCAN["target"])
    return Response(
        content=report_content,
        media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename=scan_report.html"},
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
