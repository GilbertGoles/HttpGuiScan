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
logger.info("Запуск стабильного асинхронного ядра NetScan...")

app = FastAPI(title="Network Scanner Core")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

CURRENT_SCAN = {
    "hosts": [],
    "summary": {"total": 0, "windows": 0, "linux": 0, "printer": 0, "other": 0},
    "target": "192.168.1.0/24",
    "status": "idle"
}

scanner = NetworkScanner()

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
        
    if CURRENT_SCAN["status"] == "scanning":
        logger.warning("Сканирование уже выполняется. Запрос отклонен.")
        return {"error": "Сканирование уже запущено. Пожалуйста, подождите."}

    CURRENT_SCAN["status"] = "scanning"
    CURRENT_SCAN["target"] = target

    try:
        # ИСПРАВЛЕНО: Вызываем напрямую через await новый асинхронный метод сканера!
        result = await scanner.scan_async(target, mode)

        if "error" not in result:
            CURRENT_SCAN["hosts"] = result["hosts"]
            CURRENT_SCAN["summary"] = result["summary"]
            logger.info(f"Данные сессии сканирования для {target} успешно обновлены.")
        else:
            logger.warning(f"Сканирование вернуло ошибку: {result['error']}")
        
        return result

    except Exception as e:
        logger.error(f"Ошибка в процессе выполнения: {e}", exc_info=True)
        return {"error": str(e)}
        
    finally:
        CURRENT_SCAN["status"] = "idle"

@app.get("/status")
async def get_status():
    return {"status": CURRENT_SCAN["status"]}

@app.get("/export/html")
async def export_html():
    report_content = generate_html_report(CURRENT_SCAN, CURRENT_SCAN["target"])
    return Response(
        content=report_content,
        media_type="text/html",
        headers={"Content-Disposition": "attachment; filename=scan_report.html"},
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
    uvicorn.run("main.py:app", host="127.0.0.1", port=8000, reload=False)
