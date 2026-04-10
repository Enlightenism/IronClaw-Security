from fastapi import FastAPI
from app.api.scan import router as scan_router
from app.api.history import router as history_router

app = FastAPI(title="IronClaw Gen1", version="0.1.0")

app.include_router(scan_router, prefix="/scan", tags=["scan"])
app.include_router(history_router, prefix="/history", tags=["history"])

@app.get("/", tags=["default"])
def root():
    return {"message": "IronClaw Gen1 is running"}

@app.get("/health", tags=["default"])
def health():
    return {"status": "ok"}
