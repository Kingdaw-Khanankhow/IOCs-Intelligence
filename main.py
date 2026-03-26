import models
from datetime import datetime, timezone, timedelta
import logging
import traceback
from fastapi import FastAPI, Request, Form, Depends, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from database import SessionLocal, engine, get_db
from auth_utils import (
    get_password_hash, 
    verify_password, 
    create_access_token, 
    SECRET_KEY, 
    ALGORITHM
)
from jose import jwt, JWTError
from ioc_utils import identify_and_clean_ioc, get_ip_from_domain
from api_interactions.virustotal import check_vt
from api_interactions.abuseipdb import check_abuse
from api_interactions.malwarebazaar import check_bazaar
from confident import confidence, get_likelihood_score
from collections import Counter

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database Initialize
models.Base.metadata.create_all(bind=engine) 

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# JWT Dependency
async def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        token = token.replace("Bearer ", "")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        return username
    except JWTError:
        return None

def format_timestamp(ts):
    if ts is None: return "N/A"
    try:
        if isinstance(ts, (int, float)):
            dt_ts = datetime.fromtimestamp(ts, tz=timezone.utc)
        else:
            from dateutil import parser
            dt_ts = parser.parse(str(ts))
            if dt_ts.tzinfo is None:
                dt_ts = dt_ts.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        diff = int((now - dt_ts).total_seconds())

        if diff < 0: diff = 0 
        if diff < 60: return "Just now"
        elif diff < 3600: return f"{diff // 60} minutes ago"
        elif diff < 86400: return f"{diff // 3600} hours ago"
        elif diff < 2592000: return f"{diff // 86400} days ago" 
        else: return f"{diff // 2592000} months ago"
    except Exception as e:
        logger.error(f"Error formatting timestamp: {e}")
        return "N/A"

def main_process(user_input):
    ioc_type, clean_value = identify_and_clean_ioc(user_input)
    if ioc_type == "unknown":
        return {"status": "error", "message": "รูปแบบ IOC ไม่ถูกต้อง"}

    report = {"target": clean_value, "type": ioc_type, "details": {}}
    try:
        # API Data Fetching
        if ioc_type == "ip":
            report["details"]["virustotal"] = check_vt("ip", clean_value) or {}
            report["details"]["abuseipdb"] = check_abuse(clean_value) or {}
        elif ioc_type == "domain":
            report["details"]["virustotal"] = check_vt("domain", clean_value) or {}
            res_ip = get_ip_from_domain(clean_value)
            if res_ip: report["details"]["abuseipdb"] = check_abuse(res_ip) or {}
        elif ioc_type == "hash":
            report["details"]["virustotal"] = check_vt("hash", clean_value) or {}
            report["details"]["malwarebazaar"] = check_bazaar(clean_value) or {}

        vt = report["details"].get("virustotal", {}) or {}
        abuse = report["details"].get("abuseipdb", {}) or {}
        bazaar = report["details"].get("malwarebazaar", {}) or {}

        # Scoring Logic
        total_confident, _ = confidence(ioc_type, report["details"])
        score, level = get_likelihood_score(total_confident)

        vendor_results = vt.get('last_analysis_results', {}) 
        labels = []
        if vendor_results:
            labels = [res.get('result') for res in vendor_results.values() 
                      if res.get('category') in ['malicious', 'suspicious'] and res.get('result')]
        
        if not labels and vt.get('categories'):
            labels = vt.get('categories')

        most_common_threat = Counter(labels).most_common(1)[0][0].capitalize() if labels else "Clean / Undetected"

        # UI Mapping
        ui_data = {
            "target": clean_value,
            "type": ioc_type,
            "last_analysis": format_timestamp(vt.get("last_analysis_date")),
            "vendor_analysis": most_common_threat
        }

        if ioc_type == "hash":
            ui_data.update({
                "isp": bazaar.get("signature") or vt.get("type_description") or "N/A",
                "country": "File Analysis",
                "signature": vt.get("signature") or bazaar.get("signature") or "N/A",
                "file_size": vt.get("size") or bazaar.get("file_size") or "N/A",
                "file_type": vt.get("type_description") or "N/A",
                "all_tags": vt.get("tags", [])
            })
        elif ioc_type == "domain":
            cats_list = vt.get("categories", [])
            ui_data["categories_text"] = ", ".join(cats_list) if cats_list else "Uncategorized"
            raw_countries = vt.get("countries", []) or ([vt.get("country")] if vt.get("country") else [])
            ui_data["countries"] = list(set(raw_countries)) if raw_countries else ["Global"]
            ui_data["country"] = ", ".join(ui_data["countries"])
            ui_data["isp"] = vt.get("provider") or "Unknown"
        else: # ip
            ui_data["isp"] = vt.get("provider") or abuse.get("isp") or "N/A"
            ui_data["country"] = vt.get("country") or abuse.get("country") or "N/A"

        report["ui"] = ui_data
        report["confident"] = {
            "total_confident": round(total_confident, 2), 
            "likelihood_score": score, 
            "likelihood_level": level
        }
        return report
    except Exception as e:
        logger.error(traceback.format_exc())
        return {"status": "error", "message": str(e)}

# Routes

@app.get("/")
async def index(request: Request, username: str = Depends(get_current_user)):
    return templates.TemplateResponse("index.html", {"request": request, "username": username, "error": None})

@app.post("/search")
async def search_ioc(request: Request, user_input: str = Form(...), db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    target = user_input.strip()
    try:
        # Check Cache 
        db_ioc = db.query(models.IOCCache).filter(models.IOCCache.ioc_value == target).first()
        cache_duration = timedelta(days=1)
        now = datetime.now(timezone.utc)
        
        should_fetch_new = False
        if db_ioc:
            record_time = db_ioc.last_updated.replace(tzinfo=timezone.utc) if db_ioc.last_updated.tzinfo is None else db_ioc.last_updated
            if now - record_time > cache_duration:
                should_fetch_new = True
        else:
            should_fetch_new = True

        if not should_fetch_new and db_ioc:
            report = db_ioc.result_data
        else:
            report = main_process(target)
            if report.get("status") == "error":
                return templates.TemplateResponse("index.html", {"request": request, "error": report["message"], "username": current_user})
            
            if db_ioc:
                # Update existing record
                db_ioc.result_data = report
                db_ioc.last_updated = now
                db.commit()
            else:
                # Create new record
                try:
                    new_cache = models.IOCCache(
                        ioc_value=report["target"], 
                        ioc_type=report["type"], 
                        result_data=report,
                        last_updated=now
                    )
                    db.add(new_cache)
                    db.commit()
                except IntegrityError:
                    db.rollback()
                    db_ioc = db.query(models.IOCCache).filter(models.IOCCache.ioc_value == target).first()
                    if db_ioc: report = db_ioc.result_data

        # ประวัติการค้นหา
        if current_user:
            user = db.query(models.User).filter(models.User.username == current_user).first()
            if user:
                try:
                    new_history = models.SearchHistory(user_id=user.id, ioc_value=report["target"])
                    db.add(new_history)
                    db.commit()
                except Exception as e:
                    db.rollback()
                    logger.warning(f"Could not save history: {e}")

        return templates.TemplateResponse("detail.html", {"request": request, "report": report, "username": current_user})
    except Exception as e:
        db.rollback()
        logger.error(traceback.format_exc())
        return templates.TemplateResponse("index.html", {"request": request, "error": "เกิดข้อผิดพลาดในการประมวลผล", "username": current_user})

@app.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "error": None})

@app.post("/register")
async def register_user(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    try:
        if db.query(models.User).filter(models.User.username == username).first():
            return templates.TemplateResponse("register.html", {"request": request, "error": "ชื่อผู้ใช้นี้ถูกใช้งานแล้ว"})
        new_user = models.User(username=username, hashed_password=get_password_hash(password))
        db.add(new_user)
        db.commit()
        return RedirectResponse(url="/login", status_code=303)
    except Exception:
        db.rollback()
        return templates.TemplateResponse("register.html", {"request": request, "error": "ไม่สามารถลงทะเบียนได้"})

@app.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse("login.html", {"request": {"type": "http"}, "error": "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"})
    
    token = create_access_token(data={"sub": user.username})
    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie(
        key="access_token",
        value=f"Bearer {token}",
        httponly=True,
        path="/",
        samesite="lax"
    )
    return resp

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token")
    return response

@app.get("/history")
async def view_history(request: Request, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    try:
        user = db.query(models.User).filter(models.User.username == current_user).first()
        from sqlalchemy.orm import joinedload
        history_items = db.query(models.SearchHistory)\
            .options(joinedload(models.SearchHistory.ioc_details))\
            .filter(models.SearchHistory.user_id == user.id)\
            .order_by(models.SearchHistory.searched_at.desc())\
            .all()
        return templates.TemplateResponse("history.html", {"request": request, "username": current_user, "history": history_items})
    except Exception as e:
        logger.error(f"History error -> {e}")
        return templates.TemplateResponse("index.html", {"request": request, "error": "Database Error", "username": current_user})