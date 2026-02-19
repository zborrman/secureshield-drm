import os
import secrets
import stripe
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, Request, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import text
from database import SessionLocal, engine, Base
from auth_utils import verify_license_key, hash_license_key
from watermark_service import generate_user_fingerprint
import stripe_service
import models

app = FastAPI()

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")

async def require_admin(x_admin_key: str = Header(default="")):
    if not ADMIN_API_KEY or x_admin_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid or missing X-Admin-Key")

# Создаем таблицы при старте (в продакшене лучше использовать Alembic)
@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db():
    async with SessionLocal() as session:
        yield session

async def log_attempt(db: AsyncSession, invoice_id: str, ip: str, success: bool, ua: str):
    new_log = models.AuditLog(
        invoice_id=invoice_id,
        ip_address=ip,
        is_success=success,
        user_agent=ua
    )
    db.add(new_log)
    await db.commit()

@app.get("/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    try:
        await db.execute(text("SELECT 1"))
        return {"status": "healthy", "database": "connected"}
    except Exception:
        raise HTTPException(status_code=503, detail="Database unreachable")

@app.post("/verify-license")
async def verify(
    invoice_id: str,
    input_key: str,
    request: Request, # Получаем данные о запросе
    db: AsyncSession = Depends(get_db)
):
    # Получаем метаданные запроса
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "unknown")

    result = await db.execute(select(models.License).where(models.License.invoice_id == invoice_id))
    license_record = result.scalars().first()

    # Проверка на Brute-force (простая логика)
    recent_fails = await db.execute(
        select(models.AuditLog)
        .where(models.AuditLog.ip_address == client_ip)
        .where(models.AuditLog.is_success == False)
        .limit(5)
    )
    if len(recent_fails.all()) >= 5:
        await log_attempt(db, invoice_id, client_ip, False, user_agent)
        raise HTTPException(status_code=429, detail="Слишком много попыток. IP временно заблокирован.")

    success = False
    if license_record and verify_license_key(input_key, license_record.license_key):
        success = True

    # Записываем результат в аудит
    await log_attempt(db, invoice_id, client_ip, success, user_agent)

    if not success:
        raise HTTPException(status_code=403, detail="Invalid Key")

    return {"status": "success", "fingerprint": generate_user_fingerprint(license_record.owner_id)}

@app.post("/admin/create-license", status_code=201)
async def create_license(invoice_id: str, owner_id: str, db: AsyncSession = Depends(get_db), _: None = Depends(require_admin)):
    # Генерируем случайный безопасный ключ
    plain_key = f"SK-{secrets.token_urlsafe(16)}"
    hashed_key = hash_license_key(plain_key)

    new_license = models.License(
        invoice_id=invoice_id,
        license_key=hashed_key, # В базе только хеш!
        owner_id=owner_id,
        is_paid=False
    )

    db.add(new_license)
    await db.commit()

    return {
        "invoice_id": invoice_id,
        "plain_key_to_copy": plain_key, # Показываем один раз
        "warning": "Сохраните ключ! В базе останется только его отпечаток."
    }

@app.get("/admin/licenses")
async def list_licenses(db: AsyncSession = Depends(get_db), _: None = Depends(require_admin)):
    result = await db.execute(select(models.License))
    return result.scalars().all()

@app.get("/admin/audit-log")
async def get_audit_log(db: AsyncSession = Depends(get_db), _: None = Depends(require_admin)):
    result = await db.execute(select(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).limit(100))
    return result.scalars().all()

@app.get("/admin/alerts")
async def get_alerts(db: AsyncSession = Depends(get_db), _: None = Depends(require_admin)):
    # Ищем неудачные попытки за последние 30 минут
    time_threshold = datetime.utcnow() - timedelta(minutes=30)

    query = select(models.AuditLog).where(
        models.AuditLog.is_success == False,
        models.AuditLog.timestamp >= time_threshold
    ).order_by(models.AuditLog.timestamp.desc())

    result = await db.execute(query)
    alerts = result.scalars().all()

    return alerts

@app.post("/signout")
async def signout(invoice_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "unknown")
    await log_attempt(db, invoice_id, client_ip, False, f"SIGNOUT | {user_agent}")
    return {"status": "signed_out"}

@app.post("/create-checkout-session")
async def create_checkout(invoice_id: str):
    try:
        # Создаем сессию оплаты. Передаем invoice_id в metadata,
        # чтобы Stripe вернул его нам в вебхуке.
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {'name': f'Access License: {invoice_id}'},
                    'unit_amount': 5000, # $50.00
                },
                'quantity': 1,
            }],
            mode='payment',
            metadata={'invoice_id': invoice_id},
            success_url='http://localhost:3000/success',
            cancel_url='http://localhost:3000/cancel',
        )
        return {"url": checkout_session.url}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, stripe_service.WEBHOOK_SECRET
        )
    except Exception as e:
        return {"error": "Invalid signature"}, 400

    # Если оплата прошла успешно
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        invoice_id = session['metadata'].get('invoice_id')
        await stripe_service.handle_payment_success(invoice_id)

    return {"status": "success"}
