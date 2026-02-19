from sqlalchemy import Column, Integer, String, Boolean, DateTime
from datetime import datetime
from database import Base

class License(Base):
    __tablename__ = "licenses"

    id = Column(Integer, primary_key=True, index=True)
    invoice_id = Column(String, unique=True, index=True)
    license_key = Column(String, unique=True)
    is_paid = Column(Boolean, default=False)
    owner_id = Column(String)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    invoice_id = Column(String, index=True)
    ip_address = Column(String)
    is_success = Column(Boolean)
    user_agent = Column(String) # Чтобы понимать, не бот ли это
