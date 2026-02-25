from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import JSONB 
from database import Base

# users
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    
    history = relationship("SearchHistory", back_populates="owner", cascade="all, delete-orphan")

# ioc_cache
class IOCCache(Base):
    __tablename__ = "ioc_cache"

    ioc_value = Column(String(500), primary_key=True, index=True)
    ioc_type = Column(String(50))
    result_data = Column(JSONB) 
    last_updated = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    searched_in = relationship("SearchHistory", back_populates="ioc_details", cascade="all, delete-orphan")

# search_history
class SearchHistory(Base):
    __tablename__ = "search_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    ioc_value = Column(String(500), ForeignKey("ioc_cache.ioc_value", ondelete="CASCADE")) 
    searched_at = Column(DateTime(timezone=True), server_default=func.now())

    owner = relationship("User", back_populates="history")
    ioc_details = relationship("IOCCache", back_populates="searched_in")