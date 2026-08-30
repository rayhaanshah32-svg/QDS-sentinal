from __future__ import annotations

import uuid
from datetime import datetime
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class Session(Base):
    __tablename__ = "sessions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    sender_id = Column(String, nullable=False)
    recipient_id = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    verification_mode = Column(String, nullable=False)
    threat_level = Column(String, nullable=False)
    verdict = Column(String, nullable=False)
    mismatch_rate = Column(Float, nullable=False, default=0.0)
    threshold = Column(Float, nullable=False, default=0.0)
    confidence_upper_bound = Column(Float, nullable=False, default=0.0)
    mean_fidelity = Column(Float, nullable=False, default=0.0)
    attack_type = Column(String, nullable=True)
    raw_assessment_string = Column(Text, nullable=False)

    telemetry_logs = relationship("TelemetryLog", back_populates="session", cascade="all, delete-orphan")
    threat_events = relationship("ThreatEvent", back_populates="session", cascade="all, delete-orphan")


class TelemetryLog(Base):
    __tablename__ = "telemetry_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String, ForeignKey("sessions.id"), nullable=False)
    position_index = Column(Integer, nullable=False)
    basis = Column(String, nullable=False)
    bell_outcome = Column(String, nullable=False)
    expected_correction = Column(String, nullable=False)
    actual_correction = Column(String, nullable=False)
    fidelity = Column(Float, nullable=False)
    match = Column(Boolean, nullable=False)

    session = relationship("Session", back_populates="telemetry_logs")


class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String, ForeignKey("sessions.id"), nullable=False)
    threat_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    observed_evidence = Column(Text, nullable=False)
    protocol_impact = Column(Text, nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)

    session = relationship("Session", back_populates="threat_events")
