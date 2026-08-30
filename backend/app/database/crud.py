from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session as DBSession

from app.database.models import Session, TelemetryLog, ThreatEvent


def create_session(db: DBSession, session_data: dict) -> Session:
    session_id = session_data.get("id") or str(uuid.uuid4())
    record = Session(
        id=session_id,
        timestamp=session_data.get("timestamp", datetime.now(timezone.utc).replace(tzinfo=None)),
        sender_id=session_data["sender_id"],
        recipient_id=session_data["recipient_id"],
        message=session_data["message"],
        verification_mode=session_data["verification_mode"],
        threat_level=session_data["threat_level"],
        verdict=session_data["verdict"],
        mismatch_rate=session_data.get("mismatch_rate", 0.0),
        threshold=session_data.get("threshold", 0.0),
        confidence_upper_bound=session_data.get("confidence_upper_bound", 0.0),
        mean_fidelity=session_data.get("mean_fidelity", 0.0),
        attack_type=session_data.get("attack_type"),
        raw_assessment_string=session_data.get("raw_assessment_string", ""),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def get_session(db: DBSession, session_id: str) -> Optional[Session]:
    return db.query(Session).filter(Session.id == session_id).first()


def list_sessions(db: DBSession, limit: int = 50, offset: int = 0) -> list[Session]:
    return (
        db.query(Session)
        .order_by(Session.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


def get_sessions_since(db: DBSession, since: datetime) -> list[Session]:
    return (
        db.query(Session)
        .filter(Session.timestamp >= since)
        .order_by(Session.timestamp.desc())
        .all()
    )


def create_telemetry_logs(db: DBSession, session_id: str, logs: list[dict]) -> None:
    for log in logs:
        record = TelemetryLog(
            session_id=session_id,
            position_index=log["position_index"],
            basis=log["basis"],
            bell_outcome=log["bell_outcome"],
            expected_correction=log["expected_correction"],
            actual_correction=log["actual_correction"],
            fidelity=log["fidelity"],
            match=log["match"],
        )
        db.add(record)
    db.commit()


def create_threat_event(db: DBSession, session_id: str, event_data: dict) -> ThreatEvent:
    record = ThreatEvent(
        session_id=session_id,
        threat_type=event_data["threat_type"],
        severity=event_data["severity"],
        observed_evidence=event_data["observed_evidence"],
        protocol_impact=event_data["protocol_impact"],
        timestamp=event_data.get("timestamp", datetime.now(timezone.utc).replace(tzinfo=None)),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def list_threat_events(
    db: DBSession, limit: int = 50, severity: Optional[str] = None
) -> list[ThreatEvent]:
    query = db.query(ThreatEvent)
    if severity is not None:
        query = query.filter(ThreatEvent.severity == severity)
    return query.order_by(ThreatEvent.timestamp.desc()).limit(limit).all()


def get_threat_counts_by_severity(db: DBSession, since: datetime) -> dict:
    rows = (
        db.query(ThreatEvent.severity, func.count(ThreatEvent.id))
        .filter(ThreatEvent.timestamp >= since)
        .group_by(ThreatEvent.severity)
        .all()
    )
    return {row[0]: row[1] for row in rows}


def get_threat_type_breakdown(db: DBSession, since: datetime) -> dict[str, int]:
    rows = (
        db.query(ThreatEvent.threat_type, func.count(ThreatEvent.id))
        .filter(ThreatEvent.timestamp >= since)
        .group_by(ThreatEvent.threat_type)
        .all()
    )
    return {row[0]: row[1] for row in rows}


def get_telemetry_logs_for_session(db: DBSession, session_id: str) -> list[TelemetryLog]:
    return (
        db.query(TelemetryLog)
        .filter(TelemetryLog.session_id == session_id)
        .order_by(TelemetryLog.position_index.asc())
        .all()
    )


def list_telemetry_logs(db: DBSession, limit: int = 100) -> list[TelemetryLog]:
    return (
        db.query(TelemetryLog)
        .order_by(TelemetryLog.id.desc())
        .limit(limit)
        .all()
    )

