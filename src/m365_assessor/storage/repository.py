from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from m365_assessor.models.assessment import AssessmentDocument


class Base(DeclarativeBase):
    pass


class AssessmentRecord(Base):
    __tablename__ = "assessments"

    assessment_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    document_json: Mapped[str] = mapped_column(Text)


class AssessmentRepository:
    """SQLAlchemy repository usable with SQLite now and PostgreSQL later."""

    def __init__(self, database_url: str) -> None:
        self.engine = create_engine(database_url)

    def initialize(self) -> None:
        Base.metadata.create_all(self.engine)

    def save(self, document: AssessmentDocument) -> None:
        record = AssessmentRecord(
            assessment_id=str(document.assessment.id),
            tenant_id=document.tenant.tenant_id,
            started_at=document.assessment.started_at,
            document_json=document.model_dump_json(),
        )
        with Session(self.engine) as session:
            session.merge(record)
            session.commit()

    def get(self, assessment_id: str) -> AssessmentDocument | None:
        with Session(self.engine) as session:
            record = session.get(AssessmentRecord, assessment_id)
            if record is None:
                return None
            return AssessmentDocument.model_validate_json(record.document_json)
