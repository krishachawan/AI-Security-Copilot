from pydantic import BaseModel, Field
from typing import Optional


class SASTFinding(BaseModel):
    tool: str

    rule_id: Optional[str] = None
    rule_name: Optional[str] = None

    severity: str = "UNKNOWN"
    confidence: str = "UNKNOWN"

    cwe: Optional[str] = None
    owasp: Optional[str] = None

    file: str

    line: Optional[int] = None
    end_line: Optional[int] = None

    column: Optional[int] = None
    end_column: Optional[int] = None

    message: str

    code: Optional[str] = None
    reference: Optional[str] = None


class SASTSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    unknown: int = 0
    total: int = 0


class SASTScanResult(BaseModel):
    status: str
    language: str
    file: str

    findings: list[SASTFinding] = Field(
        default_factory=list
    )

    summary: SASTSummary

    scanner_errors: list[str] = Field(
        default_factory=list
    )