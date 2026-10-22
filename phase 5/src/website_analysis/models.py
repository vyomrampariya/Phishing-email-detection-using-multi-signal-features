from dataclasses import dataclass, asdict
@dataclass
class ComponentResult:
    score: float | None
    status: str
    evidence: list
    source: str
    explanation: str
    def to_dict(self): return asdict(self)
