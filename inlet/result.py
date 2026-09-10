from dataclasses import dataclass


@dataclass
class Finding:
    file: str
    line: int
    call: str
    verdict: str
    snippet: str
