"""Deterministic protocol extractors."""

from app.extractors.base import extract_candidates
from app.extractors.ftp import extract_ftp
from app.extractors.http import extract_http
from app.extractors.mongodb import extract_mongodb
from app.extractors.ssh import extract_ssh

EXTRACTORS = {
    "ssh": extract_ssh,
    "http": extract_http,
    "ftp": extract_ftp,
    "mongodb": extract_mongodb,
}

__all__ = ["EXTRACTORS", "extract_candidates"]
