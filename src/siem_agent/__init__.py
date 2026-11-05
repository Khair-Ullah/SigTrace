"""siem-agent: lightweight log shipper for the SIEM platform.

Collects local logs (files, Windows Event Log), spools them to disk and
ships them in batches to the server's ``POST /api/ingest`` endpoint.
Deliberately dependency-light (stdlib + PyYAML) so it can run on any host.
"""
from __future__ import annotations

__version__ = "1.0.0"
