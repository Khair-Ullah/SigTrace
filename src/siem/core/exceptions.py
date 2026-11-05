"""Custom exceptions for the SIEM engine."""


class SIEMError(Exception):
    """Base exception for all SIEM errors."""


class ConfigError(SIEMError):
    """Configuration loading or validation error."""


class ParseError(SIEMError):
    """Log parsing or normalization error."""


class RuleError(SIEMError):
    """Rule loading or validation error."""


class RuleValidationError(RuleError):
    """A rule file failed schema validation."""


class StorageError(SIEMError):
    """Database or persistence error."""


class IngestionError(SIEMError):
    """Log ingestion error (syslog, file tailing)."""


class CorrelationError(SIEMError):
    """Alert correlation error."""
