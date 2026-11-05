"""Constants used across the SIEM engine."""

# Severity levels (ordered low -> critical)
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

SEVERITY_ORDER = {
    SEVERITY_LOW: 0,
    SEVERITY_MEDIUM: 1,
    SEVERITY_HIGH: 2,
    SEVERITY_CRITICAL: 3,
}

VALID_SEVERITIES = set(SEVERITY_ORDER.keys())

# Incident status lifecycle
STATUS_OPEN = "open"
STATUS_INVESTIGATING = "investigating"
STATUS_CLOSED = "closed"

VALID_STATUSES = {STATUS_OPEN, STATUS_INVESTIGATING, STATUS_CLOSED}

# User roles
ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_VIEWER = "viewer"

VALID_ROLES = {ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER}

# Source types
SOURCE_SYSLOG = "syslog"
SOURCE_FILE = "file"

# Log source types (what kind of device/app produced the log)
SOURCETYPE_FIREWALL = "firewall"
SOURCETYPE_SSH = "ssh"
SOURCETYPE_WEB = "web"
SOURCETYPE_CUSTOM = "custom"

# Date/time
UTC_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

# Queue
DEFAULT_QUEUE_MAX_SIZE = 10000

# Streaming event persistence batching (flush when either limit hits)
EVENT_BATCH_SIZE = 500
EVENT_BATCH_SECONDS = 1.0

# Defaults
DEFAULT_CORRELATION_WINDOW = 300
DEFAULT_MIN_ALERTS_FOR_INCIDENT = 2
DEFAULT_SYSLOG_PORT = 514
DEFAULT_WEB_PORT = 5000
