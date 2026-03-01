"""
sinks.py — Security Sink Definitions

Every vulnerability type is a named sink.
Adding a new vulnerability = adding one SinkDef here.
No changes to the analysis architecture needed.

A sink fires when:
  1. The call/expression matches the trigger pattern
  2. At least one argument is tainted (carries attacker-controlled data)
  3. The current path has NOT passed through a recognized guard

Each SinkDef also provides the dissonance message:
  Γ cannot prove φ = "input at this sink is safe"
"""

from dataclasses import dataclass
from typing import Set, Optional, Callable


@dataclass
class SinkDef:
    """Definition of a security sink — a dangerous operation that should not receive tainted input."""
    vuln_type: str
    severity: str                       # CRITICAL | HIGH | MEDIUM | LOW
    reason: str                         # Why this is dangerous
    fix: str                            # How to fix it
    exploitability: str                 # VERY LIKELY | LIKELY | POSSIBLE
    exploit_reason: str                 # Brief exploit explanation

    # Matching criteria — checked by the taint analyzer
    call_names: Set[str] = None         # Function/method names that are sinks
    method_attrs: Set[str] = None       # Attribute names (cursor.execute → 'execute')
    requires_shell_true: bool = False   # Command sinks only fire with shell=True
    safe_variants: Set[str] = None      # Call names that are SAFE versions of this sink
    check_fn: Optional[Callable] = None # Custom check beyond name matching

    def __post_init__(self):
        self.call_names = self.call_names or set()
        self.method_attrs = self.method_attrs or set()
        self.safe_variants = self.safe_variants or set()


# ── Sink Registry ─────────────────────────────────────────────────────────────

SQL_INJECTION = SinkDef(
    vuln_type='SQL Injection',
    severity='HIGH',
    reason='User input concatenated into SQL query — allows database manipulation',
    fix='Use parameterized queries: cursor.execute("... WHERE id = %s", (uid,))',
    exploitability='VERY LIKELY',
    exploit_reason='Database can be manipulated directly — read, modify, or delete data',
    method_attrs={'execute', 'executemany'},
)

COMMAND_INJECTION = SinkDef(
    vuln_type='Command Injection',
    severity='CRITICAL',
    reason='User input executed by OS shell — allows arbitrary command execution',
    fix='Avoid shell=True. Pass arguments as a list: subprocess.run(["cmd", arg])',
    exploitability='VERY LIKELY',
    exploit_reason='Direct OS command execution — full server compromise possible',
    call_names={'system', 'popen'},
    method_attrs={'system'},
    requires_shell_true=True,   # subprocess.run etc. only dangerous with shell=True
)

# Separate entry for os.system (always dangerous, no shell=True needed)
OS_COMMAND = SinkDef(
    vuln_type='Command Injection',
    severity='CRITICAL',
    reason='User input passed to os.system() — allows arbitrary command execution',
    fix='Do not use os.system() with user input. Use subprocess with a list of arguments.',
    exploitability='VERY LIKELY',
    exploit_reason='Direct OS command execution — full server compromise possible',
    call_names={'system'},
    requires_shell_true=False,
)

PATH_TRAVERSAL = SinkDef(
    vuln_type='Path Traversal',
    severity='MEDIUM',
    reason='User input used as filesystem path — allows reading arbitrary files',
    fix='Validate the path: use os.path.basename(), check against an allowed directory',
    exploitability='LIKELY',
    exploit_reason='Attacker can read sensitive files like /etc/passwd or application secrets',
    call_names={'open'},
    requires_shell_true=False,
)

XSS = SinkDef(
    vuln_type='Cross-Site Scripting (XSS)',
    severity='HIGH',
    reason='User input returned in HTML response without escaping — allows script injection',
    fix='Escape all user input: use markupsafe.escape() or Jinja2 auto-escaping',
    exploitability='LIKELY',
    exploit_reason='Attacker can execute JavaScript in victim browser — session hijack, phishing',
    call_names={'render_template_string', 'make_response'},
    requires_shell_true=False,
)

SSRF = SinkDef(
    vuln_type='Server-Side Request Forgery (SSRF)',
    severity='HIGH',
    reason='User input controls network request destination — server makes attacker-chosen requests',
    fix='Validate URLs against an allowlist of trusted domains',
    exploitability='LIKELY',
    exploit_reason='Attacker can access internal services, cloud metadata APIs, or pivot to internal network',
    call_names={'get', 'post', 'put', 'delete', 'patch', 'request', 'urlopen', 'urlretrieve'},
    requires_shell_true=False,
)

UNSAFE_DESERIALIZATION = SinkDef(
    vuln_type='Unsafe Deserialization',
    severity='CRITICAL',
    reason='Untrusted data deserialized — pickle/yaml.load can execute arbitrary code',
    fix='Never deserialize untrusted data. Use json.loads() instead of pickle.',
    exploitability='VERY LIKELY',
    exploit_reason='Crafted payload can execute arbitrary Python code on the server',
    call_names={'loads'},
    method_attrs={'loads', 'load'},
    safe_variants={'safe_load'},    # yaml.safe_load is safe
    requires_shell_true=False,
)

IDOR = SinkDef(
    vuln_type='Insecure Direct Object Reference (IDOR)',
    severity='HIGH',
    reason='Resource accessed by user-controlled ID without authorization check',
    fix='Verify the current user is authorized to access this resource before returning it',
    exploitability='VERY LIKELY',
    exploit_reason='Attacker can access any user\'s data by changing the ID parameter',
    # IDOR is detected by the auth analyzer, not call name matching
    call_names=set(),
    requires_shell_true=False,
)

MISSING_AUTH = SinkDef(
    vuln_type='Missing Authorization',
    severity='HIGH',
    reason='Sensitive operation performed without verifying the user has permission',
    fix='Add an authorization check before this operation: verify role, ownership, or permission',
    exploitability='VERY LIKELY',
    exploit_reason='Any authenticated user can perform this privileged action',
    # Also detected by auth analyzer
    call_names=set(),
    requires_shell_true=False,
)


# ── Lookup structures ─────────────────────────────────────────────────────────

# All sinks that trigger on method attribute names (cursor.execute etc.)
METHOD_SINKS = {
    attr: sink
    for sink in [SQL_INJECTION, COMMAND_INJECTION, UNSAFE_DESERIALIZATION]
    for attr in sink.method_attrs
}

# All sinks that trigger on function call names
CALL_SINKS = {
    name: sink
    for sink in [COMMAND_INJECTION, OS_COMMAND, PATH_TRAVERSAL, SSRF, UNSAFE_DESERIALIZATION]
    for name in sink.call_names
}

# Safe variants — calls that look like sinks but are actually safe
SAFE_VARIANTS = {
    name
    for sink in [SQL_INJECTION, COMMAND_INJECTION, PATH_TRAVERSAL, XSS,
                 SSRF, UNSAFE_DESERIALIZATION, IDOR, MISSING_AUTH]
    for name in sink.safe_variants
}

# Auth-sensitive operations: if tainted ID reaches these without a guard → IDOR/Missing Auth
AUTH_SENSITIVE_PATTERNS = {
    # Database reads with ID → IDOR
    'get_document', 'get_user', 'get_record', 'get_object', 'get_item',
    'get_post', 'get_order', 'get_file', 'get_message', 'get_profile',
    'get_account', 'get_payment', 'get_transaction', 'get_report',
    'fetch', 'find', 'lookup', 'load', 'retrieve', 'read',

    # Mutations → Missing Authorization
    'delete', 'delete_user', 'delete_record', 'delete_object', 'delete_item',
    'update', 'update_user', 'update_record', 'set_password', 'reset_password',
    'transfer', 'send', 'send_message', 'publish', 'drop', 'remove',
    'approve', 'reject', 'promote', 'demote', 'ban', 'unban',
    'pay', 'charge', 'refund', 'withdraw', 'deposit',
}

# Recognized authorization guards — if any of these appear on the path before a sink,
# the finding is suppressed on that path
AUTH_GUARDS = {
    # Hard stops
    'abort',
    'redirect',

    # Raise-based guards (detected separately via ast.Raise)
    # raise PermissionError, raise Forbidden, etc.

    # Permission check methods
    'is_admin',
    'is_authorized',
    'can_access',
    'has_permission',
    'has_role',
    'require_login',
    'login_required',
    'check_permission',
    'verify_access',
    'authorize',

    # Flask-Login / common auth decorators
    'current_user',
    'login_required',
}

# Recognized sanitizers — calling these clears taint from the argument
SANITIZERS = {
    'escape',           # markupsafe.escape
    'html.escape',
    'bleach.clean',
    'bleach.linkify',
    'quote',            # urllib.parse.quote
    'quote_plus',
    'sub',              # re.sub used for sanitization
    'strip',            # str.strip alone doesn't sanitize but context matters
    'basename',         # os.path.basename (path sanitizer)
    'secure_filename',  # werkzeug.utils.secure_filename
}

# Parametrized SQL patterns — these are SAFE even if arguments are tainted
# because the DB driver handles escaping
PARAMETERIZED_SQL_INDICATORS = {
    '%s', '?', ':name', '%(name)s'
}
