package domain

import "time"

// AuditEventType names an audit event (PRD section 12, FR-11).
type AuditEventType string

// Audit events.
const (
	AuditMint        AuditEventType = "mint"
	AuditRefresh     AuditEventType = "refresh"
	AuditServe       AuditEventType = "serve"
	AuditFailure     AuditEventType = "failure"
	AuditStateChange AuditEventType = "state_change"
	AuditRevoke      AuditEventType = "revoke"
	AuditStart       AuditEventType = "start"
)

// Audit results.
const (
	ResultOK     = "ok"
	ResultError  = "error"
	ResultDenied = "denied"
)

// AuditEvent carries exactly the fields of PRD section 12 and no secret. The
// JSON names are the SIEM contract.
type AuditEvent struct {
	TS         time.Time      `json:"ts"`
	AgentID    string         `json:"agent_id"`
	Event      AuditEventType `json:"event"`
	Provider   string         `json:"provider,omitempty"`
	Audience   string         `json:"audience,omitempty"`
	JTI        string         `json:"jti,omitempty"`
	ExpiresAt  *time.Time     `json:"expires_at,omitempty"`
	CallerUID  *int           `json:"caller_uid,omitempty"`
	CallerPID  *int           `json:"caller_pid,omitempty"`
	CallerExe  string         `json:"caller_exe,omitempty"`
	Result     string         `json:"result"`
	ErrorClass string         `json:"error_class,omitempty"`
	// Detail holds non-secret context such as "valid->degraded" or the daemon
	// version at start.
	Detail string `json:"detail,omitempty"`
}

// WithCaller returns e with the caller fields set from c.
func (e AuditEvent) WithCaller(c CallerInfo) AuditEvent {
	uid, pid := c.UID, c.PID
	e.CallerUID, e.CallerPID, e.CallerExe = &uid, &pid, c.Exe
	return e
}

// WithCredential returns e with audience and expiry set from cred.
func (e AuditEvent) WithCredential(cred Credential) AuditEvent {
	e.Audience = cred.Audience()
	exp := cred.ExpiresAt
	e.ExpiresAt = &exp
	if j := cred.Meta[MetaJTI]; j != "" {
		e.JTI = j
	}
	return e
}

// WithError sets Result and ErrorClass from err.
func (e AuditEvent) WithError(err error) AuditEvent {
	if err == nil {
		e.Result = ResultOK
		return e
	}
	e.Result, e.ErrorClass = ResultError, ErrorClass(err)
	return e
}
