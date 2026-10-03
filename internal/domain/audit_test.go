package domain

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestAuditEventJSON(t *testing.T) {
	c := goodCred()
	c.Meta[MetaJTI] = "jti-1"
	e := AuditEvent{TS: t0, AgentID: "a1", Event: AuditServe, Provider: "aws", Detail: "x"}.
		WithCredential(c).WithCaller(CallerInfo{UID: 501, PID: 99, Exe: "/usr/bin/git"}).WithError(nil)
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"ts", "agent_id", "event", "provider", "audience", "jti", "expires_at", "caller_uid", "caller_pid", "caller_exe", "result"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing %s in %s", k, b)
		}
	}
	if m["result"] != ResultOK || strings.Contains(string(b), sample) {
		t.Fatal(string(b))
	}
	e2 := AuditEvent{Event: AuditFailure}.WithError(errors.New("x"))
	if e2.Result != ResultError || e2.ErrorClass != "unknown" {
		t.Fatalf("%+v", e2)
	}
}
