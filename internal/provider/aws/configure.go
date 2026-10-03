package aws

import (
	"fmt"
	"strings"
)

// ProfileName is the AWS CLI profile `configure aws` writes.
const ProfileName = "agent"

// ProfileSnippet renders the ~/.aws/config profile (AWS-3), with
// role_session_name = agent id so CloudTrail attributes actions.
func ProfileSnippet(c Config) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[profile %s]\n", ProfileName)
	fmt.Fprintf(&b, "role_arn = %s\n", c.RoleARN)
	fmt.Fprintf(&b, "web_identity_token_file = %s\n", c.TokenFile)
	fmt.Fprintf(&b, "role_session_name = %s\n", c.AgentID)
	if c.Region != "" {
		fmt.Fprintf(&b, "region = %s\n", c.Region)
	}
	return b.String(), nil
}

// EnvSnippet renders the equivalent environment form, preferred when a tool
// misbehaves with profiles (PRD 7.1 CDK quirk).
func EnvSnippet(c Config) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "export AWS_ROLE_ARN=%s\n", c.RoleARN)
	fmt.Fprintf(&b, "export AWS_WEB_IDENTITY_TOKEN_FILE=%s\n", c.TokenFile)
	fmt.Fprintf(&b, "export AWS_ROLE_SESSION_NAME=%s\n", c.AgentID)
	if c.Region != "" {
		fmt.Fprintf(&b, "export AWS_REGION=%s\n", c.Region)
	}
	return b.String(), nil
}
