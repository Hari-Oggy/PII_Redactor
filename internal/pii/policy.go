package pii

import (
	"strings"

	"github.com/enterprise/pii-gateway/pkg/models"
)

// PolicyAction defines how a PII match should be handled.
type PolicyAction string

const (
	ActionBlock  PolicyAction = "BLOCK"
	ActionRedact PolicyAction = "REDACT"
	ActionAllow  PolicyAction = "ALLOW"
)

// PolicyEngine determines the appropriate action for a given PII type
// based on the immutable UserContext (e.g., Department).
type PolicyEngine struct {
	// departmentRules maps department -> piiType -> Action
	departmentRules map[string]map[string]PolicyAction
	defaultAction   PolicyAction
}

// NewPolicyEngine initializes the RBAC rules.
func NewPolicyEngine() *PolicyEngine {
	// In a real system, these would be loaded from a config or database.
	// For this gateway, we hardcode the Phase 6 departmental rules.
	rules := map[string]map[string]PolicyAction{
		"HR": {
			"SSN":         ActionAllow,
			"CREDIT_CARD": ActionRedact,
			"EMAIL":       ActionAllow,
		},
		"FINANCE": {
			"SSN":          ActionRedact,
			"CREDIT_CARD":  ActionAllow,
			"BANK_ACCOUNT": ActionAllow,
		},
		"ENGINEERING": {
			"CREDENTIAL": ActionBlock,
			"API_KEY":    ActionBlock,
			"IP_ADDRESS": ActionAllow,
			"EMAIL":      ActionRedact,
		},
	}

	return &PolicyEngine{
		departmentRules: rules,
		defaultAction:   ActionRedact, // Default is secure-by-default (Redact)
	}
}

// Evaluate determines the action for a specific PII type and UserContext.
// Conflict resolution is strictly: BLOCK > REDACT > ALLOW.
// If a type is globally blocked, or if the department rule dictates it,
// the strict hierarchical resolution applies.
func (pe *PolicyEngine) Evaluate(ctx models.UserContext, piiType string) PolicyAction {
	dept := strings.ToUpper(ctx.Department)

	// Global strict blocks (e.g., no one is *ever* allowed to send API keys in plaintext to the LLM)
	if piiType == "API_KEY" || piiType == "CREDENTIAL" {
		return ActionBlock
	}

	// Check department-specific rules
	if deptMap, deptExists := pe.departmentRules[dept]; deptExists {
		if action, ruleExists := deptMap[strings.ToUpper(piiType)]; ruleExists {
			return action
		}
	}

	// Default fallback
	return pe.defaultAction
}
