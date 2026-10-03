package domain

// State is the cache entry state (PRD section 9).
type State string

// Cache entry states.
const (
	StateEmpty          State = "empty"
	StateMinting        State = "minting"
	StateValid          State = "valid"
	StateRefreshing     State = "refreshing"
	StateDegraded       State = "degraded"
	StateRevoked        State = "revoked"
	StateReauthRequired State = "reauth_required"
)

// AllStates lists every state in declaration order.
var AllStates = []State{StateEmpty, StateMinting, StateValid, StateRefreshing, StateDegraded, StateRevoked, StateReauthRequired}

// String implements fmt.Stringer.
func (s State) String() string { return string(s) }

// Valid reports whether s is a known state.
func (s State) Valid() bool {
	for _, k := range AllStates {
		if s == k {
			return true
		}
	}
	return false
}

// Servable reports whether a credential may be served in this state. A
// degraded entry is not served (the API answers 503 with Retry-After).
func (s State) Servable() bool { return s == StateValid || s == StateRefreshing }

// Terminal reports whether no transition leaves the state.
func (s State) Terminal() bool { return s == StateRevoked }

var transitions = map[State][]State{
	StateEmpty:          {StateMinting, StateRevoked},
	StateMinting:        {StateValid, StateDegraded, StateReauthRequired, StateEmpty, StateRevoked},
	StateValid:          {StateRefreshing, StateDegraded, StateRevoked},
	StateRefreshing:     {StateValid, StateDegraded, StateReauthRequired, StateRevoked},
	StateDegraded:       {StateRefreshing, StateValid, StateReauthRequired, StateRevoked},
	StateReauthRequired: {StateMinting, StateRevoked},
	StateRevoked:        nil,
}

// CanTransition reports whether the state machine allows from -> to. Any
// non-terminal state may move to revoked, and revoked wins over a concurrent
// refresh. reauth_required leaves only through a new mint after enrollment.
func CanTransition(from, to State) bool {
	for _, t := range transitions[from] {
		if t == to {
			return true
		}
	}
	return false
}
