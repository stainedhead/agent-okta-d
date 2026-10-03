package domain

import "testing"

func TestStates(t *testing.T) {
	if len(AllStates) != 7 {
		t.Fatal("seven states")
	}
	for _, s := range AllStates {
		if !s.Valid() || s.String() != string(s) {
			t.Fatal(s)
		}
	}
	if State("bogus").Valid() || State("").Valid() {
		t.Fatal("invalid accepted")
	}
	serv := map[State]bool{StateValid: true, StateRefreshing: true}
	for _, s := range AllStates {
		if s.Servable() != serv[s] {
			t.Fatalf("Servable(%s)", s)
		}
	}
	if !StateRevoked.Terminal() || StateValid.Terminal() {
		t.Fatal("Terminal")
	}
}

func TestTransitions(t *testing.T) {
	ok := [][2]State{
		{StateEmpty, StateMinting}, {StateMinting, StateValid}, {StateMinting, StateDegraded},
		{StateMinting, StateReauthRequired}, {StateValid, StateRefreshing}, {StateRefreshing, StateValid},
		{StateRefreshing, StateDegraded}, {StateDegraded, StateRefreshing}, {StateDegraded, StateValid},
		{StateReauthRequired, StateMinting}, {StateValid, StateRevoked}, {StateEmpty, StateRevoked},
		{StateDegraded, StateRevoked}, {StateReauthRequired, StateRevoked}, {StateRefreshing, StateReauthRequired},
	}
	for _, p := range ok {
		if !CanTransition(p[0], p[1]) {
			t.Errorf("%s -> %s should be allowed", p[0], p[1])
		}
	}
	bad := [][2]State{
		{StateRevoked, StateValid}, {StateRevoked, StateMinting}, {StateEmpty, StateValid},
		{StateValid, StateMinting}, {StateValid, StateValid}, {StateReauthRequired, StateValid},
		{State("x"), StateValid}, {StateValid, State("x")},
	}
	for _, p := range bad {
		if CanTransition(p[0], p[1]) {
			t.Errorf("%s -> %s should be refused", p[0], p[1])
		}
	}
}
