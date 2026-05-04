package setupmodel

import "testing"

func TestModelEmptyInputsNeverTerminateNewVaultFlow(t *testing.T) {
	trace := Run("empty_prefix_success", NewVaultPromptMode(), []Event{
		EventEmptyLine,
		EventWhitespaceLine,
		EventStrongCandidateA,
		EventConfirmMatchesPending,
	})

	if trace.Final != StateComplete {
		t.Fatalf("final=%q reason=%q", trace.Final, trace.Reason)
	}
	for i, step := range trace.Steps[:2] {
		if !EventIsEmpty(step.Event) {
			t.Fatalf("step %d event=%q", i, step.Event)
		}
		if step.State == StateComplete || step.State == StateInterrupted {
			t.Fatalf("empty step %d reached terminal state %q", i, step.State)
		}
		if len(step.Outputs) != 1 || step.Outputs[0] != OutputRetryEmpty {
			t.Fatalf("empty step %d outputs=%v", i, step.Outputs)
		}
	}
	if trace.Accepted != CandidateStrongA {
		t.Fatalf("accepted=%q", trace.Accepted)
	}
}

func TestModelSkipPolicyStillRequiresNonEmptyMatchingPasswords(t *testing.T) {
	trace := Run("skip_policy_requires_non_empty_match", Mode{
		Source:             SourcePromptReader,
		SkipPasswordPolicy: true,
		InteractiveRetry:   true,
	}, []Event{
		EventWhitespaceLine,
		EventStrongCandidateA,
		EventConfirmDiffers,
		EventWeakCandidateA,
		EventConfirmMatchesPending,
	})

	if trace.Final != StateComplete {
		t.Fatalf("final=%q reason=%q", trace.Final, trace.Reason)
	}
	if trace.Steps[0].State == StateComplete {
		t.Fatal("whitespace-only input completed setup")
	}
	if trace.Steps[2].Outputs[0] != OutputRetryMismatch {
		t.Fatalf("mismatch outputs=%v", trace.Steps[2].Outputs)
	}
	if trace.Accepted != CandidateWeakA {
		t.Fatalf("accepted=%q", trace.Accepted)
	}
}

func TestModelExistingResolveOnlyCompletesAfterNonEmptyInput(t *testing.T) {
	trace := Run("existing_empty_prefix_success", ExistingVaultPromptMode(), []Event{
		EventEmptyLine,
		EventWhitespaceLine,
		EventExistingRightPassword,
	})

	if trace.Final != StateComplete {
		t.Fatalf("final=%q reason=%q", trace.Final, trace.Reason)
	}
	if trace.Steps[0].Outputs[0] != OutputRetryEmpty || trace.Steps[1].Outputs[0] != OutputRetryEmpty {
		t.Fatalf("unexpected empty retries: %+v", trace.Steps[:2])
	}
	if trace.Accepted != CandidateExistingRight {
		t.Fatalf("accepted=%q", trace.Accepted)
	}
}

func TestModelTerminalReasonsAreCausal(t *testing.T) {
	tests := []struct {
		name   string
		mode   Mode
		event  Event
		state  State
		reason TerminalReason
	}{
		{
			name:   "interrupt",
			mode:   NewVaultPromptMode(),
			event:  EventInterrupt,
			state:  StateInterrupted,
			reason: ReasonInterrupt,
		},
		{
			name:   "input_error",
			mode:   NewVaultPromptMode(),
			event:  EventInputError,
			state:  StateIOFailed,
			reason: ReasonInputError,
		},
		{
			name:   "output_error",
			mode:   NewVaultPromptMode(),
			event:  EventOutputError,
			state:  StateIOFailed,
			reason: ReasonOutputError,
		},
		{
			name:   "store_error",
			mode:   NewVaultPromptMode(),
			event:  EventStoreError,
			state:  StateIOFailed,
			reason: ReasonStoreError,
		},
		{
			name:   "noninteractive_empty",
			mode:   Mode{Source: SourcePasswordEnv},
			event:  EventEmptyLine,
			state:  StateInputRejected,
			reason: ReasonNonInteractiveEmpty,
		},
		{
			name:   "existing_wrong_noninteractive",
			mode:   Mode{VaultExists: true, Source: SourceNonInteractive},
			event:  EventExistingWrongPassword,
			state:  StateInputRejected,
			reason: ReasonExistingWrongPassword,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trace := Run(tt.name, tt.mode, []Event{tt.event})
			if trace.Final != tt.state || trace.Reason != tt.reason {
				t.Fatalf("final=%q reason=%q", trace.Final, trace.Reason)
			}
		})
	}
}

func TestModelCoversInvalidAndTerminalBranches(t *testing.T) {
	existing := New(Mode{VaultExists: true})
	if existing.State != StatePromptExistingPassword || existing.Mode.Source != SourcePromptReader {
		t.Fatalf("existing initial machine=%+v", existing)
	}

	terminal := Machine{State: StateComplete}
	after, outputs := Step(terminal, EventInterrupt)
	if after.State != StateComplete || outputs != nil {
		t.Fatalf("terminal machine moved to %q outputs=%v", after.State, outputs)
	}

	machine, _ := Step(NewVaultPromptMode().machine(), EventStrongCandidateB)
	if machine.Pending != CandidateStrongB || machine.State != StatePromptConfirmPassword {
		t.Fatalf("strong_b pending machine=%+v", machine)
	}

	machine, outputs = Step(NewVaultPromptMode().machine(), EventExistingRightPassword)
	if machine.State != StateInputRejected || outputs[0] != OutputInvalidSequence {
		t.Fatalf("invalid new-password event machine=%+v outputs=%v", machine, outputs)
	}

	machine = NewVaultPromptMode().machine()
	machine.State = StatePromptConfirmPassword
	machine.Pending = CandidateNone
	machine, outputs = Step(machine, EventConfirmMatchesPending)
	if machine.State != StateInputRejected || outputs[0] != OutputInvalidSequence {
		t.Fatalf("confirm without pending machine=%+v outputs=%v", machine, outputs)
	}

	machine = NewVaultPromptMode().machine()
	machine.State = StatePromptConfirmPassword
	machine.Pending = CandidateStrongA
	machine, outputs = Step(machine, EventExistingRightPassword)
	if machine.State != StateInputRejected || outputs[0] != OutputInvalidSequence {
		t.Fatalf("invalid confirm event machine=%+v outputs=%v", machine, outputs)
	}

	machine = ExistingVaultPromptMode().machine()
	machine, outputs = Step(machine, EventExistingRightPassword)
	if machine.State != StateComplete || machine.Accepted != CandidateExistingRight || outputs[0] != OutputComplete {
		t.Fatalf("existing right machine=%+v outputs=%v", machine, outputs)
	}

	machine = ExistingVaultPromptMode().machine()
	machine, outputs = Step(machine, EventStrongCandidateA)
	if machine.State != StateInputRejected || outputs[0] != OutputInvalidSequence {
		t.Fatalf("invalid existing event machine=%+v outputs=%v", machine, outputs)
	}

	machine = NewVaultPromptMode().machine()
	machine.State = State("unknown")
	machine, outputs = Step(machine, EventStrongCandidateA)
	if machine.State != StateInputRejected || outputs[0] != OutputInvalidSequence {
		t.Fatalf("invalid state machine=%+v outputs=%v", machine, outputs)
	}

	for _, event := range []Event{EventInputError, EventOutputError, EventStoreError} {
		if !EventIsFault(event) {
			t.Fatalf("%q should be a fault", event)
		}
	}
	if EventIsFault(EventInterrupt) {
		t.Fatal("interrupt should not be an IO fault")
	}
}

func (m Mode) machine() Machine {
	return New(m)
}

func TestEventsFromBytesCoversEveryMapping(t *testing.T) {
	if events := EventsFromBytes(nil); events != nil {
		t.Fatalf("nil data mapped to %v", events)
	}
	events := EventsFromBytes([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	want := []Event{
		EventEmptyLine,
		EventWhitespaceLine,
		EventEmptyEOF,
		EventWeakCandidateA,
		EventStrongCandidateA,
		EventStrongCandidateB,
		EventConfirmMatchesPending,
		EventConfirmDiffers,
		EventExistingWrongPassword,
		EventExistingRightPassword,
		EventInterrupt,
		EventInputError,
		EventOutputError,
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("event %d=%q want %q", i, events[i], want[i])
		}
	}
}

func FuzzSetupPasswordTrace(f *testing.F) {
	for _, seed := range [][]byte{
		{0, 4, 6},
		{1, 4, 7, 4, 6},
		{3, 6, 4, 6},
		{8, 9},
		{2},
		{10},
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		trace := Run("fuzz", NewVaultPromptMode(), EventsFromBytes(data))
		for i, step := range trace.Steps {
			if EventIsEmpty(step.Event) && (step.State == StateComplete || step.State == StateInterrupted) {
				t.Fatalf("empty event at step %d reached %q", i, step.State)
			}
			if step.State == StateIOFailed && !EventIsFault(step.Event) {
				t.Fatalf("io failure at step %d from event %q", i, step.Event)
			}
			if step.State == StateInterrupted && step.Event != EventInterrupt {
				t.Fatalf("interrupt at step %d from event %q", i, step.Event)
			}
		}
		if trace.Final == StateComplete {
			switch trace.Accepted {
			case CandidateWeakA, CandidateStrongA, CandidateStrongB, CandidateExistingRight:
			default:
				t.Fatalf("complete with accepted=%q", trace.Accepted)
			}
		}
	})
}
