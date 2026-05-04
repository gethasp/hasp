package setupmodel

type StepRecord struct {
	Event   Event
	State   State
	Reason  TerminalReason
	Outputs []Output
}

type Trace struct {
	Name     string
	Mode     Mode
	Events   []Event
	Steps    []StepRecord
	Final    State
	Reason   TerminalReason
	Accepted CandidateID
	Outputs  []Output
}

func Run(name string, mode Mode, events []Event) Trace {
	machine := New(mode)
	trace := Trace{
		Name:   name,
		Mode:   mode,
		Events: append([]Event(nil), events...),
	}
	for _, event := range events {
		var outputs []Output
		machine, outputs = Step(machine, event)
		outputs = append([]Output(nil), outputs...)
		trace.Outputs = append(trace.Outputs, outputs...)
		trace.Steps = append(trace.Steps, StepRecord{
			Event:   event,
			State:   machine.State,
			Reason:  machine.Reason,
			Outputs: outputs,
		})
	}
	trace.Final = machine.State
	trace.Reason = machine.Reason
	trace.Accepted = machine.Accepted
	return trace
}

func CanonicalTraces() []Trace {
	return []Trace{
		Run("new_strong_a_matches", NewVaultPromptMode(), []Event{
			EventStrongCandidateA,
			EventConfirmMatchesPending,
		}),
		Run("new_empty_then_strong_a_matches", NewVaultPromptMode(), []Event{
			EventEmptyLine,
			EventStrongCandidateA,
			EventConfirmMatchesPending,
		}),
		Run("new_whitespace_then_strong_a_matches", NewVaultPromptMode(), []Event{
			EventWhitespaceLine,
			EventStrongCandidateA,
			EventConfirmMatchesPending,
		}),
		Run("new_weak_retries_then_strong_a_matches", NewVaultPromptMode(), []Event{
			EventWeakCandidateA,
			EventConfirmMatchesPending,
			EventStrongCandidateA,
			EventConfirmMatchesPending,
		}),
		Run("new_skip_policy_weak_a_matches", Mode{
			Source:             SourcePromptReader,
			SkipPasswordPolicy: true,
			InteractiveRetry:   true,
		}, []Event{
			EventWeakCandidateA,
			EventConfirmMatchesPending,
		}),
		Run("new_confirm_empty_then_strong_a_matches", NewVaultPromptMode(), []Event{
			EventStrongCandidateA,
			EventEmptyLine,
			EventConfirmMatchesPending,
		}),
		Run("new_confirm_differs_then_strong_a_matches", NewVaultPromptMode(), []Event{
			EventStrongCandidateA,
			EventConfirmDiffers,
			EventStrongCandidateA,
			EventConfirmMatchesPending,
		}),
		Run("existing_empty_then_right", ExistingVaultPromptMode(), []Event{
			EventEmptyLine,
			EventExistingRightPassword,
		}),
		Run("existing_wrong_then_right", ExistingVaultPromptMode(), []Event{
			EventExistingWrongPassword,
			EventExistingRightPassword,
		}),
		Run("existing_wrong_noninteractive_rejected", Mode{
			VaultExists:      true,
			Source:           SourceNonInteractive,
			InteractiveRetry: false,
		}, []Event{
			EventExistingWrongPassword,
		}),
		Run("env_empty_rejected", Mode{Source: SourcePasswordEnv}, []Event{
			EventEmptyLine,
		}),
		Run("stdin_empty_rejected", Mode{Source: SourcePasswordStdin}, []Event{
			EventEmptyEOF,
		}),
		Run("prompt_reader_empty_eof_rejected", NewVaultPromptMode(), []Event{
			EventEmptyEOF,
		}),
		Run("interactive_empty_eof_then_interrupt", Mode{
			Source:           SourceInteractiveDevice,
			InteractiveRetry: true,
		}, []Event{
			EventEmptyEOF,
			EventInterrupt,
		}),
		Run("empty_then_output_error", NewVaultPromptMode(), []Event{
			EventEmptyLine,
			EventOutputError,
		}),
		Run("empty_then_input_error", NewVaultPromptMode(), []Event{
			EventEmptyLine,
			EventInputError,
		}),
	}
}

func NewVaultPromptMode() Mode {
	return Mode{
		Source:           SourcePromptReader,
		InteractiveRetry: true,
	}
}

func ExistingVaultPromptMode() Mode {
	return Mode{
		VaultExists:      true,
		Source:           SourcePromptReader,
		InteractiveRetry: true,
	}
}

func EventsFromBytes(data []byte) []Event {
	if len(data) == 0 {
		return nil
	}
	events := make([]Event, 0, len(data))
	for _, b := range data {
		switch b % 13 {
		case 0:
			events = append(events, EventEmptyLine)
		case 1:
			events = append(events, EventWhitespaceLine)
		case 2:
			events = append(events, EventEmptyEOF)
		case 3:
			events = append(events, EventWeakCandidateA)
		case 4:
			events = append(events, EventStrongCandidateA)
		case 5:
			events = append(events, EventStrongCandidateB)
		case 6:
			events = append(events, EventConfirmMatchesPending)
		case 7:
			events = append(events, EventConfirmDiffers)
		case 8:
			events = append(events, EventExistingWrongPassword)
		case 9:
			events = append(events, EventExistingRightPassword)
		case 10:
			events = append(events, EventInterrupt)
		case 11:
			events = append(events, EventInputError)
		default:
			events = append(events, EventOutputError)
		}
	}
	return events
}
