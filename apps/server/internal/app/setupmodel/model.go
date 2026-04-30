package setupmodel

type State string

const (
	StatePromptNewPassword      State = "prompt_new_password"
	StatePromptConfirmPassword  State = "prompt_confirm_password"
	StatePromptExistingPassword State = "prompt_existing_password"
	StateComplete               State = "complete"
	StateInterrupted            State = "interrupted"
	StateIOFailed               State = "io_failed"
	StateInputRejected          State = "input_rejected"
	StatePolicyRejected         State = "policy_rejected"
)

type SourceKind string

const (
	SourceInteractiveDevice SourceKind = "interactive_device"
	SourcePromptReader      SourceKind = "prompt_reader"
	SourcePasswordEnv       SourceKind = "password_env"
	SourcePasswordStdin     SourceKind = "password_stdin"
	SourceNonInteractive    SourceKind = "non_interactive"
)

type Event string

const (
	EventEmptyLine             Event = "empty_line"
	EventWhitespaceLine        Event = "whitespace_line"
	EventEmptyEOF              Event = "empty_eof"
	EventWeakCandidateA        Event = "weak_candidate_a"
	EventStrongCandidateA      Event = "strong_candidate_a"
	EventStrongCandidateB      Event = "strong_candidate_b"
	EventConfirmMatchesPending Event = "confirm_matches_pending"
	EventConfirmDiffers        Event = "confirm_differs"
	EventExistingWrongPassword Event = "existing_wrong_password"
	EventExistingRightPassword Event = "existing_right_password"
	EventInterrupt             Event = "interrupt"
	EventInputError            Event = "input_error"
	EventOutputError           Event = "output_error"
	EventStoreError            Event = "store_error"
)

type Output string

const (
	OutputRetryEmpty      Output = "retry_empty"
	OutputRetryWeak       Output = "retry_weak"
	OutputRetryMismatch   Output = "retry_mismatch"
	OutputInvalidVault    Output = "invalid_vault_password"
	OutputComplete        Output = "complete"
	OutputInterrupted     Output = "interrupted"
	OutputIOFailed        Output = "io_failed"
	OutputInputRejected   Output = "input_rejected"
	OutputPolicyRejected  Output = "policy_rejected"
	OutputInvalidSequence Output = "invalid_sequence"
)

type CandidateID string

const (
	CandidateNone          CandidateID = "none"
	CandidateWeakA         CandidateID = "weak_a"
	CandidateStrongA       CandidateID = "strong_a"
	CandidateStrongB       CandidateID = "strong_b"
	CandidateExistingRight CandidateID = "existing_right"
)

type TerminalReason string

const (
	ReasonNone                  TerminalReason = "none"
	ReasonValidPassword         TerminalReason = "valid_password"
	ReasonInterrupt             TerminalReason = "interrupt"
	ReasonInputError            TerminalReason = "input_error"
	ReasonOutputError           TerminalReason = "output_error"
	ReasonStoreError            TerminalReason = "store_error"
	ReasonEmptyEOF              TerminalReason = "empty_eof"
	ReasonNonInteractiveEmpty   TerminalReason = "non_interactive_empty"
	ReasonExistingWrongPassword TerminalReason = "existing_wrong_password"
	ReasonInvalidSequence       TerminalReason = "invalid_sequence"
)

type Mode struct {
	VaultExists        bool
	Source             SourceKind
	SkipPasswordPolicy bool
	InteractiveRetry   bool
}

type Machine struct {
	Mode     Mode
	State    State
	Pending  CandidateID
	Accepted CandidateID
	Last     Event
	Reason   TerminalReason
}

func New(mode Mode) Machine {
	state := StatePromptNewPassword
	if mode.VaultExists {
		state = StatePromptExistingPassword
	}
	if mode.Source == "" {
		mode.Source = SourcePromptReader
	}
	return Machine{
		Mode:     mode,
		State:    state,
		Pending:  CandidateNone,
		Accepted: CandidateNone,
		Reason:   ReasonNone,
	}
}

func (m Machine) Terminal() bool {
	switch m.State {
	case StateComplete, StateInterrupted, StateIOFailed, StateInputRejected, StatePolicyRejected:
		return true
	default:
		return false
	}
}

func Step(m Machine, e Event) (Machine, []Output) {
	if m.Terminal() {
		return m, nil
	}
	m.Last = e

	switch e {
	case EventInterrupt:
		return m.terminal(StateInterrupted, ReasonInterrupt, CandidateNone), []Output{OutputInterrupted}
	case EventInputError:
		return m.terminal(StateIOFailed, ReasonInputError, CandidateNone), []Output{OutputIOFailed}
	case EventOutputError:
		return m.terminal(StateIOFailed, ReasonOutputError, CandidateNone), []Output{OutputIOFailed}
	case EventStoreError:
		return m.terminal(StateIOFailed, ReasonStoreError, CandidateNone), []Output{OutputIOFailed}
	case EventEmptyLine, EventWhitespaceLine:
		return stepEmptyLine(m)
	case EventEmptyEOF:
		return stepEmptyEOF(m)
	}

	switch m.State {
	case StatePromptNewPassword:
		return stepNewPassword(m, e)
	case StatePromptConfirmPassword:
		return stepConfirmPassword(m, e)
	case StatePromptExistingPassword:
		return stepExistingPassword(m, e)
	default:
		return m.terminal(StateInputRejected, ReasonInvalidSequence, CandidateNone), []Output{OutputInvalidSequence}
	}
}

func stepEmptyLine(m Machine) (Machine, []Output) {
	switch m.Mode.Source {
	case SourcePasswordEnv, SourcePasswordStdin, SourceNonInteractive:
		return m.terminal(StateInputRejected, ReasonNonInteractiveEmpty, CandidateNone), []Output{OutputInputRejected}
	default:
		return m, []Output{OutputRetryEmpty}
	}
}

func stepEmptyEOF(m Machine) (Machine, []Output) {
	if m.Mode.Source == SourceInteractiveDevice {
		return m, []Output{OutputRetryEmpty}
	}
	return m.terminal(StateInputRejected, ReasonEmptyEOF, CandidateNone), []Output{OutputInputRejected}
}

func stepNewPassword(m Machine, e Event) (Machine, []Output) {
	switch e {
	case EventWeakCandidateA:
		m.Pending = CandidateWeakA
		m.State = StatePromptConfirmPassword
		return m, nil
	case EventStrongCandidateA:
		m.Pending = CandidateStrongA
		m.State = StatePromptConfirmPassword
		return m, nil
	case EventStrongCandidateB:
		m.Pending = CandidateStrongB
		m.State = StatePromptConfirmPassword
		return m, nil
	default:
		return m.terminal(StateInputRejected, ReasonInvalidSequence, CandidateNone), []Output{OutputInvalidSequence}
	}
}

func stepConfirmPassword(m Machine, e Event) (Machine, []Output) {
	switch e {
	case EventConfirmDiffers:
		m.State = StatePromptNewPassword
		m.Pending = CandidateNone
		return m, []Output{OutputRetryMismatch}
	case EventConfirmMatchesPending:
		if m.Pending == CandidateNone {
			return m.terminal(StateInputRejected, ReasonInvalidSequence, CandidateNone), []Output{OutputInvalidSequence}
		}
		if m.Pending == CandidateWeakA && !m.Mode.SkipPasswordPolicy {
			m.State = StatePromptNewPassword
			m.Pending = CandidateNone
			return m, []Output{OutputRetryWeak}
		}
		return m.terminal(StateComplete, ReasonValidPassword, m.Pending), []Output{OutputComplete}
	default:
		return m.terminal(StateInputRejected, ReasonInvalidSequence, CandidateNone), []Output{OutputInvalidSequence}
	}
}

func stepExistingPassword(m Machine, e Event) (Machine, []Output) {
	switch e {
	case EventExistingWrongPassword:
		if m.Mode.InteractiveRetry {
			return m, []Output{OutputInvalidVault}
		}
		return m.terminal(StateInputRejected, ReasonExistingWrongPassword, CandidateNone), []Output{OutputInputRejected}
	case EventExistingRightPassword:
		return m.terminal(StateComplete, ReasonValidPassword, CandidateExistingRight), []Output{OutputComplete}
	default:
		return m.terminal(StateInputRejected, ReasonInvalidSequence, CandidateNone), []Output{OutputInvalidSequence}
	}
}

func (m Machine) terminal(state State, reason TerminalReason, accepted CandidateID) Machine {
	m.State = state
	m.Reason = reason
	m.Pending = CandidateNone
	if accepted != CandidateNone {
		m.Accepted = accepted
	}
	return m
}

func EventIsEmpty(e Event) bool {
	return e == EventEmptyLine || e == EventWhitespaceLine || e == EventEmptyEOF
}

func EventIsFault(e Event) bool {
	return e == EventInputError || e == EventOutputError || e == EventStoreError
}
