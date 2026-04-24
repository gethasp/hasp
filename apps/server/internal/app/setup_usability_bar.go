package app

// setupUsabilityBar defines the time and step budget for the setup onboarding
// flow.  MaxSeconds is the total wall-clock budget for a frictionless first
// run; Steps counts the discrete phases (setup init, bootstrap, brokered proof).
type setupUsabilityBarConfig struct {
	MaxSeconds int
	Steps      int
}

// setupUsabilityBar returns the usability bar configuration for the onboarding
// flow.  The values satisfy: 0 < MaxSeconds <= 120, Steps >= 1.
func setupUsabilityBar() setupUsabilityBarConfig {
	return setupUsabilityBarConfig{
		MaxSeconds: 120,
		Steps:      3,
	}
}
