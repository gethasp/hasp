package app

import (
	"bytes"
	"strings"
	"testing"
)

// TestHelpStringsDropConsumer guards the user-visible rename of the
// internal "consumer" term: the word should not appear in any rendered
// help topic. Internal struct names (AppConsumer/AgentConsumer) and
// audit-event schema keys (consumer_type/consumer_name) are explicitly
// out of scope.
func TestHelpStringsDropConsumer(t *testing.T) {
	lockAppSeams(t)

	topics := [][]string{
		{"app"},
		{"app", "connect"},
		{"app", "install"},
		{"app", "list"},
		{"app", "disconnect"},
		{"agent"},
		{"agent", "connect"},
		{"agent", "disconnect"},
	}

	for _, topic := range topics {
		var buf bytes.Buffer
		if err := printHelpTopic(&buf, topic); err != nil {
			t.Errorf("help %v: %v", topic, err)
			continue
		}
		if strings.Contains(buf.String(), "consumer") {
			t.Errorf("help %v still mentions 'consumer':\n%s", topic, buf.String())
		}
	}
}

// TestRenderListsDropConsumerLabels verifies the empty-list and stage
// titles for the app/agent listings no longer say "consumer".
func TestRenderListsDropConsumerLabels(t *testing.T) {
	lockAppSeams(t)

	var appBuf bytes.Buffer
	if err := renderAppConsumerList(&appBuf, nil); err != nil {
		t.Fatalf("renderAppConsumerList: %v", err)
	}
	if strings.Contains(appBuf.String(), "consumer") {
		t.Errorf("app list output mentions 'consumer':\n%s", appBuf.String())
	}

	var agentBuf bytes.Buffer
	if err := renderAgentConsumerList(&agentBuf, nil); err != nil {
		t.Fatalf("renderAgentConsumerList: %v", err)
	}
	if strings.Contains(agentBuf.String(), "consumer") {
		t.Errorf("agent list output mentions 'consumer':\n%s", agentBuf.String())
	}
}
