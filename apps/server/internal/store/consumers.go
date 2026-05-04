package store

import (
	"errors"
	"slices"
	"strings"
)

var ErrConsumerNotFound = errors.New("consumer not found")

func (h *Handle) UpsertAppConsumer(consumer AppConsumer) (AppConsumer, error) {
	name := strings.TrimSpace(consumer.Name)
	if name == "" {
		return AppConsumer{}, errors.New("app consumer name is required")
	}
	if len(consumer.Command) == 0 {
		return AppConsumer{}, errors.New("app consumer command is required")
	}
	if h.state.AppConsumers == nil {
		h.state.AppConsumers = map[string]AppConsumer{}
	}
	now := h.store.now()
	existing, ok := h.state.AppConsumers[name]
	if ok {
		consumer.CreatedAt = existing.CreatedAt
	} else if consumer.CreatedAt.IsZero() {
		consumer.CreatedAt = now
	}
	consumer.Name = name
	consumer.UpdatedAt = now
	h.state.AppConsumers[name] = consumer
	err := persistEnvelope(h)
	if err == nil {
		h.store.appendAuditBestEffort("consumer.app.upsert", "user", map[string]any{"name": consumer.Name, "project_root": consumer.ProjectRoot})
	}
	return consumer, err
}

func (h *Handle) GetAppConsumer(name string) (AppConsumer, error) {
	if consumer, ok := h.state.AppConsumers[strings.TrimSpace(name)]; ok {
		return consumer, nil
	}
	return AppConsumer{}, ErrConsumerNotFound
}

func (h *Handle) DeleteAppConsumer(name string) error {
	name = strings.TrimSpace(name)
	if _, ok := h.state.AppConsumers[name]; !ok {
		return ErrConsumerNotFound
	}
	delete(h.state.AppConsumers, name)
	err := persistEnvelope(h)
	if err == nil {
		h.store.appendAuditBestEffort("consumer.app.delete", "user", map[string]any{"name": name})
	}
	return err
}

func (h *Handle) ListAppConsumers() []AppConsumer {
	out := make([]AppConsumer, 0, len(h.state.AppConsumers))
	for _, consumer := range h.state.AppConsumers {
		out = append(out, consumer)
	}
	slices.SortFunc(out, func(a, b AppConsumer) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

func (h *Handle) UpsertAgentConsumer(consumer AgentConsumer) (AgentConsumer, error) {
	name := strings.TrimSpace(consumer.Name)
	if name == "" {
		return AgentConsumer{}, errors.New("agent consumer name is required")
	}
	if strings.TrimSpace(consumer.AgentID) == "" {
		return AgentConsumer{}, errors.New("agent id is required")
	}
	if strings.TrimSpace(consumer.ConfigPath) == "" {
		return AgentConsumer{}, errors.New("agent consumer config path is required")
	}
	if h.state.AgentConsumers == nil {
		h.state.AgentConsumers = map[string]AgentConsumer{}
	}
	now := h.store.now()
	existing, ok := h.state.AgentConsumers[name]
	if ok {
		consumer.CreatedAt = existing.CreatedAt
	} else if consumer.CreatedAt.IsZero() {
		consumer.CreatedAt = now
	}
	consumer.Name = name
	consumer.UpdatedAt = now
	h.state.AgentConsumers[name] = consumer
	err := persistEnvelope(h)
	if err == nil {
		h.store.appendAuditBestEffort("consumer.agent.upsert", "user", map[string]any{"name": consumer.Name, "agent_id": consumer.AgentID})
	}
	return consumer, err
}

func (h *Handle) GetAgentConsumer(name string) (AgentConsumer, error) {
	if consumer, ok := h.state.AgentConsumers[strings.TrimSpace(name)]; ok {
		return consumer, nil
	}
	return AgentConsumer{}, ErrConsumerNotFound
}

func (h *Handle) DeleteAgentConsumer(name string) error {
	name = strings.TrimSpace(name)
	if _, ok := h.state.AgentConsumers[name]; !ok {
		return ErrConsumerNotFound
	}
	delete(h.state.AgentConsumers, name)
	err := persistEnvelope(h)
	if err == nil {
		h.store.appendAuditBestEffort("consumer.agent.delete", "user", map[string]any{"name": name})
	}
	return err
}

func (h *Handle) ListAgentConsumers() []AgentConsumer {
	out := make([]AgentConsumer, 0, len(h.state.AgentConsumers))
	for _, consumer := range h.state.AgentConsumers {
		out = append(out, consumer)
	}
	slices.SortFunc(out, func(a, b AgentConsumer) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out
}
