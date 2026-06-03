package brokerops

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/auditlog"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

var (
	canonicalProjectRootFn = store.CanonicalProjectRoot
	newManagerFn           = runtime.NewManager
	resolveReferenceFn     = (*store.Handle).ResolveReference
	getItemFn              = (*store.Handle).GetItem
	authorizeFn            = (*store.Handle).Authorize
	authorizeAndConsumeFn  = (*store.Handle).AuthorizeAndConsume
	grantProjectLeaseFn    = (*store.Handle).GrantProjectLease
	grantSecretUseFn       = (*store.Handle).GrantSecretUse
	grantConvenienceFn     = (*store.Handle).GrantConvenience
	consumeProjectLeaseFn  = (*store.Handle).ConsumeProjectLease
)

// Flow:
//
//   CLI/MCP caller
//        |
//        v
//   EnsureSession
//        |
//        v
//   Resolve binding/reference
//        |
//        v
//   Authorize item or capture
//
// The point of this package is to keep session-aware authorization logic
// identical across CLI and MCP surfaces.

type Session struct {
	Token string
	Info  runtime.SessionView
}

type Connector interface {
	EnsureDaemon(context.Context) error
	Connect(context.Context) (*runtime.Client, error)
}

type managerConnector struct {
	manager *runtime.Manager
}

func (c managerConnector) EnsureDaemon(ctx context.Context) error {
	return c.manager.EnsureDaemon(ctx)
}

func (c managerConnector) Connect(ctx context.Context) (*runtime.Client, error) {
	return runtime.Dial(ctx, c.manager.SocketPath())
}

func EnsureSession(ctx context.Context, connector Connector, projectRoot string, providedToken string, hostLabel string) (Session, error) {
	canonicalRoot, err := canonicalProjectRootFn(ctx, projectRoot)
	if err != nil {
		return Session{}, err
	}
	client, err := ensureClient(ctx, connector)
	if err != nil {
		return Session{}, err
	}
	defer client.Close()

	if strings.TrimSpace(providedToken) != "" {
		reply, err := client.ResolveSession(ctx, providedToken)
		if err != nil {
			return Session{}, fmt.Errorf("resolve session: %w", err)
		}
		if reply.Session.ProjectRoot != canonicalRoot {
			return Session{}, fmt.Errorf("session project root mismatch: have %s want %s", reply.Session.ProjectRoot, canonicalRoot)
		}
		return Session{Token: providedToken, Info: reply.Session}, nil
	}

	reply, err := client.OpenSession(ctx, runtime.OpenSessionRequest{
		HostLabel:    hostLabel,
		ProjectRoot:  canonicalRoot,
		TTLSeconds:   int(runtime.DefaultSessionTTL.Seconds()),
		AuditHMACKey: auditlog.GetHMACKey(),
	})
	if err != nil {
		return Session{}, err
	}

	return Session{
		Token: reply.SessionToken,
		Info: runtime.SessionView{
			ID:          reply.SessionID,
			LocalUser:   reply.LocalUser,
			HostLabel:   reply.HostLabel,
			ProjectRoot: reply.ProjectRoot,
			ExpiresAt:   reply.ExpiresAt,
			LastSeenAt:  reply.LastSeenAt,
		},
	}, nil
}

func EnsureSessionWithManager(ctx context.Context, projectRoot string, providedToken string, hostLabel string) (Session, error) {
	manager, err := newManagerFn()
	if err != nil {
		return Session{}, err
	}
	return EnsureSession(ctx, managerConnector{manager: manager}, projectRoot, providedToken, hostLabel)
}

func AuthorizeReference(
	ctx context.Context,
	handle *store.Handle,
	bindingID string,
	projectRoot string,
	sessionToken string,
	reference string,
	operation store.Operation,
	projectGrant store.GrantScope,
	secretGrant store.GrantScope,
	convenienceGrant store.GrantScope,
	window time.Duration,
	destinationPath string,
) (store.Item, error) {
	resolved, err := resolveReferenceFn(handle, ctx, projectRoot, reference)
	if err != nil {
		return store.Item{}, err
	}
	item, err := getItemFn(handle, resolved.ItemName)
	if err != nil {
		return store.Item{}, err
	}
	request := store.AccessRequest{
		Operation:       operation,
		BindingID:       bindingID,
		SessionToken:    sessionToken,
		ItemName:        item.Name,
		Policy:          item.Metadata.Policy,
		DestinationPath: destinationPath,
		Aliases:         []string{reference},
	}
	for range 3 {
		decision := authorizeFn(handle, request)
		if decision.Allowed {
			var err error
			decision, err = authorizeAndConsumeFn(handle, request)
			if err != nil {
				return store.Item{}, err
			}
			if decision.Allowed {
				return item, nil
			}
		}
		if !decision.RequiresPrompt {
			return store.Item{}, fmt.Errorf("access denied: %s", decision.Reason)
		}
		switch decision.RequiredAction() {
		case store.AccessRequirementProjectLease, store.AccessRequirementProjectAndConvenience:
			if projectGrant == "" {
				return store.Item{}, fmt.Errorf("project lease required for %s", operation)
			}
			if _, err := grantProjectLeaseFn(handle, bindingID, sessionToken, projectGrant, window); err != nil {
				return store.Item{}, err
			}
		case store.AccessRequirementSecretGrant:
			if secretGrant == "" {
				return store.Item{}, fmt.Errorf("secret approval required for %s", item.Name)
			}
			relaxed := item.Metadata.Policy == store.PolicyAccess && secretGrant == store.GrantWindow
			if _, err := grantSecretUseFn(handle, bindingID, sessionToken, item.Name, secretGrant, window, relaxed); err != nil {
				return store.Item{}, err
			}
		case store.AccessRequirementConvenience:
			if convenienceGrant == "" {
				return store.Item{}, fmt.Errorf("convenience approval required for %s", destinationPath)
			}
			if _, err := grantConvenienceFn(handle, bindingID, sessionToken, destinationPath, []string{reference}, "user", convenienceGrant, window); err != nil {
				return store.Item{}, err
			}
		case store.AccessRequirementWriteGrant:
			return store.Item{}, errors.New("capture write grant required")
		default:
			return store.Item{}, fmt.Errorf("unsupported approval path: %s", decision.Reason)
		}
	}
	return store.Item{}, errors.New("approval still required after retry")
}

func AuthorizeItem(
	handle *store.Handle,
	bindingID string,
	sessionToken string,
	item store.Item,
	operation store.Operation,
	projectGrant store.GrantScope,
	secretGrant store.GrantScope,
	window time.Duration,
) (store.Item, error) {
	request := store.AccessRequest{
		Operation:    operation,
		BindingID:    bindingID,
		SessionToken: sessionToken,
		ItemName:     item.Name,
		Policy:       item.Metadata.Policy,
	}
	for range 3 {
		decision := authorizeFn(handle, request)
		if decision.Allowed {
			var err error
			decision, err = authorizeAndConsumeFn(handle, request)
			if err != nil {
				return store.Item{}, err
			}
			if decision.Allowed {
				return item, nil
			}
		}
		if !decision.RequiresPrompt {
			return store.Item{}, fmt.Errorf("access denied: %s", decision.Reason)
		}
		switch decision.RequiredAction() {
		case store.AccessRequirementProjectLease:
			if projectGrant == "" {
				return store.Item{}, fmt.Errorf("project lease required for %s", operation)
			}
			if _, err := grantProjectLeaseFn(handle, bindingID, sessionToken, projectGrant, window); err != nil {
				return store.Item{}, err
			}
		case store.AccessRequirementSecretGrant:
			if secretGrant == "" {
				return store.Item{}, fmt.Errorf("secret approval required for %s", item.Name)
			}
			relaxed := item.Metadata.Policy == store.PolicyAccess && secretGrant == store.GrantWindow
			if _, err := grantSecretUseFn(handle, bindingID, sessionToken, item.Name, secretGrant, window, relaxed); err != nil {
				return store.Item{}, err
			}
		default:
			return store.Item{}, fmt.Errorf("unsupported approval path: %s", decision.Reason)
		}
	}
	return store.Item{}, errors.New("approval still required after retry")
}

func AuthorizeCapture(
	ctx context.Context,
	handle *store.Handle,
	bindingID string,
	sessionToken string,
	name string,
	projectGrant store.GrantScope,
	secretGrant store.GrantScope,
	window time.Duration,
	writeGrant bool,
) error {
	item, err := getItemFn(handle, name)
	if err == nil {
		_, err = AuthorizeItem(handle, bindingID, sessionToken, item, store.OperationCapture, projectGrant, secretGrant, window)
		return err
	}
	if !errors.Is(err, store.ErrItemNotFound) {
		return err
	}
	request := store.AccessRequest{
		Operation:    store.OperationCapture,
		BindingID:    bindingID,
		SessionToken: sessionToken,
		CreatingNew:  true,
	}
	decision := authorizeFn(handle, request)
	if decision.Allowed {
		return nil
	}
	if !decision.RequiresPrompt {
		return fmt.Errorf("access denied: %s", decision.Reason)
	}
	if decision.RequiredAction() == store.AccessRequirementProjectLease {
		if projectGrant == "" {
			return errors.New("project lease required for capture")
		}
		if _, err := grantProjectLeaseFn(handle, bindingID, sessionToken, projectGrant, window); err != nil {
			return err
		}
		decision = authorizeFn(handle, request)
	}
	if decision.RequiredAction() != store.AccessRequirementWriteGrant {
		return fmt.Errorf("unsupported capture approval path: %s", decision.Reason)
	}
	if !writeGrant {
		return errors.New("capture write grant required")
	}
	// New-item capture never returns an "Allowed" decision (it always prompts for
	// a write grant), so AuthorizeAndConsume's consume path never fires. Spend the
	// one-time project lease here so a single capture approval can't be reused for
	// a later list/run. No-op for session/window leases.
	if err := consumeProjectLeaseFn(handle, bindingID, sessionToken); err != nil {
		return err
	}
	return nil
}

func ensureClient(ctx context.Context, connector Connector) (*runtime.Client, error) {
	if err := connector.EnsureDaemon(ctx); err != nil {
		return nil, err
	}
	return connector.Connect(ctx)
}
