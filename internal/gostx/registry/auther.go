package registry

import (
	"context"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/auth"
)

type autherRegistry struct {
	registry[auth.Authenticator]
}

func (r *autherRegistry) Register(name string, v auth.Authenticator) error {
	return r.registry.Register(name, v)
}

func (r *autherRegistry) Get(name string) auth.Authenticator {
	if name != "" {
		return &autherWrapper{name: name, r: r}
	}
	return nil
}

func (r *autherRegistry) get(name string) auth.Authenticator {
	return r.registry.Get(name)
}

type autherWrapper struct {
	name string
	r    *autherRegistry
}

// Authenticate refuses every login when the named auther is not registered,
// for the same reason as bypassWrapper.Contains.
func (w *autherWrapper) Authenticate(ctx context.Context, user, password string, opts ...auth.Option) (string, bool) {
	v := w.r.get(w.name)
	if v == nil {
		return "", false
	}
	return v.Authenticate(ctx, user, password, opts...)
}
