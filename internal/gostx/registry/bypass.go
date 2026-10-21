package registry

import (
	"context"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/bypass"
)

type bypassRegistry struct {
	registry[bypass.Bypass]
}

func (r *bypassRegistry) Register(name string, v bypass.Bypass) error {
	return r.registry.Register(name, v)
}

func (r *bypassRegistry) Get(name string) bypass.Bypass {
	if name != "" {
		return &bypassWrapper{name: name, r: r}
	}
	return nil
}

func (r *bypassRegistry) get(name string) bypass.Bypass {
	return r.registry.Get(name)
}

type bypassWrapper struct {
	name string
	r    *bypassRegistry
}

// Contains blocks everything when the named bypass is not registered: a
// config that names a bypass expects it to filter, so a missing one (a typo,
// or a plugin that failed to start) must not let all traffic through.
func (w *bypassWrapper) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	bp := w.r.get(w.name)
	if bp == nil {
		return true
	}
	return bp.Contains(ctx, network, addr, opts...)
}

func (p *bypassWrapper) IsWhitelist() bool {
	bp := p.r.get(p.name)
	if bp == nil {
		return false
	}
	return bp.IsWhitelist()
}
