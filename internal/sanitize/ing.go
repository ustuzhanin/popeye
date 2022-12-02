package sanitize

import (
	"context"
	"github.com/derailed/popeye/internal/cache"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"

	"github.com/derailed/popeye/internal"
	"github.com/derailed/popeye/internal/issues"
)

type (
	// Ingress tracks Ingress sanitization.
	Ingress struct {
		*issues.Collector
		IngressLister
	}

	// IngLister list ingresses.
	IngLister interface {
		ListIngresses() map[string]*netv1.Ingress
	}

	// IngressLister list available Ingresss on a cluster.
	IngressLister interface {
		IngLister
		ServiceGetter
	}

	ServiceGetter interface {
		GetService(fqn string) *v1.Service
	}
)

// NewIngress returns a new sanitizer.
func NewIngress(co *issues.Collector, lister IngressLister) *Ingress {
	return &Ingress{
		Collector:     co,
		IngressLister: lister,
	}
}

// Sanitize cleanse the resource.
func (i *Ingress) Sanitize(ctx context.Context) error {
	for fqn, ing := range i.ListIngresses() {
		i.InitOutcome(fqn)
		ctx = internal.WithFQN(ctx, fqn)

		i.checkDeprecation(ctx, ing)
		i.checkService(ctx, ing)

		if i.NoConcerns(fqn) && i.Config.ExcludeFQN(internal.MustExtractSectionGVR(ctx), fqn) {
			i.ClearOutcome(fqn)
		}
	}

	return nil
}

func (i *Ingress) checkDeprecation(ctx context.Context, ing *netv1.Ingress) {
	const current = "networking.k8s.io/v1"
	rev, err := resourceRev(internal.MustExtractFQN(ctx), "Ingress", ing.Annotations)
	if err != nil {
		if rev = revFromLink(ing.SelfLink); rev == "" {
			return
		}
	}
	if rev != current {
		i.AddCode(ctx, 403, "Ingress", rev, current)
	}
}
func (i *Ingress) checkService(ctx context.Context, ing *netv1.Ingress) {
	if ing.Spec.DefaultBackend != nil {
		service := i.GetService(cache.FQN(ing.Namespace, ing.Spec.DefaultBackend.Service.Name))
		if service == nil {
			i.AddCode(ctx, 401, cache.FQN(ing.Namespace, ing.Spec.DefaultBackend.Service.Name))
		}
	}

	for _, rule := range ing.Spec.Rules {
		for _, path := range rule.HTTP.Paths {
			service := i.GetService(cache.FQN(ing.Namespace, path.Backend.Service.Name))
			if service == nil {
				i.AddCode(ctx, 401, cache.FQN(ing.Namespace, path.Backend.Service.Name))
			}

		}
	}
}
