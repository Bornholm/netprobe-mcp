package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Registry struct {
	reg *prometheus.Registry

	ProbesTotal       *prometheus.CounterVec
	DenialsTotal      *prometheus.CounterVec
	ProbeDurationSecs *prometheus.HistogramVec
}

func New() *Registry {
	reg := prometheus.NewRegistry()
	r := &Registry{
		reg: reg,
		ProbesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "probe_mcp_probes_total",
			Help: "Total probes by tool and outcome.",
		}, []string{"tool", "outcome"}),
		DenialsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "probe_mcp_denials_total",
			Help: "Authorisation denials by tool and category.",
		}, []string{"tool", "category"}),
		ProbeDurationSecs: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "probe_mcp_probe_duration_seconds",
			Help:    "Probe duration in seconds.",
			Buckets: []float64{.01, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
		}, []string{"tool"}),
	}
	reg.MustRegister(r.ProbesTotal, r.DenialsTotal, r.ProbeDurationSecs)
	return r
}

func (r *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

// HandlerAt returns an http.Handler that serves the metrics at the given path.
func (r *Registry) HandlerAt(_ string) http.Handler { return r.Handler() }
