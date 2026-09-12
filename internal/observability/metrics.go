package observability

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics is the process-wide Prometheus registry and the counters/
// histograms the api package's handlers update. Served at GET /metrics
// via promhttp -- see docs/design.md's Phase 3 roadmap entry.
type Metrics struct {
	Registry *prometheus.Registry

	CertificatesIssuedTotal  *prometheus.CounterVec
	CertificatesRevokedTotal prometheus.Counter
	OCSPRequestsTotal        *prometheus.CounterVec
	OCSPRequestDuration      prometheus.Histogram
	TSARequestsTotal         *prometheus.CounterVec
	TSARequestDuration       prometheus.Histogram
	StoreUp                  prometheus.Gauge
}

// NewMetrics builds a Metrics with a fresh registry -- one per process.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		Registry: reg,
		CertificatesIssuedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trustmate_certificates_issued_total",
			Help: "Total number of leaf certificates issued, by profile.",
		}, []string{"profile"}),
		CertificatesRevokedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "trustmate_certificates_revoked_total",
			Help: "Total number of certificates revoked.",
		}),
		OCSPRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trustmate_ocsp_requests_total",
			Help: "Total number of OCSP requests handled, by response status.",
		}, []string{"status"}),
		OCSPRequestDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "trustmate_ocsp_request_duration_seconds",
			Help: "OCSP request handling latency.",
		}),
		TSARequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trustmate_tsa_requests_total",
			Help: "Total number of RFC 3161 timestamp requests handled, by response status.",
		}, []string{"status"}),
		TSARequestDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "trustmate_tsa_request_duration_seconds",
			Help: "TSA request handling latency.",
		}),
		StoreUp: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "trustmate_store_up",
			Help: "1 if the datastore was reachable on the last readiness check, else 0.",
		}),
	}

	reg.MustRegister(
		m.CertificatesIssuedTotal,
		m.CertificatesRevokedTotal,
		m.OCSPRequestsTotal,
		m.OCSPRequestDuration,
		m.TSARequestsTotal,
		m.TSARequestDuration,
		m.StoreUp,
	)
	return m
}
