package observability

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics is the process-wide Prometheus registry and the counters/
// histograms the api package's handlers update. Served at GET /metrics
// via promhttp -- see docs/design.md's Phase 3 roadmap entry.
type Metrics struct {
	Registry *prometheus.Registry

	// InstanceInfo is always 1, labeled with the configured instance
	// name -- the standard Prometheus "info metric" pattern (cf.
	// *_build_info) for surfacing a label on a target with no natural
	// numeric value of its own.
	InstanceInfo             prometheus.Gauge
	CertificatesIssuedTotal  *prometheus.CounterVec
	CertificatesRevokedTotal prometheus.Counter
	OCSPRequestsTotal        *prometheus.CounterVec
	OCSPRequestDuration      prometheus.Histogram
	TSARequestsTotal         *prometheus.CounterVec
	TSARequestDuration       prometheus.Histogram
	StoreUp                  prometheus.Gauge
	ACMEAccountsTotal        prometheus.Counter
	ACMEOrdersTotal          *prometheus.CounterVec
}

// NewMetrics builds a Metrics with a fresh registry -- one per process.
// instanceName labels InstanceInfo (see Config.InstanceName).
func NewMetrics(instanceName string) *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		Registry: reg,
		InstanceInfo: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:        "trustmate_instance_info",
			Help:        "Always 1; labeled with the configured instance name.",
			ConstLabels: prometheus.Labels{"instance": instanceName},
		}),
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
		ACMEAccountsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "trustmate_acme_accounts_total",
			Help: "Total number of ACME accounts created via External Account Binding.",
		}),
		ACMEOrdersTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trustmate_acme_orders_total",
			Help: "Total number of ACME orders, by outcome (created, finalized).",
		}, []string{"outcome"}),
	}

	reg.MustRegister(
		m.InstanceInfo,
		m.CertificatesIssuedTotal,
		m.CertificatesRevokedTotal,
		m.OCSPRequestsTotal,
		m.OCSPRequestDuration,
		m.TSARequestsTotal,
		m.TSARequestDuration,
		m.StoreUp,
		m.ACMEAccountsTotal,
		m.ACMEOrdersTotal,
	)
	m.InstanceInfo.Set(1)
	return m
}
