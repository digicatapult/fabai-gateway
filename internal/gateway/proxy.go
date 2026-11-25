package gateway

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
)

// newProxy returns the reverse proxy to the replica chosen for each request.
// It flushes every write, as SSE needs, and never follows a redirect: the
// upstream transports don't, and a 3xx is passed to the client as it is.
func newProxy(log *slog.Logger) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			u := infoFrom(pr.In.Context()).upstream
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = u.host
			pr.Out.Host = u.host
			pr.Out.Header.Del("Origin")
		},
		Transport:     upstreamTransport{},
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			stripCORS(resp.Header)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			u := infoFrom(r.Context()).upstream
			log.Warn("upstream request failed", "host", u.host, "upstream", u.addr.String(), "error", err.Error())
			http.Error(w, upstreamErrorMessage, http.StatusBadGateway)
		},
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// upstreamTransport sends each request through its replica host's pool.
type upstreamTransport struct{}

func (upstreamTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return infoFrom(r.Context()).upstream.transport.RoundTrip(r)
}
