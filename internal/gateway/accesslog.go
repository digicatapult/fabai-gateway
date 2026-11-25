package gateway

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
)

// requestInfo is what the access log records about a request, beyond what
// the request itself carries. Handlers fill it in.
type requestInfo struct {
	model    string
	seal     string
	enclave  string
	upstream *upstream
}

type infoKey struct{}

func infoFrom(ctx context.Context) *requestInfo {
	info, _ := ctx.Value(infoKey{}).(*requestInfo)
	return info
}

// accessLog logs one line per request, with metadata only: never a body, a
// query string, or a header value other than the model and the seal host.
func accessLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		info := &requestInfo{}
		body := &countingReader{ReadCloser: r.Body}
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = body
		}
		rec := &recorder{ResponseWriter: w}
		// Deferred, so a stream the proxy aborts with http.ErrAbortHandler
		// is still logged.
		defer func() { logRequest(log, r, rec, body.n.Load(), info, time.Since(start)) }()
		next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), infoKey{}, info)))
	})
}

func logRequest(log *slog.Logger, r *http.Request, rec *recorder, bytesIn int64, info *requestInfo, elapsed time.Duration) {
	attrs := []slog.Attr{
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.Int("status", rec.status()),
		slog.Int64("bytes_in", bytesIn),
		slog.Int64("bytes_out", rec.n),
		slog.Int64("duration_ms", elapsed.Milliseconds()),
	}
	if info.model != "" {
		attrs = append(attrs, slog.String("model", info.model))
	}
	if info.seal != "" {
		attrs = append(attrs, slog.String("seal", info.seal))
	}
	if info.enclave != "" {
		attrs = append(attrs, slog.String("enclave", info.enclave))
	}
	if info.upstream != nil {
		attrs = append(attrs, slog.String("upstream", info.upstream.addr.String()))
	}
	log.LogAttrs(r.Context(), slog.LevelInfo, "request", attrs...)
}

// countingReader counts the request body's bytes. The proxy's transport may
// still be reading when the handler returns, so the count is atomic.
type countingReader struct {
	io.ReadCloser
	n atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// recorder counts the bytes written and keeps the status. Unwrap lets
// http.ResponseController reach the underlying writer's Flush.
type recorder struct {
	http.ResponseWriter
	code int
	n    int64
}

func (r *recorder) WriteHeader(code int) {
	if r.code == 0 && code >= 200 {
		r.code = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(p []byte) (int, error) {
	if r.code == 0 {
		r.code = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(p)
	r.n += int64(n)
	return n, err
}

func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *recorder) status() int {
	if r.code == 0 {
		return http.StatusOK
	}
	return r.code
}
