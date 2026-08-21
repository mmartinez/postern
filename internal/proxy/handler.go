package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"

	"github.com/mmartinez/postern/internal/logging"
)

// badGatewayBody is the stage-independent body returned to the client. It is
// kept identical to broker.failClosedBody so a hostile agent cannot tell a
// panic from a resolve/inject failure; the specific cause is logged instead.
const badGatewayBody = "postern: bad gateway\n"

// bad502 builds an http.Response that goproxy returns to the client without
// dialling upstream. The body is generic (see badGatewayBody); the caller logs
// the specific cause.
//
// This is intentionally identical to broker.failClosed — the broker owns the
// same fail-closed shape but must not import this package. If you change that
// shape, change both.
func bad502(req *http.Request) *http.Response {
	return &http.Response{
		Status:        http.StatusText(http.StatusBadGateway),
		StatusCode:    http.StatusBadGateway,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
		Body:          io.NopCloser(strings.NewReader(badGatewayBody)),
		ContentLength: int64(len(badGatewayBody)),
	}
}

// installInnerGuard binds every inner MITM request to the CONNECT authority
// stashed by the CONNECT handler in ctx.UserData (goproxy copies that slot
// onto each inner request's fresh ProxyCtx). goproxy rebuilds only
// relative-form inner URLs against the tunnel host; an absolute-form inner
// request keeps its own URL host, and a cross-scheme one makes goproxy's
// unchecked re-parse fail, leaving req.URL nil. Without this guard the first
// case would be forwarded under passthrough policy and the second would
// panic the logging handler, so both fail closed with the generic 502.
func installInnerGuard(gp *goproxy.ProxyHttpServer, logger *slog.Logger) {
	gp.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		authority, ok := ctx.UserData.(string)
		if !ok || authority == "" {
			// Not an intercepted tunnel (plain HTTP proxying leaves UserData
			// unset); nothing to bind.
			return req, nil
		}
		if req.URL == nil {
			logger.Info("rejecting malformed inner request",
				slog.Int64("session", ctx.Session),
				slog.String("method", req.Method),
				slog.String("authority", authority),
			)
			return req, bad502(req) //nolint:bodyclose // goproxy owns the synthetic body
		}
		if host := strings.ToLower(stripPort(req.URL.Host)); host != authority {
			logger.Info("rejecting non-brokered inner host",
				slog.Int64("session", ctx.Session),
				slog.String("method", req.Method),
				slog.String("host", host),
				slog.String("authority", authority),
			)
			return req, bad502(req) //nolint:bodyclose // goproxy owns the synthetic body
		}
		return req, nil
	})
}

// installPreUpstream wires the user-supplied PreUpstreamHandler into the
// goproxy request chain. A nil hook installs nothing (passthrough). A
// non-nil hook runs under a recover() so a bug or attacker-induced panic
// surfaces as 502 with no upstream contact — fail closed.
func installPreUpstream(gp *goproxy.ProxyHttpServer, logger *slog.Logger, hook func(*http.Request) *http.Response) {
	if hook == nil {
		return
	}
	gp.OnRequest().DoFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (r *http.Request, resp *http.Response) {
		r = req
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("proxy hook panic",
					slog.String("host", req.URL.Host),
					slog.String("path", req.URL.Path),
					slog.Any("recover", rec),
				)
				r = nil
				// goproxy closes the response body after writing it
				// to the client, so bodyclose's complaint here would
				// double-close. Annotate inline.
				resp = bad502(req) //nolint:bodyclose // goproxy owns the synthetic body
			}
		}()
		if out := hook(req); out != nil {
			r = nil
			resp = out
		}
		return r, resp
	})
}

// sensitiveHeaders is the canonical set of header names whose values must
// never appear in audit output: Authorization, Cookie,
// Set-Cookie, and any token-bearing vendor header (x-api-key, x-amz-security-
// token, etc); we keep this list short and rely on prefix matching for the
// vendor family rather than enumerate every product header.
var sensitiveHeaders = map[string]struct{}{
	"Authorization":       {},
	"Proxy-Authorization": {},
	"Cookie":              {},
	"Set-Cookie":          {},
}

// redactionValue is what postern substitutes for a sensitive header value
// in slog output. It's a constant string so log scrapers can pattern-match.
const redactionValue = "<redacted>"

// installHandlers wires request and response logging handlers onto gp. The
// handlers emit a single slog line per request with the destination host,
// method, and path; sensitive headers are flattened to a redacted summary.
// The body is never read or logged.
func installHandlers(gp *goproxy.ProxyHttpServer, logger *slog.Logger) {
	gp.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		logger.Info("proxy request",
			slog.Int64("session", ctx.Session),
			slog.String("method", req.Method),
			slog.String("host", req.URL.Host),
			slog.String("path", req.URL.Path),
			slog.Any("headers", redactHeaders(req.Header)),
		)
		return req, nil
	})

	gp.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil {
			return nil
		}
		// One log call per response. In info/debug this is the
		// per-stage "proxy response" record operators expect; in quiet
		// mode it is the single per-request lifecycle line the summary
		// wrapper lets through despite the Warn-level inner filter.
		// resp.Request.Context() is the request-scoped ctx so any future
		// trace/correlation handler can read it.
		logging.Summary(resp.Request.Context(), logger, "proxy response",
			slog.Int64("session", ctx.Session),
			slog.String("method", resp.Request.Method),
			slog.String("host", resp.Request.URL.Host),
			slog.Int("status", resp.StatusCode),
		)
		return resp
	})
}

// redactHeaders returns a header map suitable for logging: sensitive entries
// are replaced with redactionValue and a list of non-sensitive headers is
// preserved verbatim. The original headers are never mutated.
func redactHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		if isSensitive(k) {
			out[k] = redactionValue
			continue
		}
		out[k] = strings.Join(vs, ",")
	}
	return out
}

// isSensitive returns true when name should be redacted. Matching is
// case-insensitive and prefix-based for the "x-*-key" / "x-*-token" /
// "x-*-secret" vendor families so future SDKs we haven't named explicitly
// still get redacted by default.
func isSensitive(name string) bool {
	canon := http.CanonicalHeaderKey(name)
	if _, ok := sensitiveHeaders[canon]; ok {
		return true
	}
	lower := strings.ToLower(canon)
	switch {
	case strings.HasPrefix(lower, "x-api-"):
		return true
	case strings.HasPrefix(lower, "x-auth-"):
		return true
	case strings.HasSuffix(lower, "-key"):
		return true
	case strings.HasSuffix(lower, "-token"):
		return true
	case strings.HasSuffix(lower, "-secret"):
		return true
	}
	return false
}
