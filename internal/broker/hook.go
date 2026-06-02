package broker

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/mmartinez/postern/internal/config"
)

// Resolver turns a vendor-specific secret reference into the resolved
// credential value. The interface is declared here, in the consumer
// package, so the broker has no compile-time dependency on the credential
// vendor SDK or its wrapper; any implementation that satisfies this
// signature works (production wires in a credstore provider — see
// internal/credstore).
//
// vaultID is reserved for future multi-vault routing and must currently be
// the empty string. Each credstore provider enforces this.
type Resolver interface {
	Resolve(ctx context.Context, vaultID, secretRef string) (string, error)
}

// Hook returns a goproxy PreUpstreamHandler that brokers credentials for
// every outbound request that matches a rule in engine:
//
//  1. Match the request host (with any :port stripped) against the engine.
//     No match defers to onNoMatch: passthrough (or the empty default)
//     returns nil so goproxy forwards the request unmodified, while block
//     returns a synthesized 502 so non-matching egress is denied — the
//     allowlist-only containment an operator opts into with
//     proxy.on_no_match: block.
//  2. Refuse to broker over an insecure transport: a matched request whose
//     scheme is not https (i.e. plain http forwarded through the proxy, not
//     MITM-terminated TLS) fails closed before any resolve, so a credential
//     is never injected onto a cleartext hop.
//  3. Resolve the matched rule's secret reference. The vaultID is always
//     empty today; future multi-vault routing will populate it.
//  4. Inject the resolved credential per the rule's InjectSpec.
//
// On any resolve or inject error the hook returns a synthesized 502 — fail
// closed: the proxy must never let an unauthenticated request out to the
// upstream once it has matched a rule. The underlying error message is
// logged via logger but never surfaced to the client.
func Hook(engine *Engine, resolver Resolver, onNoMatch config.OnNoMatch, logger *slog.Logger) func(*http.Request) *http.Response {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return func(req *http.Request) *http.Response {
		host := stripPort(req.URL.Host)
		rule, ok := engine.Match(host)
		if !ok {
			if onNoMatch == config.OnNoMatchBlock {
				logger.Info("broker blocked unmatched request",
					slog.String("host", host),
				)
				return failClosed(req)
			}
			return nil
		}

		// Transport-confidentiality guard. A matched rule means we are about
		// to inject a real credential. goproxy rewrites the request scheme to
		// https only after it has terminated the client's TLS during MITM; a
		// plain-http request forwarded through the proxy keeps scheme "http".
		// Injecting onto that cleartext hop would hand the secret to anyone on
		// the wire, so fail closed before resolving — the resolver is never
		// called and no header is set.
		if req.URL.Scheme != "https" {
			logger.Warn("broker refused injection over insecure transport",
				slog.String("host", host),
				slog.String("rule", rule.Host),
				slog.String("scheme", req.URL.Scheme),
			)
			return failClosed(req)
		}

		cred, err := resolver.Resolve(req.Context(), "", rule.SecretRef)
		if err != nil {
			logger.Warn("broker resolve failed",
				slog.String("host", host),
				slog.String("rule", rule.Host),
				slog.Any("err", err),
			)
			return failClosed(req)
		}

		// An empty resolved value is never a usable credential: injecting it
		// would forward a credential-less request (e.g. "Bearer "). Fail closed
		// rather than trust a resolver that returned ("", nil).
		if cred == "" {
			logger.Warn("broker resolved empty credential",
				slog.String("host", host),
				slog.String("rule", rule.Host),
			)
			return failClosed(req)
		}

		if err := rule.Inject(req, cred); err != nil {
			logger.Warn("broker inject failed",
				slog.String("host", host),
				slog.String("rule", rule.Host),
				slog.Any("err", err),
			)
			return failClosed(req)
		}

		logger.Info("broker injected",
			slog.String("host", host),
			slog.String("rule", rule.Host),
		)
		return nil
	}
}

// failClosedBody is the single, stage-independent body every fail-closed 502
// carries. It is deliberately uniform: the client must not be able to tell a
// no-match from an insecure-transport refusal from a resolve failure from an
// inject failure — that differential is an information oracle for a hostile
// agent (e.g. "injection failed" would reveal the credential resolved fine).
// The specific stage is recorded in the proxy's logs for the operator instead.
const failClosedBody = "postern: bad gateway\n"

// failClosed builds the 502 the proxy returns when the broker cannot or must
// not let the request reach the upstream. The body is generic (see
// failClosedBody); the caller logs the specific reason.
//
// This is intentionally identical to proxy.bad502 — the broker must not
// import the proxy package, so the fail-closed response shape is duplicated.
// If you change that shape, change both.
func failClosed(req *http.Request) *http.Response {
	return &http.Response{
		Status:        http.StatusText(http.StatusBadGateway),
		StatusCode:    http.StatusBadGateway,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
		Body:          io.NopCloser(strings.NewReader(failClosedBody)),
		ContentLength: int64(len(failClosedBody)),
	}
}

// stripPort drops the optional :port suffix from an HTTP request URL host.
// MITM'd HTTPS requests usually arrive as "api.example.com:443"; the broker
// matches against bare hostnames.
func stripPort(hostport string) string {
	if hostport == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}
