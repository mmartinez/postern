package broker

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // OAuth 1.0a (RFC 5849) mandates HMAC-SHA1; not a security choice
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	oauth1SignatureMethod = "HMAC-SHA1"
	oauth1Version         = "1.0"
)

// oauth1Creds carries the four OAuth 1.0a secrets used to sign a request: the
// application's consumer key/secret and the user's token/token secret.
type oauth1Creds struct {
	consumerKey    string
	consumerSecret string
	token          string
	tokenSecret    string
}

// oauth1AuthHeader builds the "Authorization: OAuth ..." header value for the
// request described by method, u, and body, signed with HMAC-SHA1 per RFC 5849.
//
// body holds application/x-www-form-urlencoded parameters (nil for any other
// content type); RFC 5849 §3.4.1.3.1 folds only form bodies into the signature,
// so a JSON or multipart body contributes nothing here. nonce and timestamp are
// parameters so tests can pin deterministic values; production passes a random
// nonce and the current Unix time.
func oauth1AuthHeader(method string, u *url.URL, body url.Values, c oauth1Creds, nonce string, timestamp int64) string {
	oauth := map[string]string{
		"oauth_consumer_key":     c.consumerKey,
		"oauth_nonce":            nonce,
		"oauth_signature_method": oauth1SignatureMethod,
		"oauth_timestamp":        strconv.FormatInt(timestamp, 10),
		"oauth_token":            c.token,
		"oauth_version":          oauth1Version,
	}
	oauth["oauth_signature"] = oauth1Signature(method, u, body, oauth, c)

	keys := make([]string, 0, len(oauth))
	for k := range oauth {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("OAuth ")
	for i, k := range keys {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(pctEncodeOAuth1(k))
		b.WriteString(`="`)
		b.WriteString(pctEncodeOAuth1(oauth[k]))
		b.WriteByte('"')
	}
	return b.String()
}

// oauth1Signature computes the base64 HMAC-SHA1 signature over the RFC 5849
// signature base string. The oauth map must exclude oauth_signature. Query
// params come from u, form params from body, protocol params from oauth; all
// three are percent-encoded, sorted, and joined per §3.4.1.3.2.
func oauth1Signature(method string, u *url.URL, body url.Values, oauth map[string]string, c oauth1Creds) string {
	type pair struct{ k, v string }
	var pairs []pair
	add := func(k, v string) { pairs = append(pairs, pair{pctEncodeOAuth1(k), pctEncodeOAuth1(v)}) }

	for k, vs := range u.Query() {
		for _, v := range vs {
			add(k, v)
		}
	}
	for k, vs := range body {
		for _, v := range vs {
			add(k, v)
		}
	}
	for k, v := range oauth {
		add(k, v)
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})

	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	paramString := strings.Join(parts, "&")

	base := strings.ToUpper(method) + "&" + pctEncodeOAuth1(oauth1BaseURL(u)) + "&" + pctEncodeOAuth1(paramString)
	key := pctEncodeOAuth1(c.consumerSecret) + "&" + pctEncodeOAuth1(c.tokenSecret)

	mac := hmac.New(sha1.New, []byte(key)) //nolint:gosec // OAuth 1.0a (RFC 5849) mandates HMAC-SHA1
	mac.Write([]byte(base))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// oauth1BaseURL normalizes u for the signature base string per RFC 5849
// §3.4.1.2: lowercase scheme and host, the default port removed, the path kept,
// and the query and fragment excluded.
func oauth1BaseURL(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	switch {
	case scheme == "https" && strings.HasSuffix(host, ":443"):
		host = strings.TrimSuffix(host, ":443")
	case scheme == "http" && strings.HasSuffix(host, ":80"):
		host = strings.TrimSuffix(host, ":80")
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path
}

// resolveOAuth1Creds resolves the four OAuth 1.0a secret references through
// resolver. It fails closed if any resolve errors or returns an empty value, so
// a partial credential never produces a malformed (and useless) signature.
func resolveOAuth1Creds(ctx context.Context, resolver Resolver, refs OAuth1Refs) (oauth1Creds, error) {
	consumerKey, err := resolver.Resolve(ctx, "", refs.ConsumerKeyRef)
	if err != nil {
		return oauth1Creds{}, fmt.Errorf("resolve consumer key: %w", err)
	}
	consumerSecret, err := resolver.Resolve(ctx, "", refs.ConsumerSecretRef)
	if err != nil {
		return oauth1Creds{}, fmt.Errorf("resolve consumer secret: %w", err)
	}
	token, err := resolver.Resolve(ctx, "", refs.TokenRef)
	if err != nil {
		return oauth1Creds{}, fmt.Errorf("resolve token: %w", err)
	}
	tokenSecret, err := resolver.Resolve(ctx, "", refs.TokenSecretRef)
	if err != nil {
		return oauth1Creds{}, fmt.Errorf("resolve token secret: %w", err)
	}
	if consumerKey == "" || consumerSecret == "" || token == "" || tokenSecret == "" {
		return oauth1Creds{}, errors.New("oauth1: a resolved credential is empty")
	}
	return oauth1Creds{
		consumerKey:    consumerKey,
		consumerSecret: consumerSecret,
		token:          token,
		tokenSecret:    tokenSecret,
	}, nil
}

// injectOAuth1 signs req with OAuth 1.0a and sets the Authorization header. A
// form-urlencoded body contributes its parameters to the signature (RFC 5849
// §3.4.1.3.1) and is buffered and restored so the upstream still receives it;
// any other body is signed without its content. The nonce is random and the
// timestamp is the current Unix time.
func (r Rule) injectOAuth1(req *http.Request, c oauth1Creds, globalCap int) error {
	body, err := oauth1FormBody(req, effectiveBodyCap(globalCap, r.Injection.MaxBodyBytes))
	if err != nil {
		return err
	}
	nonce, err := randomOAuth1Nonce()
	if err != nil {
		return err
	}
	header := oauth1AuthHeader(req.Method, req.URL, body, c, nonce, time.Now().Unix())
	req.Header.Set("Authorization", header)
	return nil
}

// oauth1FormBody returns the request's form parameters when the body is
// application/x-www-form-urlencoded, buffering the body (capped) and restoring
// it so the upstream is unaffected. Any other content type returns nil: RFC 5849
// folds only form bodies into the signature.
func oauth1FormBody(req *http.Request, maxBytes int) (url.Values, error) {
	if req.Body == nil {
		return nil, nil
	}
	// A malformed or absent Content-Type yields an empty media type, which is
	// (correctly) not a form body — the parse error is not actionable here.
	mediaType, _, _ := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if mediaType != "application/x-www-form-urlencoded" {
		return nil, nil
	}

	// An oversized form body surfaces here as a read error and the caller fails
	// closed with 502 — deliberately, not the 413 the placeholder body path
	// returns: a signable body is small, and threading a 413 sentinel up to the
	// hook is not worth it. Either way the upstream is never contacted.
	buf, err := io.ReadAll(http.MaxBytesReader(nil, req.Body, int64(maxBytes)))
	if err != nil {
		return nil, fmt.Errorf("oauth1: read form body: %w", err)
	}
	// goproxy closes the original body; replace it with the buffered copy rather
	// than closing it here (a double close).
	req.Body = io.NopCloser(bytes.NewReader(buf))
	req.ContentLength = int64(len(buf))

	vals, err := url.ParseQuery(string(buf))
	if err != nil {
		return nil, fmt.Errorf("oauth1: parse form body: %w", err)
	}
	return vals, nil
}

// randomOAuth1Nonce returns a URL-safe random nonce for the oauth_nonce
// parameter (RFC 5849 §3.3 requires only uniqueness per timestamp).
func randomOAuth1Nonce() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth1: nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pctEncodeOAuth1 percent-encodes s per RFC 3986/5849 §3.6: every byte except
// the unreserved set A-Z a-z 0-9 - . _ ~ is encoded as %XX (uppercase hex). This
// differs from url.QueryEscape, which encodes a space as "+" and leaves some
// reserved characters unescaped.
func pctEncodeOAuth1(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'A' && ch <= 'Z', ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9',
			ch == '-', ch == '.', ch == '_', ch == '~':
			b.WriteByte(ch)
		default:
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}
