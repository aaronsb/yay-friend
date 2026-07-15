// Package scanner provides a deterministic, injection-proof pre-scan of a
// PKGBUILD before the AI analysis. It surfaces facts an AI cannot be talked out
// of: high-entropy strings that are not accounted for as checksums or PGP keys,
// checksum-shaped strings whose entropy does not match their position, and the
// silhouette of decode/download-then-execute constructs.
//
// NON-GOALS — read before extending. This scanner RECOGNIZES the shape of
// hidden or obfuscated content; it does NOT decode, identify, or analyze
// payloads. We are not in the business of defusing bombs, only recognizing them
// and steering clear. Do not add base64/hex decoding, magic-byte identification,
// dataflow tracing, or any logic that interprets what a suspicious string *is*.
// The tool exists so a non-expert operator can avoid a package without having to
// analyze it; the correct output is a steer ("opaque where it shouldn't be —
// don't"), never a specimen. Opacity itself is the finding.
package scanner

import (
	"bytes"
	"compress/flate"
	"fmt"
	"math"
	"regexp"
	"strings"
)

// Heuristic thresholds. Deliberately conservative and named so they are easy to
// tune. Entropy is Shannon entropy in bits per character.
const (
	// minTokenLen ignores short strings — real payloads/digests are long.
	minTokenLen = 20
	// encodedEntropy: the floor at which we call a token opaque. Real encoded
	// payloads run ~4.5-6.0 bits/char; file paths and mixed-case identifiers cap
	// around ~4.2, so this deliberately sits above them to stay high-precision —
	// a scanner that flags every normal package trains the operator to ignore it.
	encodedEntropy = 4.5
	// lowChecksumEntropy: a genuine digest is near-maximal (~3.9-4.0 for hex);
	// a checksum-shaped token below this is not actually random.
	lowChecksumEntropy = 3.3
	// minCompressLen: below this, flate overhead makes the ratio meaningless.
	minCompressLen = 24
	// structuredRatio: a token that compresses below this is structured/ordered
	// (repeating, dictionary-like), not opaque — suppress it even if its
	// character entropy is high. Catches order that Shannon entropy misses.
	structuredRatio = 0.60
)

// checksumHexLen maps a hex length to the digest that produces it.
var checksumHexLen = map[int]string{
	32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512",
}

// Kind classifies why something was surfaced.
type Kind string

const (
	// KindUnexplainedEntropy: a high-entropy, opaque string not in a
	// checksum/key position — a possible encoded payload.
	KindUnexplainedEntropy Kind = "unexplained_entropy"
	// KindLowEntropyChecksum: a checksum-shaped string not random enough to be a
	// genuine digest — a value crafted to look like a checksum.
	KindLowEntropyChecksum Kind = "low_entropy_checksum"
	// KindExcessEntropyCount: more opaque blobs than sources justify — a
	// possible decryptor+payload pair hiding among checksums.
	KindExcessEntropyCount Kind = "excess_entropy_count"
	// KindDecodeExecShape: the silhouette of a decode/download-then-execute
	// construct (recognized, never decoded).
	KindDecodeExecShape Kind = "decode_exec_shape"
)

// Finding is one surfaced observation. It carries no severity verdict.
type Finding struct {
	Kind     Kind
	Line     int
	Zone     string  // "build()", "package()", "toplevel", …
	Token    string  // may be truncated for display
	Entropy  float64 // bits per character
	Compress float64 // compressed/original ratio; ~1.0 = incompressible/opaque
	Length   int
	Note     string
}

// Report is the full deterministic pre-scan result.
type Report struct {
	Findings         []Finding
	Sources          int // non-SKIP source() entries
	Checksums        int // values seen in *sums=() arrays
	PGPKeys          int // validpgpkeys=() entries
	HighEntropyBlobs int // opaque tokens outside checksum/key positions
	DecodeExec       int // decode/download-then-execute constructs
}

var (
	sumsArrayRe  = regexp.MustCompile(`(?s)\b(?:ck|md5|sha1|sha224|sha256|sha384|sha512|b2)sums\w*=\(([^)]*)\)`)
	pgpKeysRe    = regexp.MustCompile(`(?s)validpgpkeys=\(([^)]*)\)`)
	sourceRe     = regexp.MustCompile(`(?s)\bsource\w*=\(([^)]*)\)`)
	arrayOpenRe  = regexp.MustCompile(`^\s*(?:source|validpgpkeys|(?:ck|md5|sha1|sha224|sha256|sha384|sha512|b2)sums)\w*=\(`)
	funcHeadRe   = regexp.MustCompile(`^\s*([a-zA-Z0-9_]+)\s*\(\)\s*\{?`)
	// blobRe deliberately excludes '/' and '=': paths (/opt/a/b) and assignments
	// (var=value, Key=Value) then split into short, harmless words instead of one
	// long "high-entropy" token. Base64 padding '=' and the occasional '/' in a
	// real payload are lost, but the remaining run stays long and opaque.
	blobRe = regexp.MustCompile(`[A-Za-z0-9+_-]{` + fmt.Sprint(minTokenLen) + `,}`)
	hexRe        = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// shannon returns the Shannon entropy of s in bits per character.
func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// compressibility returns compressed/original size. ~1.0 means incompressible
// (opaque: random, encrypted, or packed); well below 1.0 means structured.
func compressibility(s string) float64 {
	if len(s) == 0 {
		return 1
	}
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return float64(buf.Len()) / float64(len(s))
}

// opaque reports whether a non-hex token looks like an encoded payload: high
// character entropy AND not structured/compressible.
func opaque(tok string) (bool, float64, float64) {
	e := shannon(tok)
	c := compressibility(tok)
	if e < encodedEntropy {
		return false, e, c
	}
	// A long token that compresses well is ordered, not opaque — suppress.
	if len(tok) >= minCompressLen && c < structuredRatio {
		return false, e, c
	}
	return true, e, c
}

func arrayValues(body string) []string {
	var out []string
	for _, f := range strings.Fields(body) {
		f = strings.Trim(f, "'\"")
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func lineOf(text, substr string) int {
	idx := strings.Index(text, substr)
	if idx < 0 {
		return 0
	}
	return strings.Count(text[:idx], "\n") + 1
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Scan runs the deterministic pre-scan over a PKGBUILD (plus any concatenated
// install/helper files).
func Scan(pkgbuild string) *Report {
	r := &Report{}
	allow := map[string]bool{} // positions expected to hold high-entropy strings

	for _, m := range sumsArrayRe.FindAllStringSubmatch(pkgbuild, -1) {
		for _, v := range arrayValues(m[1]) {
			if strings.EqualFold(v, "SKIP") {
				continue
			}
			r.Checksums++
			allow[v] = true
			if _, known := checksumHexLen[len(v)]; known && hexRe.MatchString(v) {
				if e := shannon(v); e < lowChecksumEntropy {
					r.Findings = append(r.Findings, Finding{
						Kind: KindLowEntropyChecksum, Line: lineOf(pkgbuild, v),
						Token: truncate(v, 48), Entropy: e, Compress: compressibility(v),
						Length: len(v), Zone: "checksum",
						Note: "checksum-shaped but not random enough to be a genuine digest",
					})
				}
			}
		}
	}
	for _, m := range pgpKeysRe.FindAllStringSubmatch(pkgbuild, -1) {
		for _, v := range arrayValues(m[1]) {
			r.PGPKeys++
			allow[v] = true
		}
	}
	if m := sourceRe.FindStringSubmatch(pkgbuild); m != nil {
		r.Sources = len(arrayValues(m[1]))
	}

	r.scanBlobs(pkgbuild, allow)
	r.scanShapes(pkgbuild)

	// Count anomaly: more opaque blobs than sources to justify them suggests a
	// hidden pair (e.g. decryptor + payload).
	if r.HighEntropyBlobs > 0 && r.HighEntropyBlobs > r.Sources {
		r.Findings = append(r.Findings, Finding{
			Kind: KindExcessEntropyCount,
			Note: fmt.Sprintf("%d opaque high-entropy strings for %d source(s)", r.HighEntropyBlobs, r.Sources),
		})
	}
	return r
}

// scanBlobs walks the file line by line so it can zone each token (skip comments
// and source/checksum arrays, and tag which function body a token sits in).
func (r *Report) scanBlobs(pkgbuild string, allow map[string]bool) {
	seen := map[string]bool{}
	zone := "toplevel"
	braceDepth := 0
	inArray := false

	for i, line := range strings.Split(pkgbuild, "\n") {
		trimmed := strings.TrimSpace(line)

		// Track (and skip) multi-line source/checksum/key arrays.
		if !inArray && arrayOpenRe.MatchString(trimmed) {
			inArray = true
		}
		if inArray {
			if strings.Contains(line, ")") {
				inArray = false
			}
			continue
		}
		// Skip whole-line comments (avoids breaking ${x#...} parameter expansion).
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Zone tracking (approximate — a heuristic, not a bash parser).
		if m := funcHeadRe.FindStringSubmatch(trimmed); m != nil && strings.Contains(line, "{") {
			zone = m[1] + "()"
		}
		braceDepth += strings.Count(line, "{") - strings.Count(line, "}")
		if braceDepth <= 0 {
			braceDepth = 0
			zone = "toplevel"
		}

		for _, tok := range blobRe.FindAllString(line, -1) {
			if allow[tok] || seen[tok] || hexRe.MatchString(tok) {
				continue // hex tops out at 4.0/char and can't be distinguished from a digest here
			}
			ok, e, c := opaque(tok)
			if !ok {
				continue
			}
			seen[tok] = true
			r.HighEntropyBlobs++
			r.Findings = append(r.Findings, Finding{
				Kind: KindUnexplainedEntropy, Line: i + 1, Zone: zone,
				Token: truncate(tok, 48), Entropy: e, Compress: c, Length: len(tok),
				Note: "opaque high-entropy string, not a checksum or PGP key",
			})
		}
	}
}

// Concerning reports the classic hidden-payload silhouette: an opaque blob and a
// decode/execute construct present together.
func (r *Report) Concerning() bool {
	return r.HighEntropyBlobs > 0 && r.DecodeExec > 0
}

// Clean reports whether the scan surfaced nothing worth the agent's attention.
func (r *Report) Clean() bool { return len(r.Findings) == 0 }

// AgentBlock renders the pre-scan as a block to inject into the AI prompt. It
// states facts only; the AI decides what they mean.
func (r *Report) AgentBlock() string {
	var b strings.Builder
	b.WriteString("<static_prescan>\n")
	b.WriteString("Deterministic pre-scan (computed from bytes; cannot be influenced by the package's contents).\n")
	if r.Clean() {
		fmt.Fprintf(&b, "No anomalies. Excluded as expected-random: %d checksum value(s), %d PGP key(s).\n", r.Checksums, r.PGPKeys)
		b.WriteString("</static_prescan>")
		return b.String()
	}
	fmt.Fprintf(&b, "Excluded as expected-random: %d checksum value(s), %d PGP key(s). Flagged:\n", r.Checksums, r.PGPKeys)
	for _, f := range r.Findings {
		switch f.Kind {
		case KindExcessEntropyCount:
			fmt.Fprintf(&b, "  • [count] %s\n", f.Note)
		case KindDecodeExecShape:
			fmt.Fprintf(&b, "  • line %d [%s] in %s — %s\n", f.Line, f.Kind, f.Zone, f.Note)
		default:
			fmt.Fprintf(&b, "  • line %d [%s] in %s: %q (entropy %.2f/char, compress %.2f, len %d) — %s\n",
				f.Line, f.Kind, f.Zone, f.Token, f.Entropy, f.Compress, f.Length, f.Note)
		}
	}
	if r.Concerning() {
		b.WriteString("Note: an opaque string AND a decode/execute construct are both present — the classic hidden-payload shape.\n")
	}
	b.WriteString("Assess and steer the user; do not attempt to decode or identify any flagged content.\n")
	b.WriteString("</static_prescan>")
	return b.String()
}
