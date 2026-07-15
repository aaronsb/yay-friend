// Package scanner provides a deterministic, injection-proof pre-scan of a
// PKGBUILD before the AI analysis. It surfaces facts an AI cannot be talked out
// of: high-entropy strings that are not accounted for as checksums or PGP keys,
// and checksum-shaped strings whose entropy does not match what their position
// claims (a genuine digest is near-maximal entropy).
//
// The scanner renders no verdict — it hands the agent ground truth to assess.
package scanner

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// Heuristic thresholds. Deliberately conservative and named so they are easy to
// tune. Entropy is Shannon entropy in bits per character.
const (
	// minTokenLen ignores short strings — real payloads/digests are long.
	minTokenLen = 16
	// encodedEntropy: a base64/encoded blob exceeds hex's 4.0 bits/char ceiling.
	encodedEntropy = 4.1
	// lowChecksumEntropy: a genuine digest is near-maximal (~3.9-4.0 for hex);
	// a checksum-shaped token below this is not actually random.
	lowChecksumEntropy = 3.3
)

// checksumHexLen maps a hex length to the digest that produces it.
var checksumHexLen = map[int]string{
	32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512",
}

// Kind classifies why a token was surfaced.
type Kind string

const (
	// KindUnexplainedEntropy: a high-entropy string not in a checksum/key
	// position — a possible encoded payload.
	KindUnexplainedEntropy Kind = "unexplained_entropy"
	// KindLowEntropyChecksum: a checksum-shaped string that is not random
	// enough to be a genuine digest — a value crafted to look like a checksum.
	KindLowEntropyChecksum Kind = "low_entropy_checksum"
	// KindExcessEntropyCount: more high-entropy blobs than there are sources to
	// justify them — a possible decryptor+payload pair hiding among checksums.
	KindExcessEntropyCount Kind = "excess_entropy_count"
)

// Finding is one surfaced observation. It carries no severity verdict.
type Finding struct {
	Kind    Kind
	Line    int
	Token   string  // may be truncated for display
	Entropy float64 // bits per character
	Length  int
	Note    string
}

// Report is the full deterministic pre-scan result.
type Report struct {
	Findings         []Finding
	Sources          int // non-SKIP source() entries
	Checksums        int // values seen in *sums=() arrays
	PGPKeys          int // validpgpkeys=() entries
	HighEntropyBlobs int // high-entropy tokens outside checksum/key positions
}

var (
	sumsArrayRe = regexp.MustCompile(`(?s)\b(?:ck|md5|sha1|sha224|sha256|sha384|sha512|b2)sums=\(([^)]*)\)`)
	pgpKeysRe   = regexp.MustCompile(`(?s)validpgpkeys=\(([^)]*)\)`)
	sourceRe    = regexp.MustCompile(`(?s)\bsource=\(([^)]*)\)`)
	// A run of base64/hex-ish characters — the shape an encoded blob or digest takes.
	blobRe = regexp.MustCompile(`[A-Za-z0-9+/=_-]{` + fmt.Sprint(minTokenLen) + `,}`)
	hexRe  = regexp.MustCompile(`^[0-9a-fA-F]+$`)
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

// arrayValues pulls the quoted/bare tokens from a bash array body.
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

// lineOf returns the 1-based line number where substr first appears in text.
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

// Scan runs the deterministic entropy pre-scan over a PKGBUILD.
func Scan(pkgbuild string) *Report {
	r := &Report{}

	// Positions that are EXPECTED to hold high-entropy strings.
	allow := map[string]bool{}

	for _, m := range sumsArrayRe.FindAllStringSubmatch(pkgbuild, -1) {
		for _, v := range arrayValues(m[1]) {
			if strings.EqualFold(v, "SKIP") {
				continue
			}
			r.Checksums++
			allow[v] = true

			// A checksum-shaped token whose entropy is too low to be a genuine
			// digest is suspicious — it may be a crafted/encoded value.
			if _, isKnownLen := checksumHexLen[len(v)]; isKnownLen && hexRe.MatchString(v) {
				if e := shannon(v); e < lowChecksumEntropy {
					r.Findings = append(r.Findings, Finding{
						Kind:    KindLowEntropyChecksum,
						Line:    lineOf(pkgbuild, v),
						Token:   truncate(v, 48),
						Entropy: e,
						Length:  len(v),
						Note:    "checksum-shaped but not random enough to be a genuine digest",
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

	// Surface high-entropy blobs that are NOT in an allowlisted position.
	seen := map[string]bool{}
	for _, tok := range blobRe.FindAllString(pkgbuild, -1) {
		if allow[tok] || seen[tok] {
			continue
		}
		// A bare hex run of exactly a checksum length is almost certainly a
		// digest the author placed outside a *sums array (or in a comment);
		// leave those to the AI rather than crying wolf.
		e := shannon(tok)
		isHex := hexRe.MatchString(tok)
		if isHex {
			// Pure hex tops out at 4.0 bits/char, so it never trips the
			// encodedEntropy gate; only flag non-hex (base64-charset) blobs,
			// which cannot be plain digests.
			continue
		}
		if e >= encodedEntropy {
			seen[tok] = true
			r.HighEntropyBlobs++
			r.Findings = append(r.Findings, Finding{
				Kind:    KindUnexplainedEntropy,
				Line:    lineOf(pkgbuild, tok),
				Token:   truncate(tok, 48),
				Entropy: e,
				Length:  len(tok),
				Note:    "high-entropy string, not a checksum or PGP key",
			})
		}
	}

	// Count anomaly: more unexplained high-entropy blobs than sources to justify
	// them suggests a hidden pair (e.g. decryptor + payload).
	if r.HighEntropyBlobs > 0 && r.HighEntropyBlobs > r.Sources {
		r.Findings = append(r.Findings, Finding{
			Kind: KindExcessEntropyCount,
			Note: fmt.Sprintf("%d unexplained high-entropy strings for %d source(s)", r.HighEntropyBlobs, r.Sources),
		})
	}

	return r
}

// Clean reports whether the scan surfaced nothing worth the agent's attention.
func (r *Report) Clean() bool { return len(r.Findings) == 0 }

// AgentBlock renders the pre-scan as a block to inject into the AI prompt. It
// states facts only; the AI decides what they mean.
func (r *Report) AgentBlock() string {
	var b strings.Builder
	b.WriteString("<static_prescan>\n")
	b.WriteString("Deterministic entropy pre-scan (cannot be influenced by the PKGBUILD's contents).\n")
	if r.Clean() {
		fmt.Fprintf(&b, "No anomalies. Excluded as expected-random: %d checksum value(s), %d PGP key(s).\n", r.Checksums, r.PGPKeys)
		b.WriteString("</static_prescan>")
		return b.String()
	}
	fmt.Fprintf(&b, "Excluded as expected-random: %d checksum value(s), %d PGP key(s). Flagged:\n", r.Checksums, r.PGPKeys)
	for _, f := range r.Findings {
		if f.Kind == KindExcessEntropyCount {
			fmt.Fprintf(&b, "  • [count] %s\n", f.Note)
			continue
		}
		fmt.Fprintf(&b, "  • line %d [%s] %q (entropy %.2f/char, len %d) — %s\n",
			f.Line, f.Kind, f.Token, f.Entropy, f.Length, f.Note)
	}
	b.WriteString("Assess whether any flagged string is an encoded payload or a value masquerading as a checksum.\n")
	b.WriteString("</static_prescan>")
	return b.String()
}
