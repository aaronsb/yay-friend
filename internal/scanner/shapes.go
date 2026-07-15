package scanner

import (
	"regexp"
	"strings"
)

// dangerShapes recognize the SILHOUETTE of decode/download-then-execute
// constructs. We match the shape only — we never run, decode, or interpret what
// flows through them. Recognition and avoidance, not forensics.
var dangerShapes = []struct {
	re   *regexp.Regexp
	note string
}{
	{regexp.MustCompile(`(?i)base64\s+(?:-d|--decode)\b[^\n|]*\|\s*(?:sh|bash|zsh|dash)\b`),
		"base64-decoded output piped straight to a shell"},
	{regexp.MustCompile(`(?i)(?:xxd\s+-r|openssl\s+enc[^\n|]*-d|gunzip|zcat|gzip\s+-d|xz\s+-d|base32\s+-d)\b[^\n|]*\|\s*(?:sh|bash|zsh|dash)\b`),
		"decoded/decompressed output piped straight to a shell"},
	{regexp.MustCompile(`(?i)\beval\s+["']?\$`),
		"eval of a variable's contents"},
	{regexp.MustCompile(`(?i)(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash|zsh|dash)\b`),
		"download piped straight to a shell"},
	{regexp.MustCompile(`(?i)(?:sh|bash)\s+-c\s+["']?\$\(\s*(?:curl|wget)`),
		"shell -c executing the output of a download"},
	{regexp.MustCompile(`/dev/tcp/`),
		"raw /dev/tcp socket (possible reverse shell)"},
	{regexp.MustCompile(`(?i)\bnc\b[^\n]*\s-[a-z]*e[a-z]*\b`),
		"netcat with command execution (-e)"},
}

// scanShapes appends decode/exec silhouette findings. It ignores whole-line
// comments so a documented example doesn't trip it.
func (r *Report) scanShapes(pkgbuild string) {
	for i, line := range strings.Split(pkgbuild, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, s := range dangerShapes {
			if s.re.MatchString(line) {
				r.DecodeExec++
				r.Findings = append(r.Findings, Finding{
					Kind: KindDecodeExecShape,
					Line: i + 1,
					Zone: "code",
					Note: s.note,
				})
			}
		}
	}
}
