package cmd

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	"github.com/aaronsb/yay-friend/internal/types"
	"github.com/aaronsb/yay-friend/internal/ui"
	"github.com/aaronsb/yay-friend/internal/version"
)

// Where the PKGBUILD under analysis came from.
const (
	sourceAUR   = "aur"
	sourceLocal = "local"
)

// analysisReport is yay-friend's own machine-readable shape: the whole analysis,
// plus the context it was produced in.
//
// It is deliberately not a grading contract. `yay-friend grade` emits
// pacrat-grade/v1, which is a narrow answer to one question and drops
// everything a host cannot act on; this carries the opposite bias — the
// educational summary, the per-finding suggestions and notes, the
// predictability score, the AUR community numbers — because a caller shaping
// its own pipeline should not have to run the analysis twice to see what the
// analyzer actually said.
//
// The entropy block is redundant with analysis.overall_entropy on purpose. The
// analysis serializes the level as its integer, which is the honest storage
// form and what the cache holds; a consumer writing a one-line jq filter wants
// the name and the bounds without having to know the enum.
type analysisReport struct {
	YayFriendVersion string                  `json:"yay_friend_version"`
	Source           string                  `json:"source"`
	Cached           bool                    `json:"cached"`
	Package          packageContext          `json:"package"`
	Entropy          entropyReport           `json:"entropy"`
	Analysis         *types.SecurityAnalysis `json:"analysis"`
}

type packageContext struct {
	Name         string   `json:"name"`
	Version      string   `json:"version,omitempty"`
	CommitHash   string   `json:"commit_hash,omitempty"`
	Description  string   `json:"description,omitempty"`
	URL          string   `json:"url,omitempty"`
	Maintainer   string   `json:"maintainer,omitempty"`
	AURPageURL   string   `json:"aur_page_url,omitempty"`
	Votes        int      `json:"votes,omitempty"`
	Popularity   float64  `json:"popularity,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
	MakeDepends  []string `json:"make_depends,omitempty"`
	PKGBUILDPath string   `json:"pkgbuild_path,omitempty"`
	// Files names the companion files that were read and sent for analysis —
	// the .install hook and any source= entry shipped beside the PKGBUILD.
	Files []string `json:"files,omitempty"`
}

type entropyReport struct {
	Value int    `json:"value"`
	Name  string `json:"name"`
	Min   int    `json:"min"`
	Max   int    `json:"max"`
}

// present writes the finished analysis in whichever shape was asked for.
func present(out analyzeOutput, source string, pkgInfo *types.PackageInfo, analysis *types.SecurityAnalysis, cached bool) error {
	if !out.asJSON {
		ui.RenderAnalysis(analysis, true)
		return nil
	}

	report := analysisReport{
		YayFriendVersion: version.Version,
		Source:           source,
		Cached:           cached,
		Package: packageContext{
			Name:         pkgInfo.Name,
			Version:      pkgInfo.Version,
			CommitHash:   pkgInfo.CommitHash,
			Description:  pkgInfo.Description,
			URL:          pkgInfo.URL,
			Maintainer:   pkgInfo.Maintainer,
			AURPageURL:   pkgInfo.AURPageURL,
			Votes:        pkgInfo.Votes,
			Popularity:   pkgInfo.Popularity,
			Dependencies: pkgInfo.Dependencies,
			MakeDepends:  pkgInfo.MakeDepends,
			PKGBUILDPath: pkgInfo.PKGBUILDPath,
			Files:        sortedKeys(pkgInfo.AdditionalFiles),
		},
		Entropy: entropyReport{
			Value: int(analysis.OverallEntropy),
			Name:  analysis.OverallEntropy.String(),
			Min:   int(types.EntropyMinimal),
			Max:   int(types.EntropyCritical),
		},
		Analysis: analysis,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal analysis: %w", err)
	}
	_, err = fmt.Fprintf(out.out, "%s\n", data)
	return err
}

// sortedKeys returns a map's keys in a stable order, so two runs over the same
// tree produce byte-identical JSON.
func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(m))
}
