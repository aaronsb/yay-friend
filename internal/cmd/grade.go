package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aaronsb/yay-friend/internal/cache"
	"github.com/aaronsb/yay-friend/internal/config"
	"github.com/aaronsb/yay-friend/internal/grade"
	"github.com/aaronsb/yay-friend/internal/types"
	"github.com/aaronsb/yay-friend/internal/ui"
)

// subject is what a grading is about: a package name, the staged tree holding
// the bytes to read, and the commit those bytes are at.
type subject struct {
	pkg    string
	tree   string
	commit string
}

func newGradeCmd() *cobra.Command {
	var flags subject

	cmd := &cobra.Command{
		Use:   "grade",
		Short: "Emit a pacrat-grade/v1 grading of a staged package tree",
		Long: `Grade a staged package tree and write a pacrat-grade/v1 report to stdout.

This is the grader interface of pacrat (https://github.com/aaronsb/pacrat), which
gates AUR updates on a grade from any program that speaks the contract. The
subject arrives in the environment, so registering yay-friend is one line:

    [[graders]]
    name = "yay-friend"
    cmd = "yay-friend grade"
    timeout_s = 600
    scale = { min = 0, max = 4 }

The tree is what gets read — the PKGBUILD pacrat staged, its .install hook and
any file shipped beside it — not a fresh fetch of whatever the AUR is serving
now. The result is filed in yay-friend's own cache under the commit, so a second
ask about the same tree replays instead of calling a model again.

stdout carries the grading and nothing else. Any failure is a nonzero exit with
the reason on stderr and no JSON at all: pacrat reads that as UNGRADED, which
holds, and a half-report is worse than none.

The grade is how alarming the tree is, on 0-4, and only that. PROCEED / WARN /
BLOCK is pacrat's to derive from it with the host's own thresholds.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// stdout is reserved for the grading from here on.
			ui.Out = cmd.ErrOrStderr()

			return withUsage(cmd, func() error {
				return runGrade(cmd.Context(), flags, cmd.OutOrStdout())
			})
		},
	}

	cmd.Flags().StringVar(&flags.pkg, "package", "", "Package name (default $PACRAT_PACKAGE)")
	cmd.Flags().StringVar(&flags.tree, "tree", "", "Directory holding the PKGBUILD to grade (default $PACRAT_TREE)")
	cmd.Flags().StringVar(&flags.commit, "commit", "", "Commit the tree is at, as a hex object id (default $PACRAT_COMMIT)")

	return cmd
}

func runGrade(ctx context.Context, flags subject, out io.Writer) error {
	subj, err := resolveSubject(flags)
	if err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// The cache is keyed by the commit in lowercase, because git and yay-friend
	// both spell object ids that way; an uppercase request would otherwise miss
	// an entry sitting right there and spend a real analysis discovering it. The
	// grading still reports the commit as pacrat spelled it.
	key := strings.ToLower(subj.commit)

	var cacheManager *cache.CacheManager
	if cfg.Cache.Enabled {
		cacheManager, err = cache.NewCacheManager()
		if err != nil {
			ui.Warn("could not initialize cache: %v", err)
			cacheManager = nil
		}
	}

	var analysis *types.SecurityAnalysis
	cached := false
	if cacheManager != nil {
		if hit, cacheErr := cacheManager.GetCachedAnalysis(subj.pkg, key); cacheErr == nil {
			ui.Say("replaying cached analysis for %s@%s", subj.pkg, cache.ShortHash(subj.commit))
			analysis, cached = hit, true
		}
	}

	if analysis == nil {
		pkgInfo, err := readSubjectTree(subj)
		if err != nil {
			return err
		}

		// Only on the miss path: a hit is a file read, and demanding a
		// configured, reachable provider for it would fail a question that was
		// already answered.
		aiProvider, err := resolveProvider(ctx, cfg)
		if err != nil {
			return err
		}
		ui.Say("analyzing %s@%s with %s", subj.pkg, cache.ShortHash(subj.commit), aiProvider.Name())

		analysis, err = analyzeWith(ctx, aiProvider, pkgInfo, true)
		if err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}

		if cacheManager != nil {
			if cacheErr := cacheManager.SaveAnalysis(subj.pkg, key, analysis); cacheErr != nil {
				ui.Warn("could not save analysis to cache: %v", cacheErr)
			}
		}
	}

	report, err := grade.FromAnalysis(grade.Subject{
		Package: subj.pkg,
		Commit:  subj.commit,
		Version: treeVersion(subj.tree),
	}, analysis, cached)
	if err != nil {
		return err
	}

	// Marshalled whole before a byte reaches stdout: an encoder writing
	// straight to the pipe and failing partway would leave half a grading
	// there, and half a grading parses as garbage rather than as the failure it
	// is.
	data, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("failed to marshal grading: %w", err)
	}
	_, err = fmt.Fprintf(out, "%s\n", data)
	return err
}

// resolveSubject takes the subject from the flags, falling back to the
// PACRAT_* environment variables pacrat exports for every grader run. Flags win
// when both are present, so a human can drive the same command by hand.
func resolveSubject(flags subject) (subject, error) {
	subj := subject{
		pkg:    firstNonEmpty(flags.pkg, os.Getenv("PACRAT_PACKAGE")),
		tree:   firstNonEmpty(flags.tree, os.Getenv("PACRAT_TREE")),
		commit: firstNonEmpty(flags.commit, os.Getenv("PACRAT_COMMIT")),
	}

	for _, missing := range []struct{ value, flag, env string }{
		{subj.pkg, "--package", "PACRAT_PACKAGE"},
		{subj.tree, "--tree", "PACRAT_TREE"},
		{subj.commit, "--commit", "PACRAT_COMMIT"},
	} {
		if missing.value == "" {
			return subject{}, usageError{fmt.Errorf("no subject to grade: %s is required, or set %s",
				missing.flag, missing.env)}
		}
	}

	// pacrat validates these too, but a grader that only works when its caller
	// is careful is a grader that breaks the first time it is run by hand. Both
	// become path components in the cache.
	if err := validatePackageName(subj.pkg); err != nil {
		return subject{}, usageError{err}
	}
	if err := validateCommit(subj.commit); err != nil {
		return subject{}, usageError{err}
	}

	return subj, nil
}

func validatePackageName(name string) error {
	if strings.HasPrefix(name, "-") || strings.HasPrefix(name, ".") {
		return fmt.Errorf("%q is not a package name", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '@' || r == '.' || r == '_' || r == '+' || r == '-':
		default:
			return fmt.Errorf("%q is not a package name", name)
		}
	}
	return nil
}

func validateCommit(commit string) error {
	for _, r := range commit {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return fmt.Errorf("%q is not a commit hash", commit)
		}
	}
	// Seven is the shortest prefix git will abbreviate to, and the shortest
	// pacrat compares. Sixty-four admits the SHA-256 object ids git is moving
	// toward. Bounded at all so an impossible commit is refused before the miss
	// path spends a model call discovering that no such tree exists.
	if len(commit) < 7 {
		return fmt.Errorf("commit %q is too short to name a tree", commit)
	}
	if len(commit) > 64 {
		return fmt.Errorf("commit %q is longer than any git object id", commit)
	}
	return nil
}

// readSubjectTree collects the bytes under judgement: the PKGBUILD pacrat
// staged and every companion file it references.
//
// The name and commit come from the subject rather than from the tree. pacrat
// discards a grading whose subject is not the one it asked about, and a
// PKGBUILD is untrusted input — letting it name itself would be letting it pick
// which cache entry the grading lands in.
func readSubjectTree(subj subject) (types.PackageInfo, error) {
	info, err := os.Stat(subj.tree)
	if err != nil {
		return types.PackageInfo{}, fmt.Errorf("cannot read tree %s: %w", subj.tree, err)
	}
	if !info.IsDir() {
		return types.PackageInfo{}, fmt.Errorf("tree %s is not a directory", subj.tree)
	}

	pkgInfo, _, err := collectPackageTree(filepath.Join(subj.tree, "PKGBUILD"))
	if err != nil {
		return types.PackageInfo{}, err
	}

	pkgInfo.Name = subj.pkg
	pkgInfo.CommitHash = subj.commit
	if v := treeVersion(subj.tree); v != "" {
		pkgInfo.Version = v
	}
	return pkgInfo, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
