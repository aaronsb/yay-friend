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
		Short: "Grade a staged package tree as structured output",
		Long: `Grade a staged package tree and write a structured output report to stdout.

This is yay-friend's machine-readable interface: JSON for another program to
read, rather than the rendered report a person reads. Any tool that manages
packages can call it for a second opinion without yay-friend knowing what the
tool intends to do with the answer.

The subject can arrive as flags or in the environment, so wiring yay-friend into
a host is usually one line of that host's config. With pacrat
(https://github.com/aaronsb/pacrat), the reference consumer:

    [[graders]]
    name = "yay-friend"
    cmd = "yay-friend grade"
    timeout_s = 600
    scale = { min = 0, max = 4 }

The tree is what gets read — the PKGBUILD the caller staged, its .install hook
and any file shipped beside it — not a fresh fetch of whatever the AUR is
serving now. The result is filed in yay-friend's own cache under the commit, so
a second ask about the same tree replays instead of calling a model again.

stdout carries the grading and nothing else. Any failure is a nonzero exit with
the reason on stderr and no JSON at all, which a caller should read as "no
grading" — a half-report is worse than none.

The grade is how alarming the tree is, on 0-4, and only that. What to do about
that number is the caller's decision, made with its own thresholds.

The report declares its contract as pacrat-grade/v1. That is the wire format's
name, kept as-is so existing readers keep working; it does not limit who may
call this.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// stdout is reserved for the grading from here on. Warnings move
			// with it, so everything yay-friend narrates leaves by one door.
			ui.Out = cmd.ErrOrStderr()
			ui.Err = cmd.ErrOrStderr()

			return withUsage(cmd, func() error {
				return runGrade(cmd.Context(), flags, cmd.OutOrStdout())
			})
		},
	}

	cmd.Flags().StringVar(&flags.pkg, "package", "", "Package name (default $YAY_FRIEND_PACKAGE, or $PACRAT_PACKAGE)")
	cmd.Flags().StringVar(&flags.tree, "tree", "", "Directory holding the PKGBUILD to grade (default $YAY_FRIEND_TREE, or $PACRAT_TREE)")
	cmd.Flags().StringVar(&flags.commit, "commit", "", "Commit the tree is at, as a hex object id (default $YAY_FRIEND_COMMIT, or $PACRAT_COMMIT)")

	return cmd
}

func runGrade(ctx context.Context, flags subject, out io.Writer) error {
	subj, err := resolveSubject(flags)
	if err != nil {
		return err
	}

	// Checked before the cache is consulted, so both paths agree on what a
	// gradeable subject is. Skipping it on a hit meant an unreadable --tree
	// still produced a grading, just one with subject.version quietly missing:
	// the tree is where that field comes from, and nothing else noticed it had
	// not been read.
	if err := validateTree(subj.tree); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// The cache is keyed by the commit in lowercase, because git and yay-friend
	// both spell object ids that way; an uppercase request would otherwise miss
	// an entry sitting right there and spend a real analysis discovering it. The
	// grading still reports the commit as the caller spelled it.
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
	producedBy := ""
	if cacheManager != nil {
		if entry, cacheErr := cacheManager.GetCachedEntry(subj.pkg, key); cacheErr == nil {
			ui.Say("replaying cached analysis for %s@%s", subj.pkg, cache.ShortHash(subj.commit))
			analysis, cached = entry.Analysis, true
			// The version that produced the analysis, not the one replaying
			// it — the adapter reported the same thing under the same key.
			producedBy = entry.CacheMetadata.YayFriendVersion
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

	// The tree is readable by now, so an empty version means it declares none --
	// no .SRCINFO and a PKGBUILD with no pkgver, or one that will not parse.
	// The field is optional in the contract and a grading is still worth
	// emitting without it, but silently dropping the one piece of the subject
	// that says *which* version was graded is how it went missing before.
	subjectVersion := treeVersion(subj.tree)
	if subjectVersion == "" {
		ui.Warn("no version declared in %s (.SRCINFO absent or unparseable, PKGBUILD has no pkgver); omitting subject.version", subj.tree)
	}

	report, err := grade.FromAnalysis(grade.Subject{
		Package: subj.pkg,
		Commit:  subj.commit,
		Version: subjectVersion,
	}, analysis, cached, producedBy)
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
// environment. Flags win, so a human can drive the same command by hand.
//
// Two spellings are read for each value. YAY_FRIEND_* is the name a host should
// set: this is yay-friend's own interface, and nothing about it is specific to
// one caller. PACRAT_* is still honored because pacrat shipped against it and
// exports it for every grader run -- dropping it would break working installs to
// rename a variable, which is not a trade worth making. The canonical name wins
// if a host sets both.
func resolveSubject(flags subject) (subject, error) {
	subj := subject{
		pkg:    firstNonEmpty(flags.pkg, os.Getenv("YAY_FRIEND_PACKAGE"), os.Getenv("PACRAT_PACKAGE")),
		tree:   firstNonEmpty(flags.tree, os.Getenv("YAY_FRIEND_TREE"), os.Getenv("PACRAT_TREE")),
		commit: firstNonEmpty(flags.commit, os.Getenv("YAY_FRIEND_COMMIT"), os.Getenv("PACRAT_COMMIT")),
	}

	for _, missing := range []struct{ value, flag, env string }{
		{subj.pkg, "--package", "YAY_FRIEND_PACKAGE"},
		{subj.tree, "--tree", "YAY_FRIEND_TREE"},
		{subj.commit, "--commit", "YAY_FRIEND_COMMIT"},
	} {
		if missing.value == "" {
			return subject{}, usageError{fmt.Errorf("no subject to grade: %s is required, or set %s",
				missing.flag, missing.env)}
		}
	}

	// A caller may validate these too, but a grader that only works when its
	// caller is careful is a grader that breaks the first time it is run by
	// hand. Both become path components in the cache.
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

// validateTree checks that the staged tree is there to be read. It is a
// precondition of grading at all, not of analyzing: the version reported in the
// subject is read from this directory on every run, cache hit included.
func validateTree(tree string) error {
	info, err := os.Stat(tree)
	if err != nil {
		return fmt.Errorf("cannot read tree %s: %w", tree, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("tree %s is not a directory", tree)
	}
	return nil
}

func validateCommit(commit string) error {
	for _, r := range commit {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return fmt.Errorf("%q is not a commit hash", commit)
		}
	}
	// Seven is the shortest prefix git will abbreviate to. Sixty-four admits the
	// SHA-256 object ids git is moving toward. Bounded at all so an impossible
	// commit is refused before the miss path spends a model call discovering
	// that no such tree exists.
	if len(commit) < 7 {
		return fmt.Errorf("commit %q is too short to name a tree", commit)
	}
	if len(commit) > 64 {
		return fmt.Errorf("commit %q is longer than any git object id", commit)
	}
	return nil
}

// readSubjectTree collects the bytes under judgement: the PKGBUILD the caller
// staged and every companion file it references.
//
// The name and commit come from the subject rather than from the tree. The
// caller checks a grading is about the subject it asked about, and a PKGBUILD is
// untrusted input — letting it name itself would be letting it pick which cache
// entry the grading lands in.
func readSubjectTree(subj subject) (types.PackageInfo, error) {
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
