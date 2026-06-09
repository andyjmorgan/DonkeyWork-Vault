package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"donkeywork.dev/vault-cli/internal/selfupdate"
)

// checkInterval is how long a passive update check stays fresh before the next refresh.
const checkInterval = 24 * time.Hour

// runUpdate performs the in-place upgrade: resolve the latest release, and unless it's
// already current (or force is set), download+verify it and replace this binary. checkOnly
// reports availability without installing. All output goes to STDERR.
func runUpdate(force, checkOnly bool) error {
	if version == "dev" && !force {
		fmt.Fprintln(os.Stderr, "dwvault: built from source (version \"dev\"); nothing to update — use --force to install the latest release anyway")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rel, err := selfupdate.Latest(ctx)
	if err != nil {
		return fmt.Errorf("check for updates: %w", err)
	}

	// Refresh the passive-notice cache while we have a fresh answer.
	_ = selfupdate.SaveState(selfupdate.State{CheckedAt: time.Now(), LatestVersion: rel.TagName})

	newer := selfupdate.Compare(rel.TagName, version) > 0
	if checkOnly {
		if newer {
			fmt.Fprintf(os.Stderr, "dwvault %s is available (you have %s) — run `dwvault update` to upgrade\n", rel.TagName, version)
		} else {
			fmt.Fprintf(os.Stderr, "dwvault %s is the latest release (you have %s)\n", rel.TagName, version)
		}
		return nil
	}
	if !newer && !force {
		fmt.Fprintf(os.Stderr, "dwvault %s is up to date\n", version)
		return nil
	}

	fmt.Fprintf(os.Stderr, "downloading dwvault %s (%s)…\n", rel.TagName, selfupdate.AssetName())
	bin, err := selfupdate.Download(ctx, rel)
	if err != nil {
		return fmt.Errorf("download update: %w", err)
	}
	path, err := selfupdate.Apply(bin)
	if err != nil {
		return fmt.Errorf("install update: %w", err)
	}
	fmt.Fprintf(os.Stderr, "updated dwvault %s → %s (%s)\n", version, rel.TagName, path)
	warnIfNotOnPath(path)
	return nil
}

// warnIfNotOnPath advises the user when the (in-place) binary lives in a directory that
// isn't on $PATH — the one case the in-place update can't fix on its own. Mirrors the PATH
// hint install.sh prints. Advisory only: it never edits PATH or any shell profile.
func warnIfNotOnPath(path string) {
	dir := filepath.Dir(path)
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		if p == dir {
			return
		}
	}
	fmt.Fprintf(os.Stderr,
		"\nnote: %s is not on your PATH. Add it, e.g.:\n  echo 'export PATH=\"%s:$PATH\"' >> ~/.profile && . ~/.profile\n",
		dir, dir)
}

func cmdUpdate() *cobra.Command {
	var check, force bool
	c := &cobra.Command{
		Use:   "update",
		Short: "Upgrade dwvault to the latest release (in place)",
		Long: "Download the latest dwvault release for this platform, verify its checksum, and\n" +
			"replace the running binary in place. PATH is not modified — the binary is updated\n" +
			"wherever it already lives.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runUpdate(force, check)
		},
	}
	c.Flags().BoolVar(&check, "check", false, "report whether an update is available, without installing")
	c.Flags().BoolVar(&force, "force", false, "reinstall the latest release even if already current")
	return c
}

// cmdUpdateCheckHidden is the detached worker spawned by the passive check: it fetches the
// latest version and refreshes the cache, then exits 0. It is silent and never user-facing.
func cmdUpdateCheckHidden() *cobra.Command {
	return &cobra.Command{
		Use:    "__update-check",
		Hidden: true,
		Args:   cobra.NoArgs,
		// Bypass the passive hook on the parent (it's already skipped for this name, but be
		// explicit) and never error out — this is best-effort background work.
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			rel, err := selfupdate.Latest(ctx)
			if err != nil {
				return nil // swallow: a failed background check just leaves the cache stale
			}
			_ = selfupdate.SaveState(selfupdate.State{CheckedAt: time.Now(), LatestVersion: rel.TagName})
			return nil
		},
	}
}

// maybeNotifyUpdate is the passive, best-effort update notice run before every command. It
// adds no network latency to the real command: it only reads a cached version file (printing
// a one-line STDERR notice when a newer release is known) and, if the cache is stale, spawns
// a detached child to refresh it for next time. It is a no-op for dev builds, when opted out,
// for the update commands themselves, and when STDERR is not a terminal (keeps scripts and
// agents — whose STDOUT carries secrets — free of noise).
func maybeNotifyUpdate(cmd *cobra.Command) {
	if version == "dev" || doUpdate || os.Getenv("VAULT_NO_UPDATE_CHECK") != "" {
		return
	}
	switch cmd.Name() {
	case "update", "__update-check", "help", "completion", "version":
		return
	}
	if cmd.Parent() != nil && cmd.Parent().Name() == "completion" {
		return
	}
	if !term.IsTerminal(int(os.Stderr.Fd())) {
		return
	}

	state, err := selfupdate.LoadState()
	if err != nil {
		return // cache dir unreadable — stay silent rather than spawn a child every run
	}
	if state.LatestVersion != "" && selfupdate.Compare(state.LatestVersion, version) > 0 {
		fmt.Fprintf(os.Stderr, "dwvault: a newer version is available: %s (you have %s) — run `dwvault update`\n",
			state.LatestVersion, version)
	}
	if time.Since(state.CheckedAt) > checkInterval {
		spawnBackgroundCheck()
	}
}

// spawnBackgroundCheck launches `dwvault __update-check` fully detached (own session, all
// std streams to /dev/null) and returns immediately without waiting. Any failure to launch
// is ignored — the notice simply lags by one invocation.
func spawnBackgroundCheck() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return
	}
	defer devnull.Close()
	c := exec.Command(exe, "__update-check")
	c.Stdin, c.Stdout, c.Stderr = devnull, devnull, devnull
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // outlive the parent process
	if err := c.Start(); err == nil {
		_ = c.Process.Release()
	}
}
