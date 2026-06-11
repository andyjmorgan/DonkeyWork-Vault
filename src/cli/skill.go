package main

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// skillMD is the credential-manager agent skill, bundled at build time so any agent that
// finds the binary can bootstrap usage instructions matching this exact CLI surface —
// no network, no pre-installed skill. Canonical source: src/cli/skill/SKILL.md.
//
//go:embed skill/SKILL.md
var skillMD string

// defaultSkillPath is where Claude Code looks for the credential-manager skill on this machine.
func defaultSkillPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".claude", "skills", "credential-manager", "SKILL.md"), nil
}

func cmdSkill() *cobra.Command {
	c := &cobra.Command{
		Use:   "skill",
		Short: "Print the bundled credential-manager agent skill (SKILL.md) to stdout",
		Long: "Print the credential-manager agent skill bundled into this binary. The skill\n" +
			"teaches an agent how to discover and use vault credentials via dwvault.\n\n" +
			"Pipe it where you want it, or use `dwvault skill install` to write it to the\n" +
			"local Claude profile (and keep it in lockstep with this binary):\n\n" +
			"  dwvault skill > ~/.claude/skills/credential-manager/SKILL.md\n" +
			"  dwvault skill install",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			_, err := fmt.Fprint(os.Stdout, skillMD)
			return err
		},
	}
	c.AddCommand(cmdSkillInstall())
	return c
}

func cmdSkillInstall() *cobra.Command {
	var force, diff bool
	c := &cobra.Command{
		Use:   "install [dest]",
		Short: "Install/sync the bundled SKILL.md into a local Claude profile",
		Long: "Write the SKILL.md bundled into this binary to a local Claude skill file, so the\n" +
			"on-disk skill stays in lockstep with the installed CLI instead of drifting to old\n" +
			"command guidance.\n\n" +
			"Defaults to ~/.claude/skills/credential-manager/SKILL.md; pass a path to override.\n" +
			"Refuses to overwrite a file that differs from the bundled copy unless --force is\n" +
			"given; --diff reports whether they match without writing. Output goes to stderr.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			dest := ""
			if len(args) == 1 {
				dest = args[0]
			} else {
				d, err := defaultSkillPath()
				if err != nil {
					return err
				}
				dest = d
			}
			return installSkill(dest, force, diff)
		},
	}
	c.Flags().BoolVar(&force, "force", false, "overwrite local edits to the destination file")
	c.Flags().BoolVar(&diff, "diff", false, "report whether the destination matches the bundled skill, without writing")
	return c
}

// installSkill writes the bundled skillMD to dest. It is a no-op when dest already matches,
// refuses to clobber a differing file unless force is set, and writes atomically (temp file +
// rename) so a crash never leaves a half-written skill. All messages go to stderr.
func installSkill(dest string, force, diff bool) error {
	want := []byte(skillMD)
	existing, err := os.ReadFile(dest)
	switch {
	case err == nil:
		if bytes.Equal(existing, want) {
			fmt.Fprintf(os.Stderr, "skill already up to date: %s\n", dest)
			return nil
		}
		if diff {
			fmt.Fprintf(os.Stderr, "skill differs from the bundled copy: %s (run `dwvault skill install --force` to overwrite)\n", dest)
			return nil
		}
		if !force {
			return fmt.Errorf("%s differs from the bundled skill; pass --force to overwrite (or --diff to inspect)", dest)
		}
	case errors.Is(err, os.ErrNotExist):
		if diff {
			fmt.Fprintf(os.Stderr, "skill not installed: %s\n", dest)
			return nil
		}
	default:
		return fmt.Errorf("read %s: %w", dest, err)
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("create skill directory: %w", err)
	}
	if err := atomicWriteFile(dest, want, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "installed skill → %s\n", dest)
	return nil
}

// atomicWriteFile writes data to a temp file in the destination directory and renames it over
// dest, so a reader never observes a partially written file.
func atomicWriteFile(dest string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(dest), ".skill-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // harmless no-op once the rename below succeeds
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		return fmt.Errorf("install %s: %w", dest, err)
	}
	return nil
}
