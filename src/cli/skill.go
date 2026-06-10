package main

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// skillMD is the credential-manager agent skill, bundled at build time so any agent that
// finds the binary can bootstrap usage instructions matching this exact CLI surface —
// no network, no pre-installed skill. Canonical source: src/cli/skill/SKILL.md.
//
//go:embed skill/SKILL.md
var skillMD string

func cmdSkill() *cobra.Command {
	return &cobra.Command{
		Use:   "skill",
		Short: "Print the bundled credential-manager agent skill (SKILL.md) to stdout",
		Long: "Print the credential-manager agent skill bundled into this binary. The skill\n" +
			"teaches an agent how to discover and use vault credentials via dwvault. Install\n" +
			"it for Claude Code with:\n\n" +
			"  mkdir -p ~/.claude/skills/credential-manager\n" +
			"  dwvault skill > ~/.claude/skills/credential-manager/SKILL.md",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			_, err := fmt.Fprint(os.Stdout, skillMD)
			return err
		},
	}
}
