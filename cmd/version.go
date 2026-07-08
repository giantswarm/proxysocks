package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/giantswarm/proxysocks/pkg/project"
)

// versionCmd prints the build version information.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("version: %s\n", project.Version())
		fmt.Printf("git sha: %s\n", project.GitSHA())
		fmt.Printf("build timestamp: %s\n", project.BuildTimestamp())
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
