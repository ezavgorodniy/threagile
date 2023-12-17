package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/threagile/threagile/pkg/docs"
	"github.com/threagile/threagile/pkg/security/types"
)

var listTypesCmd = &cobra.Command{
	Use:   "list-types",
	Short: "Print type information (enum values to be used in models)",
	Long:  "\n" + docs.Logo + "\n\n" + docs.VersionText,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Println(docs.Logo + "\n\n" + docs.VersionText)
		cmd.Println()
		cmd.Println()
		cmd.Println("The following types are available (can be extended for custom rules):")
		cmd.Println()
		for name, values := range types.GetBuiltinTypeValues() {
			cmd.Println(fmt.Sprintf("  %v: %v", name, values))
		}

		types.TechnicalAssetTechnologyValues()
	},
}
