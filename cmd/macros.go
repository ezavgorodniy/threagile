/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

// fmt.Println(docs.Logo + "\n\n" + docs.VersionText)
// fmt.Println("The following model macros are available (can be extended via custom model macros):")
// fmt.Println()
// /* TODO finish plugin stuff
// fmt.Println("Custom model macros:")
// for id, customModelMacro := range customModelMacros {
// 	fmt.Println(id, "-->", customModelMacro.GetMacroDetails().Title)
// }
// fmt.Println()
// */
// fmt.Println("----------------------")
// fmt.Println("Built-in model macros:")
// fmt.Println("----------------------")
// fmt.Println(addbuildpipeline.GetMacroDetails().ID, "-->", addbuildpipeline.GetMacroDetails().Title)
// fmt.Println(addvault.GetMacroDetails().ID, "-->", addvault.GetMacroDetails().Title)
// fmt.Println(prettyprint.GetMacroDetails().ID, "-->", prettyprint.GetMacroDetails().Title)
// fmt.Println(removeunusedtags.GetMacroDetails().ID, "-->", removeunusedtags.GetMacroDetails().Title)
// fmt.Println(seedrisktracking.GetMacroDetails().ID, "-->", seedrisktracking.GetMacroDetails().Title)
// fmt.Println(seedtags.GetMacroDetails().ID, "-->", seedtags.GetMacroDetails().Title)
// fmt.Println()

import (
	"github.com/spf13/cobra"

	"github.com/threagile/threagile/pkg/docs"
	"github.com/threagile/threagile/pkg/macros"
)

var listMacrosCmd = &cobra.Command{
	Use:   "list-model-macros",
	Short: "Print model macros",
	Long:  "\n" + docs.Logo + "\n\n" + docs.VersionText,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Println(docs.Logo + "\n\n" + docs.VersionText)
		cmd.Println("The following model macros are available (can be extended via custom model macros):")
		cmd.Println()
		/* TODO finish plugin stuff
		cmd.Println("Custom model macros:")
		for id, customModelMacro := range macros.ListCustomMacros() {
			cmd.Println(id, "-->", customModelMacro.GetMacroDetails().Title)
		}
		cmd.Println()
		*/
		cmd.Println("----------------------")
		cmd.Println("Built-in model macros:")
		cmd.Println("----------------------")
		for _, macros := range macros.ListBuiltInMacros() {
			cmd.Println(macros.ID, "-->", macros.Title)
		}
		cmd.Println()
	},
}
