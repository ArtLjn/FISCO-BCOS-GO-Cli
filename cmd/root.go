/*
@Time : 2024/6/12 下午7:19
@Author : ljn
@File : root
@Software: GoLand
*/

package cmd

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
	Use:   "fisco-golang-cli",
	Short: "quickly deploy golang web applications",
	Long:  `quickly deploy golang web applications`,
}

func init() {
	rootCmd.AddCommand(apiTemplateCmd)
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}
