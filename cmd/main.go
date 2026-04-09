package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/yourname/iam-analyzer/internal/analyzer"
	awsclient "github.com/yourname/iam-analyzer/internal/aws"
	"github.com/yourname/iam-analyzer/internal/report"
)

var (
	flagRole   string
	flagDays   int
	flagOutput string
	flagRegion string
	flagHTML   string
)

func main() {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	rootCmd := &cobra.Command{
		Use:   "iam-analyzer",
		Short: "IAM permissions analyzer — finds unused permissions in AWS",
	}

	analyzeCmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze a specific IAM role",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAnalyze(logger)
		},
	}

	listCmd := &cobra.Command{
		Use:   "list-roles",
		Short: "List all IAM roles in the account",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runListRoles(logger)
		},
	}

	analyzeCmd.Flags().StringVar(&flagRole, "role", "", "IAM role name to analyze")
	analyzeCmd.Flags().IntVar(&flagDays, "days", 30, "Number of days to analyze CloudTrail logs")
	analyzeCmd.Flags().StringVar(&flagOutput, "output", "", "Path to save JSON report")
	analyzeCmd.Flags().StringVar(&flagRegion, "region", "us-east-1", "AWS region")
	analyzeCmd.Flags().StringVar(&flagHTML, "html", "", "Path to save HTML report")
	analyzeCmd.MarkFlagRequired("role")

	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(listCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runAnalyze(logger *zap.Logger) error {
	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(flagRegion),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to AWS: %w", err)
	}

	iamClient := awsclient.NewIAMClient(cfg, logger)
	cloudTrailClient := awsclient.NewCloudTrailClient(cfg, logger)
	analyzerEngine := analyzer.New()
	printer := report.New()

	fmt.Printf("Fetching role '%s'...\n", flagRole)
	role, err := iamClient.GetRole(ctx, flagRole)
	if err != nil {
		return fmt.Errorf("failed to get role: %w", err)
	}

	fmt.Printf("Reading CloudTrail logs for the last %d days...\n", flagDays)
	events, err := cloudTrailClient.GetEventsForRole(ctx, role.ARN, flagDays)
	if err != nil {
		return fmt.Errorf("failed to get events: %w", err)
	}

	fmt.Println("Analyzing...")
	result := analyzerEngine.Analyze(*role, events)

	printer.PrintToTerminal(result)

	if flagOutput != "" {
		if err := printer.SaveToJSON(result, flagOutput); err != nil {
			return err
		}
	}

	if flagHTML != "" {
		return printer.SaveToHTML(result, flagHTML)
	}

	return nil
}

func runListRoles(logger *zap.Logger) error {
	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(flagRegion),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to AWS: %w", err)
	}

	iamClient := awsclient.NewIAMClient(cfg, logger)

	roles, err := iamClient.ListRoles(ctx)
	if err != nil {
		return err
	}

	fmt.Println("All IAM roles in the account:")
	for i, role := range roles {
		fmt.Printf("  %d. %s\n", i+1, role)
	}
	fmt.Printf("\nTotal: %d roles\n", len(roles))

	return nil
}