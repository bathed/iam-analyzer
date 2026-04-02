package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/yourname/iam-analyzer/internal/analyzer"
	"go.uber.org/zap"
)

type CloudTrailClient struct {
	client *cloudtrail.Client
	logger *zap.Logger
}

func NewCloudTrailClient(cfg aws.Config, logger *zap.Logger) *CloudTrailClient {
	return &CloudTrailClient{client: cloudtrail.NewFromConfig(cfg), logger: logger}
}

func (c *CloudTrailClient) GetEventsForRole(ctx context.Context, roleARN string, days int) ([]analyzer.CloudTrailEvent, error) {
	c.logger.Info("Fetching CloudTrail events", zap.String("role", roleARN), zap.Int("days", days))

	endTime := time.Now()
	startTime := endTime.AddDate(0, 0, -days)

	var events []analyzer.CloudTrailEvent

	input := &cloudtrail.LookupEventsInput{
		StartTime: aws.Time(startTime),
		EndTime:   aws.Time(endTime),
		LookupAttributes: []types.LookupAttribute{
			{
				AttributeKey:   types.LookupAttributeKeyUsername,
				AttributeValue: aws.String(roleARN),
			},
		},
	}

	paginator := cloudtrail.NewLookupEventsPaginator(c.client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to lookup events: %w", err)
		}
		for _, event := range page.Events {
			parsed := analyzer.CloudTrailEvent{UserARN: roleARN}
			if event.EventTime != nil {
				parsed.EventTime = *event.EventTime
			}
			if event.EventName != nil {
				parsed.EventName = *event.EventName
			}
			if event.EventSource != nil {
				parsed.EventSource = *event.EventSource
			}
			events = append(events, parsed)
		}
	}

	c.logger.Info("Fetched events", zap.Int("total", len(events)))
	return events, nil
}