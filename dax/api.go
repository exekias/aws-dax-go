/*
  Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.

  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  A copy of the License is located at

      http://www.apache.org/licenses/LICENSE-2.0

  or in the "license" file accompanying this file. This file is distributed
  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
  express or implied. See the License for the specific language governing
  permissions and limitations under the License.
*/

package dax

import (
	"context"
	"errors"
	"io"

	"github.com/aws/aws-dax-go/dax/internal"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go/middleware"

	"github.com/aws/aws-dax-go/dax/internal/client"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go/aws/request"
	dynamov1 "github.com/aws/aws-sdk-go/service/dynamodb"
)

//func (d *Dax) PutItem(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
//	return d.PutItemWithContext(nil, input)
//}

func (d *Dax) PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	o, cfn, err := d.config.requestOptionsV2(false, ctx, optFns...)
	if err != nil {
		return nil, err
	}
	if cfn != nil {
		defer cfn()
	}

	co := string(params.ConditionalOperator)
	input := &dynamov1.PutItemInput{
		ConditionExpression:         params.ConditionExpression,
		ConditionalOperator:         &co,
		Expected:                    internal.ConvertExpectedAttributeValueV2toV1Map(params.Expected),
		ExpressionAttributeNames:    internal.ConvertToPointerMap(params.ExpressionAttributeNames),
		ExpressionAttributeValues:   internal.ConvertAttributeValueV2toV1Map(params.ExpressionAttributeValues),
		Item:                        internal.ConvertAttributeValueV2toV1Map(params.Item),
		ReturnConsumedCapacity:      (*string)(&params.ReturnConsumedCapacity),
		ReturnItemCollectionMetrics: (*string)(&params.ReturnItemCollectionMetrics),
		ReturnValues:                (*string)(&params.ReturnValues),
		TableName:                   params.TableName,
	}

	output, err := d.client.PutItemWithOptions(input, &dynamov1.PutItemOutput{}, o)

	if err != nil {
		return nil, err
	}

	if output.Attributes == nil && output.ItemCollectionMetrics == nil {
		return nil, err
	}

	out := &dynamodb.PutItemOutput{
		Attributes:            internal.ConvertAttributeValueV1toV2Map(output.Attributes),
		ItemCollectionMetrics: internal.ConvertItemCollectionMetrics(*output.ItemCollectionMetrics),
	}

	if output.ConsumedCapacity != nil {
		out.ConsumedCapacity = internal.ConvertConsumedCapacity(output.ConsumedCapacity)
	}
	return out, nil
}

func (d *Dax) DeleteItem(ctx context.Context, input *dynamodb.DeleteItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	o, cfn, err := d.config.requestOptionsV2(false, ctx, opts...)
	if err != nil {
		return nil, err
	}
	if cfn != nil {
		defer cfn()
	}

	inputV1 := &dynamov1.DeleteItemInput{
		Key:                       internal.ConvertAttributeValueV2toV1Map(input.Key),
		ExpressionAttributeNames:  internal.ConvertToPointerMap(input.ExpressionAttributeNames),
		ExpressionAttributeValues: internal.ConvertAttributeValueV2toV1Map(input.ExpressionAttributeValues),
		TableName:                 input.TableName,
		Expected:                  internal.ConvertExpectedAttributeValueV2toV1Map(input.Expected),
	}
	output, err := d.client.DeleteItemWithOptions(inputV1, &dynamov1.DeleteItemOutput{}, o)

	if err != nil {
		return nil, err
	}

	outputV2 := &dynamodb.DeleteItemOutput{
		Attributes:            internal.ConvertAttributeValueV1toV2Map(output.Attributes),
		ItemCollectionMetrics: internal.ConvertItemCollectionMetrics(*output.ItemCollectionMetrics),
	}

	if output.ConsumedCapacity != nil {
		outputV2.ConsumedCapacity = internal.ConvertConsumedCapacity(output.ConsumedCapacity)
	}
	return outputV2, nil
}

func (d *Dax) UpdateItem(ctx context.Context, input *dynamodb.UpdateItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	o, cfn, err := d.config.requestOptionsV2(false, ctx, opts...)
	if err != nil {
		return nil, err
	}
	if cfn != nil {
		defer cfn()
	}

	inputV1 := &dynamov1.UpdateItemInput{
		Key:                       internal.ConvertAttributeValueV2toV1Map(input.Key),
		ExpressionAttributeNames:  internal.ConvertToPointerMap(input.ExpressionAttributeNames),
		ExpressionAttributeValues: internal.ConvertAttributeValueV2toV1Map(input.ExpressionAttributeValues),
		TableName:                 input.TableName,
		Expected:                  internal.ConvertExpectedAttributeValueV2toV1Map(input.Expected),
	}

	output, err := d.client.UpdateItemWithOptions(inputV1, &dynamov1.UpdateItemOutput{}, o)

	if err != nil {
		return nil, err
	}

	if output.Attributes == nil && output.ItemCollectionMetrics == nil {
		return nil, err
	}

	outputV2 := &dynamodb.UpdateItemOutput{
		Attributes:            internal.ConvertAttributeValueV1toV2Map(output.Attributes),
		ItemCollectionMetrics: internal.ConvertItemCollectionMetrics(*output.ItemCollectionMetrics),
	}

	if output.ConsumedCapacity != nil {
		outputV2.ConsumedCapacity = internal.ConvertConsumedCapacity(output.ConsumedCapacity)
	}
	return outputV2, nil
}

func (d *Dax) GetItem(ctx context.Context, input *dynamodb.GetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	o, cfn, err := d.config.requestOptionsV2(true, ctx, opts...)
	if err != nil {
		return nil, err
	}
	if cfn != nil {
		defer cfn()
	}

	oldInput := &dynamov1.GetItemInput{
		ExpressionAttributeNames: internal.ConvertToPointerMap(input.ExpressionAttributeNames),
		ProjectionExpression:     input.ProjectionExpression,
		TableName:                input.TableName,
		Key:                      internal.ConvertAttributeValueV2toV1Map(input.Key),
	}

	itemOutput, err := d.client.GetItemWithOptions(oldInput, &dynamov1.GetItemOutput{}, o)

	v2Output := &dynamodb.GetItemOutput{
		Item: internal.ConvertAttributeValueV1toV2Map(itemOutput.Item),
	}

	return v2Output, err

}

func (d *Dax) Scan(ctx context.Context, input *dynamodb.ScanInput, opts ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error) {
	o, cfn, err := d.config.requestOptionsV2(true, ctx, opts...)
	if err != nil {
		return nil, err
	}
	if cfn != nil {
		defer cfn()
	}

	limit := int64(*input.Limit)

	scanInputV1 := &dynamov1.ScanInput{
		ExpressionAttributeNames:  internal.ConvertToPointerMap(input.ExpressionAttributeNames),
		ExpressionAttributeValues: internal.ConvertAttributeValueV2toV1Map(input.ExpressionAttributeValues),
		FilterExpression:          input.FilterExpression,
		IndexName:                 input.IndexName,
		TableName:                 input.TableName,
		ProjectionExpression:      input.ProjectionExpression,
		Limit:                     &limit,
	}

	scanOutput, err := d.client.ScanWithOptions(scanInputV1, &dynamov1.ScanOutput{}, o)

	if err != nil {
		return nil, err
	}

	scanOutputV2 := &dynamodb.ScanOutput{
		Items:        internal.ConvertAttributeValueV1toV2MapList(scanOutput.Items),
		Count:        int32(*scanOutput.Count),
		ScannedCount: int32(*scanOutput.ScannedCount),
	}

	return scanOutputV2, err
}

func (d *Dax) Query(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	o, cfn, err := d.config.requestOptionsV2(false, ctx, optFns...)
	if err != nil {
		return nil, err
	}
	if cfn != nil {
		defer cfn()
	}

	co := string(params.ConditionalOperator)
	var limit *int64 = nil
	if params.Limit != nil {
		i := int64(*params.Limit)
		limit = &i
	}
	sel := string(params.Select)
	input := &dynamov1.QueryInput{
		//AttributesToGet:           toGet,
		ConditionalOperator:       &co,
		ConsistentRead:            params.ConsistentRead,
		ExclusiveStartKey:         internal.ConvertAttributeValueV2toV1Map(params.ExclusiveStartKey),
		ExpressionAttributeNames:  internal.ConvertToPointerMap(params.ExpressionAttributeNames),
		ExpressionAttributeValues: internal.ConvertAttributeValueV2toV1Map(params.ExpressionAttributeValues),
		FilterExpression:          params.FilterExpression,
		IndexName:                 params.IndexName,
		KeyConditionExpression:    params.KeyConditionExpression,
		KeyConditions:             internal.ConvertConditionMap(params.KeyConditions),
		Limit:                     limit,
		ProjectionExpression:      params.ProjectionExpression,
		QueryFilter:               internal.ConvertConditionMap(params.QueryFilter),
		ReturnConsumedCapacity:    (*string)(&params.ReturnConsumedCapacity),
		ScanIndexForward:          params.ScanIndexForward,
		Select:                    &sel,
		TableName:                 params.TableName,
	}

	if params.AttributesToGet != nil {
		toGet := make([]*string, 0)

		for _, s := range params.AttributesToGet {
			toGet = append(toGet, &s)
		}

		input.AttributesToGet = toGet
	}

	output, err := d.client.QueryWithOptions(input, &dynamov1.QueryOutput{}, o)

	if err != nil {
		return nil, err
	}

	var count int32
	if output.Count != nil {
		count = int32(*output.Count)
	}
	items := make([]map[string]types.AttributeValue, 0)
	for _, item := range output.Items {
		items = append(items, internal.ConvertAttributeValueV1toV2Map(item))
	}
	sc := int32(*output.ScannedCount)
	out := &dynamodb.QueryOutput{
		Count:        count,
		Items:        items,
		ScannedCount: sc,
		//ResultMetadata:
	}
	if output.ConsumedCapacity != nil {
		out.ConsumedCapacity = internal.ConvertConsumedCapacity(output.ConsumedCapacity)
	}
	if output.LastEvaluatedKey != nil {
		out.LastEvaluatedKey = internal.ConvertAttributeValueV1toV2Map(output.LastEvaluatedKey)
	}

	return out, nil
}

func (d *Dax) BatchWriteItem(ctx context.Context, input *dynamodb.BatchWriteItemInput, opts ...request.Option) (*dynamodb.BatchWriteItemOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) BatchGetItem(ctx context.Context, input *dynamodb.BatchGetItemInput, opts ...request.Option) (*dynamodb.BatchGetItemOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) TransactWriteItems(ctx context.Context, params *dynamodb.TransactWriteItemsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	o, cfn, err := d.config.requestOptionsV2(false, ctx, optFns...)
	if err != nil {
		return nil, err
	}
	if cfn != nil {
		defer cfn()
	}

	var items []*dynamov1.TransactWriteItem
	for _, item := range params.TransactItems {
		out := &dynamov1.TransactWriteItem{}

		if item.ConditionCheck != nil {
			out.ConditionCheck = &dynamov1.ConditionCheck{
				ConditionExpression:                 item.ConditionCheck.ConditionExpression,
				ExpressionAttributeNames:            internal.ConvertToPointerMap(item.ConditionCheck.ExpressionAttributeNames),
				ExpressionAttributeValues:           internal.ConvertAttributeValueV2toV1Map(item.ConditionCheck.ExpressionAttributeValues),
				Key:                                 internal.ConvertAttributeValueV2toV1Map(item.ConditionCheck.Key),
				ReturnValuesOnConditionCheckFailure: (*string)(&item.ConditionCheck.ReturnValuesOnConditionCheckFailure),
				TableName:                           item.ConditionCheck.TableName,
			}
		}

		if item.Delete != nil {
			out.Delete = &dynamov1.Delete{
				ConditionExpression:                 item.Delete.ConditionExpression,
				ExpressionAttributeNames:            internal.ConvertToPointerMap(item.Delete.ExpressionAttributeNames),
				ExpressionAttributeValues:           internal.ConvertAttributeValueV2toV1Map(item.Delete.ExpressionAttributeValues),
				Key:                                 internal.ConvertAttributeValueV2toV1Map(item.Delete.Key),
				ReturnValuesOnConditionCheckFailure: (*string)(&item.Delete.ReturnValuesOnConditionCheckFailure),
				TableName:                           item.Delete.TableName,
			}
		}

		if item.Put != nil {
			out.Put = &dynamov1.Put{
				ConditionExpression:                 item.Put.ConditionExpression,
				ExpressionAttributeNames:            internal.ConvertToPointerMap(item.Put.ExpressionAttributeNames),
				ExpressionAttributeValues:           internal.ConvertAttributeValueV2toV1Map(item.Put.ExpressionAttributeValues),
				Item:                                internal.ConvertAttributeValueV2toV1Map(item.Put.Item),
				ReturnValuesOnConditionCheckFailure: (*string)(&item.Put.ReturnValuesOnConditionCheckFailure),
				TableName:                           item.Put.TableName,
			}
		}

		if item.Update != nil {
			out.Update = &dynamov1.Update{
				ConditionExpression:                 item.Update.ConditionExpression,
				ExpressionAttributeNames:            internal.ConvertToPointerMap(item.Update.ExpressionAttributeNames),
				ExpressionAttributeValues:           internal.ConvertAttributeValueV2toV1Map(item.Update.ExpressionAttributeValues),
				Key:                                 internal.ConvertAttributeValueV2toV1Map(item.Update.Key),
				ReturnValuesOnConditionCheckFailure: (*string)(&item.Update.ReturnValuesOnConditionCheckFailure),
				TableName:                           item.Update.TableName,
				UpdateExpression:                    item.Update.UpdateExpression,
			}
		}

		items = append(items, out)
	}

	input := &dynamov1.TransactWriteItemsInput{
		TransactItems: items,
	}

	output, err := d.client.TransactWriteItemsWithOptions(input, &dynamov1.TransactWriteItemsOutput{}, o)
	if err != nil {
		return nil, err
	}

	out := &dynamodb.TransactWriteItemsOutput{
		ResultMetadata: middleware.Metadata{},
	}

	if len(output.ConsumedCapacity) > 0 {
		consumeCapacity := make([]types.ConsumedCapacity, len(output.ConsumedCapacity))
		for i, cap := range output.ConsumedCapacity {
			consumeCapacity[i] = *internal.ConvertConsumedCapacity(cap)
		}
		out.ConsumedCapacity = consumeCapacity
	}

	if len(output.ItemCollectionMetrics) > 0 {
		itemCollectionMetrics := make(map[string][]types.ItemCollectionMetrics, len(output.ConsumedCapacity))
		for name, items := range output.ItemCollectionMetrics {
			res := []types.ItemCollectionMetrics{}
			for _, item := range items {
				res = append(res, *internal.ConvertItemCollectionMetrics(*item))
			}
			itemCollectionMetrics[name] = res
		}
		out.ItemCollectionMetrics = itemCollectionMetrics
	}

	return out, nil

}

func (d *Dax) TransactGetItems(ctx context.Context, input *dynamodb.TransactGetItemsInput, opts ...request.Option) (*dynamodb.TransactGetItemsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) CreateBackup(*dynamodb.CreateBackupInput) (*dynamodb.CreateBackupOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) CreateBackupWithContext(context.Context, *dynamodb.CreateBackupInput, ...request.Option) (*dynamodb.CreateBackupOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) CreateBackupRequest(*dynamodb.CreateBackupInput) (*request.Request, *dynamodb.CreateBackupOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.CreateBackupOutput{}
}

func (d *Dax) CreateGlobalTable(*dynamodb.CreateGlobalTableInput) (*dynamodb.CreateGlobalTableOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) CreateGlobalTableWithContext(context.Context, *dynamodb.CreateGlobalTableInput, ...request.Option) (*dynamodb.CreateGlobalTableOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) CreateGlobalTableRequest(*dynamodb.CreateGlobalTableInput) (*request.Request, *dynamodb.CreateGlobalTableOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.CreateGlobalTableOutput{}
}

func (d *Dax) CreateTable(*dynamodb.CreateTableInput) (*dynamodb.CreateTableOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) CreateTableWithContext(context.Context, *dynamodb.CreateTableInput, ...request.Option) (*dynamodb.CreateTableOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) CreateTableRequest(*dynamodb.CreateTableInput) (*request.Request, *dynamodb.CreateTableOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.CreateTableOutput{}
}

func (d *Dax) DeleteBackup(*dynamodb.DeleteBackupInput) (*dynamodb.DeleteBackupOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DeleteBackupWithContext(context.Context, *dynamodb.DeleteBackupInput, ...request.Option) (*dynamodb.DeleteBackupOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DeleteBackupRequest(*dynamodb.DeleteBackupInput) (*request.Request, *dynamodb.DeleteBackupOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.DeleteBackupOutput{}
}

func (d *Dax) DeleteTable(*dynamodb.DeleteTableInput) (*dynamodb.DeleteTableOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DeleteTableWithContext(context.Context, *dynamodb.DeleteTableInput, ...request.Option) (*dynamodb.DeleteTableOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DeleteTableRequest(*dynamodb.DeleteTableInput) (*request.Request, *dynamodb.DeleteTableOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.DeleteTableOutput{}
}

func (d *Dax) DescribeBackup(*dynamodb.DescribeBackupInput) (*dynamodb.DescribeBackupOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeBackupWithContext(context.Context, *dynamodb.DescribeBackupInput, ...request.Option) (*dynamodb.DescribeBackupOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeBackupRequest(*dynamodb.DescribeBackupInput) (*request.Request, *dynamodb.DescribeBackupOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.DescribeBackupOutput{}
}

func (d *Dax) DescribeContinuousBackups(*dynamodb.DescribeContinuousBackupsInput) (*dynamodb.DescribeContinuousBackupsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeContinuousBackupsWithContext(context.Context, *dynamodb.DescribeContinuousBackupsInput, ...request.Option) (*dynamodb.DescribeContinuousBackupsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeContinuousBackupsRequest(*dynamodb.DescribeContinuousBackupsInput) (*request.Request, *dynamodb.DescribeContinuousBackupsOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.DescribeContinuousBackupsOutput{}
}

func (d *Dax) DescribeContributorInsights(*dynamodb.DescribeContributorInsightsInput) (*dynamodb.DescribeContributorInsightsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeContributorInsightsWithContext(context.Context, *dynamodb.DescribeContributorInsightsInput, ...request.Option) (*dynamodb.DescribeContributorInsightsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeContributorInsightsRequest(*dynamodb.DescribeContributorInsightsInput) (*request.Request, *dynamodb.DescribeContributorInsightsOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.DescribeContributorInsightsOutput{}
}

func (d *Dax) DescribeEndpoints(*dynamodb.DescribeEndpointsInput) (*dynamodb.DescribeEndpointsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeEndpointsWithContext(context.Context, *dynamodb.DescribeEndpointsInput, ...request.Option) (*dynamodb.DescribeEndpointsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeEndpointsRequest(*dynamodb.DescribeEndpointsInput) (*request.Request, *dynamodb.DescribeEndpointsOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.DescribeEndpointsOutput{}
}

func (d *Dax) DescribeGlobalTable(*dynamodb.DescribeGlobalTableInput) (*dynamodb.DescribeGlobalTableOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeGlobalTableWithContext(context.Context, *dynamodb.DescribeGlobalTableInput, ...request.Option) (*dynamodb.DescribeGlobalTableOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeGlobalTableRequest(*dynamodb.DescribeGlobalTableInput) (*request.Request, *dynamodb.DescribeGlobalTableOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.DescribeGlobalTableOutput{}
}

func (d *Dax) DescribeGlobalTableSettings(*dynamodb.DescribeGlobalTableSettingsInput) (*dynamodb.DescribeGlobalTableSettingsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeGlobalTableSettingsWithContext(context.Context, *dynamodb.DescribeGlobalTableSettingsInput, ...request.Option) (*dynamodb.DescribeGlobalTableSettingsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeGlobalTableSettingsRequest(*dynamodb.DescribeGlobalTableSettingsInput) (*request.Request, *dynamodb.DescribeGlobalTableSettingsOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.DescribeGlobalTableSettingsOutput{}
}

func (d *Dax) DescribeLimits(*dynamodb.DescribeLimitsInput) (*dynamodb.DescribeLimitsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeLimitsWithContext(context.Context, *dynamodb.DescribeLimitsInput, ...request.Option) (*dynamodb.DescribeLimitsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeLimitsRequest(*dynamodb.DescribeLimitsInput) (*request.Request, *dynamodb.DescribeLimitsOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.DescribeLimitsOutput{}
}

func (d *Dax) DescribeTable(*dynamodb.DescribeTableInput) (*dynamodb.DescribeTableOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeTableWithContext(context.Context, *dynamodb.DescribeTableInput, ...request.Option) (*dynamodb.DescribeTableOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeTableRequest(*dynamodb.DescribeTableInput) (*request.Request, *dynamodb.DescribeTableOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.DescribeTableOutput{}
}

func (d *Dax) DescribeTableReplicaAutoScaling(*dynamodb.DescribeTableReplicaAutoScalingInput) (*dynamodb.DescribeTableReplicaAutoScalingOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeTableReplicaAutoScalingWithContext(context.Context, *dynamodb.DescribeTableReplicaAutoScalingInput, ...request.Option) (*dynamodb.DescribeTableReplicaAutoScalingOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeTableReplicaAutoScalingRequest(*dynamodb.DescribeTableReplicaAutoScalingInput) (*request.Request, *dynamodb.DescribeTableReplicaAutoScalingOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.DescribeTableReplicaAutoScalingOutput{}
}

func (d *Dax) DescribeTimeToLive(*dynamodb.DescribeTimeToLiveInput) (*dynamodb.DescribeTimeToLiveOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeTimeToLiveWithContext(context.Context, *dynamodb.DescribeTimeToLiveInput, ...request.Option) (*dynamodb.DescribeTimeToLiveOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeTimeToLiveRequest(*dynamodb.DescribeTimeToLiveInput) (*request.Request, *dynamodb.DescribeTimeToLiveOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.DescribeTimeToLiveOutput{}
}

func (d *Dax) BatchExecuteStatement(*dynamodb.BatchExecuteStatementInput) (*dynamodb.BatchExecuteStatementOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) BatchExecuteStatementRequest(*dynamodb.BatchExecuteStatementInput) (*request.Request, *dynamodb.BatchExecuteStatementOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.BatchExecuteStatementOutput{}
}

func (d *Dax) BatchExecuteStatementWithContext(context.Context, *dynamodb.BatchExecuteStatementInput, ...request.Option) (*dynamodb.BatchExecuteStatementOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeExport(*dynamodb.DescribeExportInput) (*dynamodb.DescribeExportOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeExportWithContext(context.Context, *dynamodb.DescribeExportInput, ...request.Option) (*dynamodb.DescribeExportOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeExportRequest(*dynamodb.DescribeExportInput) (*request.Request, *dynamodb.DescribeExportOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.DescribeExportOutput{}
}

func (d *Dax) DescribeKinesisStreamingDestination(*dynamodb.DescribeKinesisStreamingDestinationInput) (*dynamodb.DescribeKinesisStreamingDestinationOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeKinesisStreamingDestinationWithContext(context.Context, *dynamodb.DescribeKinesisStreamingDestinationInput, ...request.Option) (*dynamodb.DescribeKinesisStreamingDestinationOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DescribeKinesisStreamingDestinationRequest(*dynamodb.DescribeKinesisStreamingDestinationInput) (*request.Request, *dynamodb.DescribeKinesisStreamingDestinationOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.DescribeKinesisStreamingDestinationOutput{}
}

func (d *Dax) DisableKinesisStreamingDestination(*dynamodb.DisableKinesisStreamingDestinationInput) (*dynamodb.DisableKinesisStreamingDestinationOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DisableKinesisStreamingDestinationWithContext(context.Context, *dynamodb.DisableKinesisStreamingDestinationInput, ...request.Option) (*dynamodb.DisableKinesisStreamingDestinationOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) DisableKinesisStreamingDestinationRequest(*dynamodb.DisableKinesisStreamingDestinationInput) (*request.Request, *dynamodb.DisableKinesisStreamingDestinationOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.DisableKinesisStreamingDestinationOutput{}
}

func (d *Dax) EnableKinesisStreamingDestination(*dynamodb.EnableKinesisStreamingDestinationInput) (*dynamodb.EnableKinesisStreamingDestinationOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) EnableKinesisStreamingDestinationWithContext(context.Context, *dynamodb.EnableKinesisStreamingDestinationInput, ...request.Option) (*dynamodb.EnableKinesisStreamingDestinationOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) EnableKinesisStreamingDestinationRequest(*dynamodb.EnableKinesisStreamingDestinationInput) (*request.Request, *dynamodb.EnableKinesisStreamingDestinationOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.EnableKinesisStreamingDestinationOutput{}
}

func (d *Dax) ExecuteStatement(*dynamodb.ExecuteStatementInput) (*dynamodb.ExecuteStatementOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) ExecuteStatementWithContext(context.Context, *dynamodb.ExecuteStatementInput, ...request.Option) (*dynamodb.ExecuteStatementOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) ExecuteStatementRequest(*dynamodb.ExecuteStatementInput) (*request.Request, *dynamodb.ExecuteStatementOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.ExecuteStatementOutput{}
}

func (d *Dax) ExecuteTransaction(*dynamodb.ExecuteTransactionInput) (*dynamodb.ExecuteTransactionOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) ExecuteTransactionWithContext(context.Context, *dynamodb.ExecuteTransactionInput, ...request.Option) (*dynamodb.ExecuteTransactionOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) ExecuteTransactionRequest(*dynamodb.ExecuteTransactionInput) (*request.Request, *dynamodb.ExecuteTransactionOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.ExecuteTransactionOutput{}
}

func (d *Dax) ExportTableToPointInTime(*dynamodb.ExportTableToPointInTimeInput) (*dynamodb.ExportTableToPointInTimeOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) ExportTableToPointInTimeWithContext(context.Context, *dynamodb.ExportTableToPointInTimeInput, ...request.Option) (*dynamodb.ExportTableToPointInTimeOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) ExportTableToPointInTimeRequest(*dynamodb.ExportTableToPointInTimeInput) (*request.Request, *dynamodb.ExportTableToPointInTimeOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.ExportTableToPointInTimeOutput{}
}

func (d *Dax) ListBackups(*dynamodb.ListBackupsInput) (*dynamodb.ListBackupsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) ListBackupsWithContext(context.Context, *dynamodb.ListBackupsInput, ...request.Option) (*dynamodb.ListBackupsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) ListBackupsRequest(*dynamodb.ListBackupsInput) (*request.Request, *dynamodb.ListBackupsOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.ListBackupsOutput{}
}

func (d *Dax) ListContributorInsights(*dynamodb.ListContributorInsightsInput) (*dynamodb.ListContributorInsightsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) ListContributorInsightsWithContext(context.Context, *dynamodb.ListContributorInsightsInput, ...request.Option) (*dynamodb.ListContributorInsightsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) ListContributorInsightsRequest(*dynamodb.ListContributorInsightsInput) (*request.Request, *dynamodb.ListContributorInsightsOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.ListContributorInsightsOutput{}
}

func (d *Dax) ListContributorInsightsPages(*dynamodb.ListContributorInsightsInput, func(*dynamodb.ListContributorInsightsOutput, bool) bool) error {
	return d.unImpl()
}

func (d *Dax) ListContributorInsightsPagesWithContext(context.Context, *dynamodb.ListContributorInsightsInput, func(*dynamodb.ListContributorInsightsOutput, bool) bool, ...request.Option) error {
	return d.unImpl()
}

func (d *Dax) ListExports(*dynamodb.ListExportsInput) (*dynamodb.ListExportsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) ListExportsWithContext(context.Context, *dynamodb.ListExportsInput, ...request.Option) (*dynamodb.ListExportsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) ListExportsRequest(*dynamodb.ListExportsInput) (*request.Request, *dynamodb.ListExportsOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.ListExportsOutput{}
}

func (d *Dax) ListExportsPages(*dynamodb.ListExportsInput, func(*dynamodb.ListExportsOutput, bool) bool) error {
	return d.unImpl()
}

func (d *Dax) ListExportsPagesWithContext(context.Context, *dynamodb.ListExportsInput, func(*dynamodb.ListExportsOutput, bool) bool, ...request.Option) error {
	return d.unImpl()
}

func (d *Dax) ListGlobalTables(*dynamodb.ListGlobalTablesInput) (*dynamodb.ListGlobalTablesOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) ListGlobalTablesWithContext(context.Context, *dynamodb.ListGlobalTablesInput, ...request.Option) (*dynamodb.ListGlobalTablesOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) ListGlobalTablesRequest(*dynamodb.ListGlobalTablesInput) (*request.Request, *dynamodb.ListGlobalTablesOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.ListGlobalTablesOutput{}
}

func (d *Dax) ListTables(*dynamodb.ListTablesInput) (*dynamodb.ListTablesOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) ListTablesWithContext(context.Context, *dynamodb.ListTablesInput, ...request.Option) (*dynamodb.ListTablesOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) ListTablesRequest(*dynamodb.ListTablesInput) (*request.Request, *dynamodb.ListTablesOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.ListTablesOutput{}
}

func (d *Dax) ListTablesPages(*dynamodb.ListTablesInput, func(*dynamodb.ListTablesOutput, bool) bool) error {
	return d.unImpl()
}

func (d *Dax) ListTablesPagesWithContext(context.Context, *dynamodb.ListTablesInput, func(*dynamodb.ListTablesOutput, bool) bool, ...request.Option) error {
	return d.unImpl()
}

func (d *Dax) ListTagsOfResource(*dynamodb.ListTagsOfResourceInput) (*dynamodb.ListTagsOfResourceOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) ListTagsOfResourceWithContext(context.Context, *dynamodb.ListTagsOfResourceInput, ...request.Option) (*dynamodb.ListTagsOfResourceOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) ListTagsOfResourceRequest(*dynamodb.ListTagsOfResourceInput) (*request.Request, *dynamodb.ListTagsOfResourceOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.ListTagsOfResourceOutput{}
}

func (d *Dax) RestoreTableFromBackup(*dynamodb.RestoreTableFromBackupInput) (*dynamodb.RestoreTableFromBackupOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) RestoreTableFromBackupWithContext(context.Context, *dynamodb.RestoreTableFromBackupInput, ...request.Option) (*dynamodb.RestoreTableFromBackupOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) RestoreTableFromBackupRequest(*dynamodb.RestoreTableFromBackupInput) (*request.Request, *dynamodb.RestoreTableFromBackupOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.RestoreTableFromBackupOutput{}
}

func (d *Dax) RestoreTableToPointInTime(*dynamodb.RestoreTableToPointInTimeInput) (*dynamodb.RestoreTableToPointInTimeOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) RestoreTableToPointInTimeWithContext(context.Context, *dynamodb.RestoreTableToPointInTimeInput, ...request.Option) (*dynamodb.RestoreTableToPointInTimeOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) RestoreTableToPointInTimeRequest(*dynamodb.RestoreTableToPointInTimeInput) (*request.Request, *dynamodb.RestoreTableToPointInTimeOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.RestoreTableToPointInTimeOutput{}
}

func (d *Dax) TagResource(*dynamodb.TagResourceInput) (*dynamodb.TagResourceOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) TagResourceWithContext(context.Context, *dynamodb.TagResourceInput, ...request.Option) (*dynamodb.TagResourceOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) TagResourceRequest(*dynamodb.TagResourceInput) (*request.Request, *dynamodb.TagResourceOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.TagResourceOutput{}
}

func (d *Dax) UntagResource(*dynamodb.UntagResourceInput) (*dynamodb.UntagResourceOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) UntagResourceWithContext(context.Context, *dynamodb.UntagResourceInput, ...request.Option) (*dynamodb.UntagResourceOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) UntagResourceRequest(*dynamodb.UntagResourceInput) (*request.Request, *dynamodb.UntagResourceOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.UntagResourceOutput{}
}

func (d *Dax) UpdateContinuousBackups(*dynamodb.UpdateContinuousBackupsInput) (*dynamodb.UpdateContinuousBackupsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) UpdateContinuousBackupsWithContext(context.Context, *dynamodb.UpdateContinuousBackupsInput, ...request.Option) (*dynamodb.UpdateContinuousBackupsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) UpdateContinuousBackupsRequest(*dynamodb.UpdateContinuousBackupsInput) (*request.Request, *dynamodb.UpdateContinuousBackupsOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.UpdateContinuousBackupsOutput{}
}

func (d *Dax) UpdateContributorInsights(*dynamodb.UpdateContributorInsightsInput) (*dynamodb.UpdateContributorInsightsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) UpdateContributorInsightsWithContext(context.Context, *dynamodb.UpdateContributorInsightsInput, ...request.Option) (*dynamodb.UpdateContributorInsightsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) UpdateContributorInsightsRequest(*dynamodb.UpdateContributorInsightsInput) (*request.Request, *dynamodb.UpdateContributorInsightsOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.UpdateContributorInsightsOutput{}
}

func (d *Dax) UpdateGlobalTable(*dynamodb.UpdateGlobalTableInput) (*dynamodb.UpdateGlobalTableOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) UpdateGlobalTableWithContext(context.Context, *dynamodb.UpdateGlobalTableInput, ...request.Option) (*dynamodb.UpdateGlobalTableOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) UpdateGlobalTableRequest(*dynamodb.UpdateGlobalTableInput) (*request.Request, *dynamodb.UpdateGlobalTableOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.UpdateGlobalTableOutput{}
}

func (d *Dax) UpdateGlobalTableSettings(*dynamodb.UpdateGlobalTableSettingsInput) (*dynamodb.UpdateGlobalTableSettingsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) UpdateGlobalTableSettingsWithContext(context.Context, *dynamodb.UpdateGlobalTableSettingsInput, ...request.Option) (*dynamodb.UpdateGlobalTableSettingsOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) UpdateGlobalTableSettingsRequest(*dynamodb.UpdateGlobalTableSettingsInput) (*request.Request, *dynamodb.UpdateGlobalTableSettingsOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.UpdateGlobalTableSettingsOutput{}
}

func (d *Dax) UpdateTable(*dynamodb.UpdateTableInput) (*dynamodb.UpdateTableOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) UpdateTableWithContext(context.Context, *dynamodb.UpdateTableInput, ...request.Option) (*dynamodb.UpdateTableOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) UpdateTableRequest(*dynamodb.UpdateTableInput) (*request.Request, *dynamodb.UpdateTableOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.UpdateTableOutput{}
}

func (d *Dax) UpdateTableReplicaAutoScaling(*dynamodb.UpdateTableReplicaAutoScalingInput) (*dynamodb.UpdateTableReplicaAutoScalingOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) UpdateTableReplicaAutoScalingWithContext(context.Context, *dynamodb.UpdateTableReplicaAutoScalingInput, ...request.Option) (*dynamodb.UpdateTableReplicaAutoScalingOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) UpdateTableReplicaAutoScalingRequest(*dynamodb.UpdateTableReplicaAutoScalingInput) (*request.Request, *dynamodb.UpdateTableReplicaAutoScalingOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.UpdateTableReplicaAutoScalingOutput{}
}

func (d *Dax) UpdateTimeToLive(*dynamodb.UpdateTimeToLiveInput) (*dynamodb.UpdateTimeToLiveOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) UpdateTimeToLiveWithContext(context.Context, *dynamodb.UpdateTimeToLiveInput, ...request.Option) (*dynamodb.UpdateTimeToLiveOutput, error) {
	return nil, d.unImpl()
}

func (d *Dax) UpdateTimeToLiveRequest(*dynamodb.UpdateTimeToLiveInput) (*request.Request, *dynamodb.UpdateTimeToLiveOutput) {
	return newRequestForUnimplementedOperation(), &dynamodb.UpdateTimeToLiveOutput{}
}

func (d *Dax) WaitUntilTableExists(*dynamodb.DescribeTableInput) error {
	return d.unImpl()
}

func (d *Dax) WaitUntilTableExistsWithContext(context.Context, *dynamodb.DescribeTableInput, ...request.WaiterOption) error {
	return d.unImpl()
}

func (d *Dax) WaitUntilTableNotExists(*dynamodb.DescribeTableInput) error {
	return d.unImpl()
}

func (d *Dax) WaitUntilTableNotExistsWithContext(context.Context, *dynamodb.DescribeTableInput, ...request.WaiterOption) error {
	return d.unImpl()
}

func (d *Dax) unImpl() error {
	return errors.New(client.ErrCodeNotImplemented)
}

func (d *Dax) Close() error {
	if c, ok := d.client.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
