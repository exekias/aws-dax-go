package internal

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	dynamov1 "github.com/aws/aws-sdk-go/service/dynamodb"
)

func ConvertConditionMap(in map[string]types.Condition) map[string]*dynamov1.Condition {
	out := make(map[string]*dynamov1.Condition)
	for key, value := range in {
		co := string(value.ComparisonOperator)
		out[key] = &dynamov1.Condition{
			AttributeValueList: ConvertAttributeValueV2toV1List(value.AttributeValueList),
			ComparisonOperator: &co,
		}
	}
	return out
}

func ConvertItemCollectionMetrics(metrics dynamov1.ItemCollectionMetrics) *types.ItemCollectionMetrics {
	size := make([]float64, 0)
	for _, ser := range metrics.SizeEstimateRangeGB {
		size = append(size, *ser)
	}
	return &types.ItemCollectionMetrics{
		ItemCollectionKey: ConvertAttributeValueV1toV2Map(metrics.ItemCollectionKey),
		SizeEstimateRangeGB: size,
	}
}

func ConvertConsumedCapacity(capacity *dynamov1.ConsumedCapacity) *types.ConsumedCapacity {
	gsi := make(map[string]types.Capacity)
	for key, idx := range capacity.GlobalSecondaryIndexes {
		gsi[key] = types.Capacity{
			CapacityUnits:      idx.CapacityUnits,
			ReadCapacityUnits:  idx.ReadCapacityUnits,
			WriteCapacityUnits: idx.WriteCapacityUnits,
		}
	}
	lsi := make(map[string]types.Capacity)
	for key, idx := range capacity.LocalSecondaryIndexes {
		lsi[key] = types.Capacity{
			CapacityUnits:      idx.CapacityUnits,
			ReadCapacityUnits:  idx.ReadCapacityUnits,
			WriteCapacityUnits: idx.WriteCapacityUnits,
		}
	}

	table := &types.Capacity{
		CapacityUnits:      capacity.Table.CapacityUnits,
		ReadCapacityUnits:  capacity.Table.ReadCapacityUnits,
		WriteCapacityUnits: capacity.Table.WriteCapacityUnits,
	}

	return &types.ConsumedCapacity{
		CapacityUnits:          capacity.CapacityUnits,
		GlobalSecondaryIndexes: gsi,
		LocalSecondaryIndexes:  lsi,
		ReadCapacityUnits:      capacity.ReadCapacityUnits,
		Table:                  table,
		TableName:              capacity.TableName,
		WriteCapacityUnits:     capacity.WriteCapacityUnits,
	}
}

func ConvertToPointerMap(input map[string]string) map[string]*string {
	output := make(map[string]*string)
	for key, val := range input {
		output[key] = &val
	}
	return output
}

func ConvertExpectedAttributeValueV2toV1Map(values map[string]types.ExpectedAttributeValue) map[string]*dynamov1.ExpectedAttributeValue {
	out := make(map[string]*dynamov1.ExpectedAttributeValue)
	for key, val := range values {
		out[key] = ConvertExpectedAttributeValueV2toV1(val)
	}

	return out
}

func ConvertExpectedAttributeValueV2toV1(value types.ExpectedAttributeValue) *dynamov1.ExpectedAttributeValue {
	return &dynamov1.ExpectedAttributeValue{
		AttributeValueList: ConvertAttributeValueV2toV1List(value.AttributeValueList),
		ComparisonOperator: (*string)(&value.ComparisonOperator),
		Exists:             value.Exists,
		Value:              ConvertAttributeValueV2toV1(value.Value),
	}
}

func ConvertAttributeValueV2toV1List(values []types.AttributeValue) []*dynamov1.AttributeValue {
	out := make([]*dynamov1.AttributeValue, 0)
	for _, val := range values {
		v := ConvertAttributeValueV2toV1(val)
		out = append(out, v)
	}

	return out
}

func ConvertAttributeValueV2toV1Map(values map[string]types.AttributeValue) map[string]*dynamov1.AttributeValue {
	out := make(map[string]*dynamov1.AttributeValue)
	for key, val := range values {
		v := ConvertAttributeValueV2toV1(val)
		out[key] = v
	}

	return out
}

func ConvertAttributeValueV2toV1(value types.AttributeValue) *dynamov1.AttributeValue {
	val := dynamov1.AttributeValue{}
	switch v := value.(type) {
	case *types.AttributeValueMemberB:
		val.B = v.Value // Value is []byte

	case *types.AttributeValueMemberBOOL:
		val.BOOL = &v.Value // Value is bool

	case *types.AttributeValueMemberBS:
		val.BS = v.Value // Value is [][]byte

	case *types.AttributeValueMemberL:
		{
			v1 := make([]*dynamov1.AttributeValue, 0)
			for _, av := range v.Value {
				t := ConvertAttributeValueV2toV1(av)
				v1 = append(v1, t)
			}
			val.L = v1 // Value is []types.AttributeValue
		}

	case *types.AttributeValueMemberM:
		v1 := make(map[string]*dynamov1.AttributeValue)
		for key, val := range v.Value {
			v2 := ConvertAttributeValueV2toV1(val)
			v1[key] = v2
		}
		val.M = v1

	case *types.AttributeValueMemberN:
		val.N = &v.Value

	case *types.AttributeValueMemberNS:
		v1 := make([]*string, 0)
		for _, val := range v.Value {
			v1 = append(v1, &val)
		}
		val.NS = v1

	case *types.AttributeValueMemberNULL:
		val.NULL = &v.Value

	case *types.AttributeValueMemberS:
		val.S = &v.Value

	case *types.AttributeValueMemberSS:
		v1 := make([]*string, 0)
		for _, val := range v.Value {
			v1 = append(v1, &val)
		}
		val.NS = v1

	case *types.UnknownUnionMember:
		fmt.Println("unknown tag:", v.Tag)

	default:
		fmt.Println("union is nil or unknown type")
	}
	return &val
}

func ConvertAttributeValueV1toV2Map(values map[string]*dynamov1.AttributeValue) map[string]types.AttributeValue {
	output := make(map[string]types.AttributeValue)
	for key, value := range values {
		output[key] = ConvertAttributeValueV1toV2(value)
	}
	return output
}

func ConvertAttributeValueV1toV2(value *dynamov1.AttributeValue) types.AttributeValue {
	if len(value.B) > 0 {
		return &types.AttributeValueMemberB{Value: value.B}
	}
	if len(value.BS) > 0 {
		return &types.AttributeValueMemberBS{Value: value.BS}
	}
	if len(value.L) > 0 {
		v := make([]types.AttributeValue, 0)
		for _, av := range value.L {
			v = append(v, ConvertAttributeValueV1toV2(av))
		}
		return &types.AttributeValueMemberL{Value: v}
	}
	if len(value.M) > 0 {
		v := make(map[string]types.AttributeValue)
		for key, val := range value.M {
			v[key] = ConvertAttributeValueV1toV2(val)
		}
		return &types.AttributeValueMemberM{Value: v}
	}
	if value.BOOL != nil {
		return &types.AttributeValueMemberBOOL{Value: *value.BOOL}
	}
	if value.N != nil {
		return &types.AttributeValueMemberN{Value: *value.N}
	}
	if value.NS != nil {
		v := make([]string, 0)
		for _, val := range value.NS {
			v = append(v, *val)
		}
		return &types.AttributeValueMemberNS{Value: v}
	}
	if value.NULL != nil {
		return &types.AttributeValueMemberNULL{Value: *value.NULL}
	}
	if value.S != nil {
		return &types.AttributeValueMemberS{Value: *value.S}
	}
	if len(value.SS) > 0 {
		v := make([]string, 0)
		for _, val := range value.SS {
			v = append(v, *val)
		}
		return &types.AttributeValueMemberSS{Value: v}
	}

	return nil
}
