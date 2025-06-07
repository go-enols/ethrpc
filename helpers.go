package ethrpc

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func ParseBool(value string) bool {
	bigInt := new(big.Int)

	// 将十六进制字符串转换为 big.Int
	_, success := bigInt.SetString(value[2:], 16) // [2:] 用于去除 "0x" 前缀

	// 检查转换是否成功，并且 big.Int 的符号是否为正（即非零值）
	return success && bigInt.Sign() > 0
}

func ParseFloat(value *big.Int, decimal Decimal) (float64, error) {
	if value == nil {
		return 0, fmt.Errorf("value is nil")
	}

	fValue := new(big.Float).SetInt(value)
	fDecimal := new(big.Float).SetInt64(int64(decimal))
	result, _ := new(big.Float).Quo(fValue, fDecimal).Float64()
	return result, nil
}

func ParseBig(value float64, decimal Decimal) *big.Int {
	// 将单位转换为 *big.Int
	unitBigInt := big.NewInt(int64(decimal))

	// 将浮点数值转换为 *big.Float
	valueBigFloat := new(big.Float).SetFloat64(value)

	// 将单位转换为 *big.Float
	unitBigFloat := new(big.Float).SetInt(unitBigInt)

	// 计算 Wei 的值
	weiBigFloat := new(big.Float).Mul(valueBigFloat, unitBigFloat)

	// 将 *big.Float 转换为 *big.Int
	weiBigInt := new(big.Int)
	weiBigFloat.Int(weiBigInt) // 注意：这里可能会有精度损失

	return weiBigInt
}

// ParseInt parse hex string value to int
func ParseInt(value string) (int, error) {
	i, err := strconv.ParseInt(strings.TrimPrefix(value, "0x"), 16, 64)
	if err != nil {
		return 0, err
	}

	return int(i), nil
}

// ParseInt parse hex string value to int
func ParseInt64(value string) (int64, error) {
	i, err := strconv.ParseInt(strings.TrimPrefix(value, "0x"), 16, 64)
	if err != nil {
		return 0, err
	}

	return i, nil
}

// ParseBigInt parse hex string value to big.Int
func ParseBigInt(value string) (big.Int, error) {
	i := big.Int{}
	_, err := fmt.Sscan(value, &i)

	return i, err
}

// IntToHex convert int to hexadecimal representation
func IntToHex(i int) string {
	return fmt.Sprintf("0x%x", i)
}

// BigToHex covert big.Int to hexadecimal representation
func BigToHex(bigInt big.Int) string {
	if bigInt.BitLen() == 0 {
		return "0x0"
	}

	return "0x" + strings.TrimPrefix(fmt.Sprintf("%x", bigInt.Bytes()), "0")
}

func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	if number.Sign() >= 0 {
		return hexutil.EncodeBig(number)
	}
	// It's negative.
	if number.IsInt64() {
		return number.String()
	}
	// It's negative and large, which is invalid.
	return fmt.Sprintf("<invalid %d>", number)
}

func toCallArg(msg ethereum.CallMsg) interface{} {
	arg := map[string]interface{}{
		"from": msg.From,
		"to":   msg.To,
	}
	if len(msg.Data) > 0 {
		arg["input"] = hexutil.Bytes(msg.Data)
	}
	if msg.Value != nil {
		arg["value"] = (*hexutil.Big)(msg.Value)
	}
	if msg.Gas != 0 {
		arg["gas"] = hexutil.Uint64(msg.Gas)
	}
	if msg.GasPrice != nil {
		arg["gasPrice"] = (*hexutil.Big)(msg.GasPrice)
	}
	if msg.GasFeeCap != nil {
		arg["maxFeePerGas"] = (*hexutil.Big)(msg.GasFeeCap)
	}
	if msg.GasTipCap != nil {
		arg["maxPriorityFeePerGas"] = (*hexutil.Big)(msg.GasTipCap)
	}
	if msg.AccessList != nil {
		arg["accessList"] = msg.AccessList
	}
	if msg.BlobGasFeeCap != nil {
		arg["maxFeePerBlobGas"] = (*hexutil.Big)(msg.BlobGasFeeCap)
	}
	if msg.BlobHashes != nil {
		arg["blobVersionedHashes"] = msg.BlobHashes
	}
	if msg.AuthorizationList != nil {
		arg["authorizationList"] = msg.AuthorizationList
	}
	return arg
}
