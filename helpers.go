package ethrpc

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
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

// ParseInt parse hex string value to int
func ParseInt(value string) (int, error) {
	i, err := strconv.ParseInt(strings.TrimPrefix(value, "0x"), 16, 64)
	if err != nil {
		return 0, err
	}

	return int(i), nil
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
