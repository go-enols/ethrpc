package ethrpc

import (
	"context"
	"encoding/json"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

type EthereumAPI interface {
	// 基础 Web3 方法
	Web3ClientVersion() (string, error)
	Web3Sha3(data []byte) (string, error)
	
	// 网络相关方法
	NetVersion() (string, error)
	NetListening() (bool, error)
	NetPeerCount() (int, error)
	
	// 以太坊协议方法
	EthProtocolVersion() (string, error)
	EthSyncing() (*Syncing, error)
	EthCoinbase() (string, error)
	EthMining() (bool, error)
	EthHashrate() (int, error)
	EthGasPrice() (big.Int, error)
	EthAccounts() ([]string, error)
	EthBlockNumber() (int, error)
	EthGetBalance(address, block string) (big.Int, error)
	EthGetStorageAt(data string, position int, tag string) (string, error)
	EthGetTransactionCount(address, block string) (int, error)
	EthGetBlockTransactionCountByHash(hash string) (int, error)
	EthGetBlockTransactionCountByNumber(number int) (int, error)
	EthGetUncleCountByBlockHash(hash string) (int, error)
	EthGetUncleCountByBlockNumber(number int) (int, error)
	EthGetCode(address, block string) (string, error)
	EthSign(address, data string) (string, error)
	EthSendTransaction(transaction T) (string, error)
	EthSendRawTransaction(data string) (string, error)
	EthCall(transaction T, tag string) (string, error)
	EthEstimateGas(transaction T) (int, error)
	EthGetBlockByHash(hash string, withTransactions bool) (*Block, error)
	EthGetBlockByNumber(number int, withTransactions bool) (*Block, error)
	EthGetTransactionByHash(hash string) (*Transaction, error)
	EthGetTransactionByBlockHashAndIndex(blockHash string, transactionIndex int) (*Transaction, error)
	EthGetTransactionByBlockNumberAndIndex(blockNumber, transactionIndex int) (*Transaction, error)
	EthGetTransactionReceipt(hash string) (*TransactionReceipt, error)
	EthGetCompilers() ([]string, error)
	EthNewFilter(params FilterParams) (string, error)
	EthNewBlockFilter() (string, error)
	EthNewPendingTransactionFilter() (string, error)
	EthUninstallFilter(filterID string) (bool, error)
	EthGetFilterChanges(filterID string) ([]Log, error)
	EthGetFilterLogs(filterID string) ([]Log, error)
	EthGetLogs(params FilterParams) ([]Log, error)
	
	// Go-Ethereum 兼容方法
	CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)
	EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error)
	CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
	SuggestGasPrice(ctx context.Context) (*big.Int, error)
	SuggestGasTipCap(ctx context.Context) (*big.Int, error)
	SendTransaction(ctx context.Context, tx *types.Transaction) error
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
	PendingCodeAt(ctx context.Context, account common.Address) ([]byte, error)
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
	FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error)
	SubscribeFilterLogs(ctx context.Context, q ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error)
	
	// 底层调用方法
	URL() string
	Call(method string, params ...interface{}) (json.RawMessage, error)
	RawCall(method string, params ...interface{}) (json.RawMessage, error)
	CallContext(ctx context.Context, result interface{}, method string, args ...interface{}) error
	CallList(requests []BatchRequest) (*BatchResult, error)
	
	// 批量处理方法
	BatchWeb3ClientVersion(count int) ([]string, []error, error)
	BatchEthBlockNumber(count int) ([]int, []error, error)
	BatchEthGasPrice(count int) ([]big.Int, []error, error)
	BatchEthGetBalance(addresses []string, block string) ([]big.Int, []error, error)
	BatchEthGetTransactionCount(addresses []string, block string) ([]int, []error, error)
	BatchEthGetCode(addresses []string, block string) ([]string, []error, error)
	BatchEthCall(transactions []T, tag string) ([]string, []error, error)
	BatchEthEstimateGas(transactions []T) ([]int, []error, error)
	BatchEthGetTransactionByHash(hashes []string) ([]*Transaction, []error, error)
	BatchEthGetTransactionReceipt(hashes []string) ([]*TransactionReceipt, []error, error)
	BatchEthGetBlockByNumber(numbers []int, withTransactions bool) ([]*Block, []error, error)
	BatchEthGetBlockByHash(hashes []string, withTransactions bool) ([]*Block, []error, error)
	
	// 工具方法
	Eth1() *big.Int
	
	// 等待交易完成的方法
	WaitForTransactionReceipt(txHash string, timeout time.Duration, pollInterval time.Duration) (*TransactionReceipt, error)
	BatchWaitForTransactionReceipts(txHashes []string, timeout time.Duration, pollInterval time.Duration) ([]*TransactionReceipt, error)
	MonitorTransactionStatus(txHash string, statusChan chan<- TransactionStatus, timeout time.Duration, pollInterval time.Duration)
}

var _ EthereumAPI = (*EthRPC)(nil)
