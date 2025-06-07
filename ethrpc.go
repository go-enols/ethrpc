package ethrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"

	"log"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
)

// EthError - ethereum error
type EthError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (err EthError) Error() string {
	return fmt.Sprintf("Error %d (%s)", err.Code, err.Message)
}

type ethResponse struct {
	ID      int             `json:"id"`
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   *EthError       `json:"error"`
}

type ethRequest struct {
	ID      int           `json:"id"`
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

// EthRPC - Ethereum rpc client
type EthRPC struct {
	url    string
	client httpClient
	log    logger
	Debug  bool
}

func (rpc *EthRPC) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	var hex hexutil.Big
	if err := rpc.CallContext(ctx, &hex, "eth_gasPrice"); err != nil {
		return nil, err
	}
	return (*big.Int)(&hex), nil
}

func (rpc *EthRPC) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	var hex hexutil.Big
	if err := rpc.CallContext(ctx, &hex, "eth_maxPriorityFeePerGas"); err != nil {
		return nil, err
	}
	return (*big.Int)(&hex), nil
}

// New create new rpc client with given url
func New(url string, options ...func(rpc *EthRPC)) *EthRPC {
	rpc := &EthRPC{
		url:    url,
		client: http.DefaultClient,
		log:    log.New(os.Stderr, "", log.LstdFlags),
	}
	for _, option := range options {
		option(rpc)
	}

	return rpc
}

// NewEthRPC create new rpc client with given url
func NewEthRPC(url string, options ...func(rpc *EthRPC)) *EthRPC {
	return New(url, options...)
}

func (rpc *EthRPC) CallContext(ctx context.Context, result interface{}, method string, args ...interface{}) error {
	return rpc.call(method, result, args...)
}

func (rpc *EthRPC) call(method string, target interface{}, params ...interface{}) error {
	if len(params) == 0 {
		params = []interface{}{}
	}
	result, err := rpc.Call(method, params...)
	if err != nil {
		return err
	}

	if target == nil {
		return nil
	}

	return json.Unmarshal(result, target)
}

// URL returns client url
func (rpc *EthRPC) URL() string {
	return rpc.url
}

// Call returns raw response of method call
func (rpc *EthRPC) Call(method string, params ...interface{}) (json.RawMessage, error) {
	request := ethRequest{
		ID:      1,
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
	}

	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	response, err := rpc.client.Post(rpc.url, "application/json", bytes.NewBuffer(body))
	if response != nil {
		defer response.Body.Close()
	}
	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if rpc.Debug {
		rpc.log.Println(fmt.Sprintf("%s\nRequest: %s\nResponse: %s\n", method, body, data))
	}

	resp := new(ethResponse)
	if err := json.Unmarshal(data, resp); err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, *resp.Error
	}

	return resp.Result, nil

}

// RawCall returns raw response of method call (Deprecated)
func (rpc *EthRPC) RawCall(method string, params ...interface{}) (json.RawMessage, error) {
	return rpc.Call(method, params...)
}

// Web3ClientVersion returns the current client version.
func (rpc *EthRPC) Web3ClientVersion() (string, error) {
	var clientVersion string

	err := rpc.call("web3_clientVersion", &clientVersion)
	return clientVersion, err
}

// Web3Sha3 returns Keccak-256 (not the standardized SHA3-256) of the given data.
func (rpc *EthRPC) Web3Sha3(data []byte) (string, error) {
	var hash string

	err := rpc.call("web3_sha3", &hash, fmt.Sprintf("0x%x", data))
	return hash, err
}

// NetVersion returns the current network protocol version.
func (rpc *EthRPC) NetVersion() (string, error) {
	var version string

	err := rpc.call("net_version", &version)
	return version, err
}

// NetListening returns true if client is actively listening for network connections.
func (rpc *EthRPC) NetListening() (bool, error) {
	var listening bool

	err := rpc.call("net_listening", &listening)
	return listening, err
}

// NetPeerCount returns number of peers currently connected to the client.
func (rpc *EthRPC) NetPeerCount() (int, error) {
	var response string
	if err := rpc.call("net_peerCount", &response); err != nil {
		return 0, err
	}

	return ParseInt(response)
}

// EthProtocolVersion returns the current ethereum protocol version.
func (rpc *EthRPC) EthProtocolVersion() (string, error) {
	var protocolVersion string

	err := rpc.call("eth_protocolVersion", &protocolVersion)
	return protocolVersion, err
}

// EthSyncing returns an object with data about the sync status or false.
func (rpc *EthRPC) EthSyncing() (*Syncing, error) {
	result, err := rpc.RawCall("eth_syncing")
	if err != nil {
		return nil, err
	}
	syncing := new(Syncing)
	if bytes.Equal(result, []byte("false")) {
		return syncing, nil
	}
	err = json.Unmarshal(result, syncing)
	return syncing, err
}

// EthCoinbase returns the client coinbase address
func (rpc *EthRPC) EthCoinbase() (string, error) {
	var address string

	err := rpc.call("eth_coinbase", &address)
	return address, err
}

// EthMining returns true if client is actively mining new blocks.
func (rpc *EthRPC) EthMining() (bool, error) {
	var mining bool

	err := rpc.call("eth_mining", &mining)
	return mining, err
}

// EthHashrate returns the number of hashes per second that the node is mining with.
func (rpc *EthRPC) EthHashrate() (int, error) {
	var response string

	if err := rpc.call("eth_hashrate", &response); err != nil {
		return 0, err
	}

	return ParseInt(response)
}

// EthGasPrice returns the current price per gas in wei.
func (rpc *EthRPC) EthGasPrice() (big.Int, error) {
	var response string
	if err := rpc.call("eth_gasPrice", &response); err != nil {
		return big.Int{}, err
	}

	return ParseBigInt(response)
}

// EthAccounts returns a list of addresses owned by client.
func (rpc *EthRPC) EthAccounts() ([]string, error) {
	accounts := []string{}

	err := rpc.call("eth_accounts", &accounts)
	return accounts, err
}

// EthBlockNumber returns the number of most recent block.
func (rpc *EthRPC) EthBlockNumber() (int, error) {
	var response string
	if err := rpc.call("eth_blockNumber", &response); err != nil {
		return 0, err
	}

	return ParseInt(response)
}

// EthGetBalance returns the balance of the account of given address in wei.
func (rpc *EthRPC) EthGetBalance(address, block string) (big.Int, error) {
	var response string
	if err := rpc.call("eth_getBalance", &response, address, block); err != nil {
		return big.Int{}, err
	}

	return ParseBigInt(response)
}

// EthGetStorageAt returns the value from a storage position at a given address.
func (rpc *EthRPC) EthGetStorageAt(data string, position int, tag string) (string, error) {
	var result string

	err := rpc.call("eth_getStorageAt", &result, data, IntToHex(position), tag)
	return result, err
}

// EthGetTransactionCount returns the number of transactions sent from an address.
func (rpc *EthRPC) EthGetTransactionCount(address, block string) (int, error) {
	var response string

	if err := rpc.call("eth_getTransactionCount", &response, address, block); err != nil {
		return 0, err
	}

	return ParseInt(response)
}

// EthGetBlockTransactionCountByHash returns the number of transactions in a block from a block matching the given block hash.
func (rpc *EthRPC) EthGetBlockTransactionCountByHash(hash string) (int, error) {
	var response string

	if err := rpc.call("eth_getBlockTransactionCountByHash", &response, hash); err != nil {
		return 0, err
	}

	return ParseInt(response)
}

// EthGetBlockTransactionCountByNumber returns the number of transactions in a block from a block matching the given block
func (rpc *EthRPC) EthGetBlockTransactionCountByNumber(number int) (int, error) {
	var response string

	if err := rpc.call("eth_getBlockTransactionCountByNumber", &response, IntToHex(number)); err != nil {
		return 0, err
	}

	return ParseInt(response)
}

// EthGetUncleCountByBlockHash returns the number of uncles in a block from a block matching the given block hash.
func (rpc *EthRPC) EthGetUncleCountByBlockHash(hash string) (int, error) {
	var response string

	if err := rpc.call("eth_getUncleCountByBlockHash", &response, hash); err != nil {
		return 0, err
	}

	return ParseInt(response)
}

// EthGetUncleCountByBlockNumber returns the number of uncles in a block from a block matching the given block number.
func (rpc *EthRPC) EthGetUncleCountByBlockNumber(number int) (int, error) {
	var response string

	if err := rpc.call("eth_getUncleCountByBlockNumber", &response, IntToHex(number)); err != nil {
		return 0, err
	}

	return ParseInt(response)
}

// EthGetCode returns code at a given address.
func (rpc *EthRPC) EthGetCode(address, block string) (string, error) {
	var code string

	err := rpc.call("eth_getCode", &code, address, block)
	return code, err
}

// EthSign signs data with a given address.
// Calculates an Ethereum specific signature with: sign(keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)))
func (rpc *EthRPC) EthSign(address, data string) (string, error) {
	var signature string

	err := rpc.call("eth_sign", &signature, address, data)
	return signature, err
}

// EthSendTransaction creates new message call transaction or a contract creation, if the data field contains code.
func (rpc *EthRPC) EthSendTransaction(transaction T) (string, error) {
	var hash string

	err := rpc.call("eth_sendTransaction", &hash, transaction)
	return hash, err
}

// EthSendRawTransaction creates new message call transaction or a contract creation for signed transactions.
func (rpc *EthRPC) EthSendRawTransaction(data string) (string, error) {
	var hash string

	err := rpc.call("eth_sendRawTransaction", &hash, data)
	return hash, err
}

// EthCall executes a new message call immediately without creating a transaction on the block chain.
func (rpc *EthRPC) EthCall(transaction T, tag string) (string, error) {
	var data string

	err := rpc.call("eth_call", &data, transaction, tag)
	return data, err
}

// EthEstimateGas makes a call or transaction, which won't be added to the blockchain and returns the used gas, which can be used for estimating the used gas.
func (rpc *EthRPC) EthEstimateGas(transaction T) (int, error) {
	var response string

	err := rpc.call("eth_estimateGas", &response, transaction)
	if err != nil {
		return 0, err
	}

	return ParseInt(response)
}

func (rpc *EthRPC) EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error) {
	var hex hexutil.Uint64
	err := rpc.call("eth_estimateGas", &hex, toCallArg(msg))
	if err != nil {
		return 0, err
	}
	return uint64(hex), nil
}

func (rpc *EthRPC) getBlock(method string, withTransactions bool, params ...interface{}) (*Block, error) {
	result, err := rpc.RawCall(method, params...)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(result, []byte("null")) {
		return nil, nil
	}

	var response proxyBlock
	if withTransactions {
		response = new(proxyBlockWithTransactions)
	} else {
		response = new(proxyBlockWithoutTransactions)
	}

	err = json.Unmarshal(result, response)
	if err != nil {
		return nil, err
	}

	block := response.toBlock()
	return &block, nil
}

// EthGetBlockByHash returns information about a block by hash.
func (rpc *EthRPC) EthGetBlockByHash(hash string, withTransactions bool) (*Block, error) {
	return rpc.getBlock("eth_getBlockByHash", withTransactions, hash, withTransactions)
}

// EthGetBlockByNumber returns information about a block by block number.
func (rpc *EthRPC) EthGetBlockByNumber(number int, withTransactions bool) (*Block, error) {
	return rpc.getBlock("eth_getBlockByNumber", withTransactions, IntToHex(number), withTransactions)
}

func (rpc *EthRPC) getTransaction(method string, params ...interface{}) (*Transaction, error) {
	transaction := new(Transaction)

	err := rpc.call(method, transaction, params...)
	return transaction, err
}

// EthGetTransactionByHash returns the information about a transaction requested by transaction hash.
func (rpc *EthRPC) EthGetTransactionByHash(hash string) (*Transaction, error) {
	return rpc.getTransaction("eth_getTransactionByHash", hash)
}

// EthGetTransactionByBlockHashAndIndex returns information about a transaction by block hash and transaction index position.
func (rpc *EthRPC) EthGetTransactionByBlockHashAndIndex(blockHash string, transactionIndex int) (*Transaction, error) {
	return rpc.getTransaction("eth_getTransactionByBlockHashAndIndex", blockHash, IntToHex(transactionIndex))
}

// EthGetTransactionByBlockNumberAndIndex returns information about a transaction by block number and transaction index position.
func (rpc *EthRPC) EthGetTransactionByBlockNumberAndIndex(blockNumber, transactionIndex int) (*Transaction, error) {
	return rpc.getTransaction("eth_getTransactionByBlockNumberAndIndex", IntToHex(blockNumber), IntToHex(transactionIndex))
}

// EthGetTransactionReceipt returns the receipt of a transaction by transaction hash.
// Note That the receipt is not available for pending transactions.
func (rpc *EthRPC) EthGetTransactionReceipt(hash string) (*TransactionReceipt, error) {
	transactionReceipt := new(TransactionReceipt)

	err := rpc.call("eth_getTransactionReceipt", transactionReceipt, hash)
	if err != nil {
		return nil, err
	}

	return transactionReceipt, nil
}

// EthGetCompilers returns a list of available compilers in the client.
func (rpc *EthRPC) EthGetCompilers() ([]string, error) {
	compilers := []string{}

	err := rpc.call("eth_getCompilers", &compilers)
	return compilers, err
}

// EthNewFilter creates a new filter object.
func (rpc *EthRPC) EthNewFilter(params FilterParams) (string, error) {
	var filterID string
	err := rpc.call("eth_newFilter", &filterID, params)
	return filterID, err
}

// EthNewBlockFilter creates a filter in the node, to notify when a new block arrives.
// To check if the state has changed, call EthGetFilterChanges.
func (rpc *EthRPC) EthNewBlockFilter() (string, error) {
	var filterID string
	err := rpc.call("eth_newBlockFilter", &filterID)
	return filterID, err
}

// EthNewPendingTransactionFilter creates a filter in the node, to notify when new pending transactions arrive.
// To check if the state has changed, call EthGetFilterChanges.
func (rpc *EthRPC) EthNewPendingTransactionFilter() (string, error) {
	var filterID string
	err := rpc.call("eth_newPendingTransactionFilter", &filterID)
	return filterID, err
}

// EthUninstallFilter uninstalls a filter with given id.
func (rpc *EthRPC) EthUninstallFilter(filterID string) (bool, error) {
	var res bool
	err := rpc.call("eth_uninstallFilter", &res, filterID)
	return res, err
}

// EthGetFilterChanges polling method for a filter, which returns an array of logs which occurred since last poll.
func (rpc *EthRPC) EthGetFilterChanges(filterID string) ([]Log, error) {
	var logs = []Log{}
	err := rpc.call("eth_getFilterChanges", &logs, filterID)
	return logs, err
}

// EthGetFilterLogs returns an array of all logs matching filter with given id.
func (rpc *EthRPC) EthGetFilterLogs(filterID string) ([]Log, error) {
	var logs = []Log{}
	err := rpc.call("eth_getFilterLogs", &logs, filterID)
	return logs, err
}

// EthGetLogs returns an array of all logs matching a given filter object.
func (rpc *EthRPC) EthGetLogs(params FilterParams) ([]Log, error) {
	var logs = []Log{}
	err := rpc.call("eth_getLogs", &logs, params)
	return logs, err
}

// CodeAt returns the contract code of the given account.
// The block number can be nil, in which case the code is taken from the latest known block.
func (rpc *EthRPC) CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error) {
	var result hexutil.Bytes
	err := rpc.call("eth_getCode", &result, account, toBlockNumArg(blockNumber))
	return result, err
}

func (rpc *EthRPC) CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	var hex hexutil.Bytes
	err := rpc.call("eth_call", &hex, toCallArg(msg), toBlockNumArg(blockNumber))
	if err != nil {
		return nil, err
	}
	return hex, nil
}

func (rpc *EthRPC) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	// 将交易序列化为RLP编码的十六进制字符串
	data, err := tx.MarshalBinary()
	if err != nil {
		return err
	}

	// 发送原始交易
	_, err = rpc.EthSendRawTransaction(hexutil.Encode(data))
	return err
}

func (rpc *EthRPC) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	// 获取区块信息
	var blockNum int
	if number == nil {
		// 获取最新区块号
		latestNum, err := rpc.EthBlockNumber()
		if err != nil {
			return nil, err
		}
		blockNum = latestNum
	} else {
		blockNum = int(number.Int64())
	}

	block, err := rpc.EthGetBlockByNumber(blockNum, false)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, nil
	}

	// 解析Nonce
	nonce, err := ParseInt64(block.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to parse nonce: %v", err)
	}

	// 转换为types.Header
	header := &types.Header{
		ParentHash: common.HexToHash(block.ParentHash),
		UncleHash:  common.HexToHash(block.Sha3Uncles),
		Coinbase:   common.HexToAddress(block.Miner),
		Root:       common.HexToHash(block.StateRoot),
		TxHash:     common.HexToHash(block.TransactionsRoot),
		Number:     big.NewInt(int64(block.Number)),
		GasLimit:   uint64(block.GasLimit),
		GasUsed:    uint64(block.GasUsed),
		Time:       uint64(block.Timestamp),
		Extra:      common.FromHex(block.ExtraData),
		Nonce:      types.EncodeNonce(uint64(nonce)),
		Difficulty: (*big.Int)(&block.Difficulty),
	}

	return header, nil
}

func (rpc *EthRPC) PendingCodeAt(ctx context.Context, account common.Address) ([]byte, error) {
	// 获取pending状态下的合约代码
	code, err := rpc.EthGetCode(account.Hex(), "pending")
	if err != nil {
		return nil, err
	}

	return common.FromHex(code), nil
}

func (rpc *EthRPC) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	// 获取pending状态下的nonce
	nonce, err := rpc.EthGetTransactionCount(account.Hex(), "pending")
	if err != nil {
		return 0, err
	}

	return uint64(nonce), nil
}

func (rpc *EthRPC) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	// 构建过滤器参数
	params := FilterParams{
		FromBlock: toBlockNumArg(q.FromBlock),
		ToBlock:   toBlockNumArg(q.ToBlock),
	}

	// 设置地址过滤
	if len(q.Addresses) > 0 {
		addresses := make([]string, len(q.Addresses))
		for i, addr := range q.Addresses {
			addresses[i] = addr.Hex()
		}
		params.Address = addresses
	}

	// 设置主题过滤
	if len(q.Topics) > 0 {
		topics := make([][]string, len(q.Topics))
		for i, topicSet := range q.Topics {
			if len(topicSet) > 0 {
				topics[i] = make([]string, len(topicSet))
				for j, topic := range topicSet {
					topics[i][j] = topic.Hex()
				}
			}
		}
		params.Topics = topics
	}

	// 获取日志
	logs, err := rpc.EthGetLogs(params)
	if err != nil {
		return nil, err
	}

	// 转换为types.Log格式
	result := make([]types.Log, len(logs))
	for i, log := range logs {
		topics := make([]common.Hash, len(log.Topics))
		for j, topic := range log.Topics {
			topics[j] = common.HexToHash(topic)
		}

		result[i] = types.Log{
			Address:     common.HexToAddress(log.Address),
			Topics:      topics,
			Data:        common.FromHex(log.Data),
			BlockNumber: uint64(log.BlockNumber),
			TxHash:      common.HexToHash(log.TransactionHash),
			TxIndex:     uint(log.TransactionIndex),
			BlockHash:   common.HexToHash(log.BlockHash),
			Index:       uint(log.LogIndex),
			Removed:     log.Removed,
		}
	}

	return result, nil
}

func (rpc *EthRPC) SubscribeFilterLogs(ctx context.Context, q ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error) {
	// 注意：这个实现是一个简化版本，因为当前的RPC客户端不支持WebSocket订阅
	// 在实际应用中，你可能需要使用WebSocket连接来实现真正的订阅功能
	return nil, fmt.Errorf("subscription not supported in HTTP RPC client, use WebSocket client instead")
}

// Eth1 returns 1 ethereum value (10^18 wei)
func (rpc *EthRPC) Eth1() *big.Int {
	return Eth1()
}

// Eth1 returns 1 ethereum value (10^18 wei)
func Eth1() *big.Int {
	return big.NewInt(1000000000000000000)
}
