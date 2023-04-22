package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/types/tx"
	tmmath "github.com/tendermint/tendermint/libs/math"
	tmquery "github.com/tendermint/tendermint/libs/pubsub/query"
	ctypes "github.com/tendermint/tendermint/rpc/core/types"
	rpctypes "github.com/tendermint/tendermint/rpc/jsonrpc/types"

	"github.com/tendermint/tendermint/state/txindex/null"
	"github.com/tendermint/tendermint/types"
)

// add by seanxu
type IPAddressIsRestrictedCallbackFunc func(address string, ip string) bool

var IPAddressIsRestrictedCallback IPAddressIsRestrictedCallbackFunc

// Signature 和 PublicKey 使用二进制数字字符串， 以便与VUE客户端兼容
type TxSearchQuery struct {
	Query     string
	Address   string
	Signature string
	PublicKey string
}

func (txQuery TxSearchQuery) GetQuery() (string, error) {

	// var secp256k1PubKey secp256k1.PubKey

	publicKey, err := hex.DecodeString(txQuery.PublicKey)
	if err != nil {
		return "", err
	}

	signature, err := hex.DecodeString(txQuery.Signature)
	if err != nil {
		return "", err
	}
	// err = secp256k1PubKey.Unmarshal(publicKey)

	secp256k1PubKey := secp256k1.PubKey{
		Key: publicKey,
	}

	if err == nil {

		index := strings.Index(txQuery.Query, txQuery.Address)
		if index < 0 {

			// return "", fmt.Errorf("The query part needs to contain your wallet address")
		}
		// pubKey, _ := secp256k1PubKey..(cryptotypes.PubKey)
		// if pubKey != nil {
		ok := secp256k1PubKey.VerifySignature([]byte(txQuery.Address), signature)

		if ok {
			return txQuery.Query, nil
		} else {
			return "", fmt.Errorf("error Signature for query")
		}
		// }
	}

	return "", err

}

// Tx allows you to query the transaction results. `nil` could mean the
// transaction is in the mempool, invalidated, or was not sent in the first
// place.
// More: https://docs.tendermint.com/v0.34/rpc/#/Info/tx
func Tx(ctx *rpctypes.Context, hash []byte, prove bool) (*ctypes.ResultTx, error) {

	// return nil, fmt.Errorf("please use TxSearch interface")

	// if index is disabled, return error
	if _, ok := env.TxIndexer.(*null.TxIndex); ok {
		return nil, fmt.Errorf("transaction indexing is disabled")
	}

	r, err := env.TxIndexer.Get(hash, false)
	if err != nil {
		return nil, err
	}

	if r == nil {
		return nil, fmt.Errorf("tx (%X) not found", hash)
	}

	height := r.Height
	index := r.Index

	var proof types.TxProof
	if prove {
		block := env.BlockStore.LoadBlock(height, false)
		proof = block.Data.Txs.Proof(int(index)) // XXX: overflow on 32-bit machines
	}

	return &ctypes.ResultTx{
		Hash:     hash,
		Height:   height,
		Index:    index,
		TxResult: r.Result,
		Tx:       r.Tx,
		Proof:    proof,
	}, nil
}

// TxSearch allows you to query for multiple transactions results. It returns a
// list of transactions (maximum ?per_page entries) and the total count.
// More: https://docs.tendermint.com/v0.34/rpc/#/Info/tx_search
// modify by seanxu
// 隐私链，查询时需要对钱包地址进行签名
func TxSearch(
	ctx *rpctypes.Context,
	jsonQuery string,
	prove bool,
	pagePtr, perPagePtr *int,
	orderBy string,
) (*ctypes.ResultTxSearch, error) {

	authorized := false

	txSearchQuery_Address := ""

	query := jsonQuery

	if jsonQuery[0] == '{' {

		var txSearchQuery TxSearchQuery
		err := json.Unmarshal([]byte(jsonQuery), &txSearchQuery)
		if err != nil {
			return nil, errors.New("query need json format for Signature")
		}

		// 这里添加远程IP锁定策略
		remoteAddr := ""

		if ctx.HTTPReq != nil {
			remoteAddr = ctx.HTTPReq.RemoteAddr
			fmt.Printf("remoteAddr=%s\n", remoteAddr)
		}

		query, err = txSearchQuery.GetQuery()
		if err != nil {
			return nil, err
		}
		if query == "" {
			return nil, errors.New("error Signature for query")
		} else {
			authorized = true
		}

		if IPAddressIsRestrictedCallback != nil {
			if remoteAddr != "" && txSearchQuery.Address != "" {
				isRestricted := IPAddressIsRestrictedCallback(txSearchQuery.Address, remoteAddr)

				if isRestricted {
					return nil, errors.New("Your wallet cannot be accessed from multiple IP addresses at the same time, try later")
				}
			}
		}

		txSearchQuery_Address = txSearchQuery.Address

	}

	// if index is disabled, return error
	if _, ok := env.TxIndexer.(*null.TxIndex); ok {
		return nil, errors.New("transaction indexing is disabled")
	} else if len(query) > maxQueryLength {
		return nil, errors.New("maximum query length exceeded")
	}

	q, err := tmquery.New(query)
	if err != nil {
		return nil, err
	}

	results, err := env.TxIndexer.Search(ctx.Context(), q, authorized)
	if err != nil {
		return nil, err
	}

	// sort results (must be done before pagination)
	switch orderBy {
	case "desc":
		sort.Slice(results, func(i, j int) bool {
			if results[i].Height == results[j].Height {
				return results[i].Index > results[j].Index
			}
			return results[i].Height > results[j].Height
		})
	case "asc", "":
		sort.Slice(results, func(i, j int) bool {
			if results[i].Height == results[j].Height {
				return results[i].Index < results[j].Index
			}
			return results[i].Height < results[j].Height
		})
	default:
		return nil, errors.New("expected order_by to be either `asc` or `desc` or empty")
	}

	// paginate results
	totalCount := len(results)
	perPage := validatePerPage(perPagePtr)

	page, err := validatePage(pagePtr, perPage, totalCount)
	if err != nil {
		return nil, err
	}

	skipCount := validateSkipCount(page, perPage)
	pageSize := tmmath.MinInt(perPage, totalCount-skipCount)

	apiResults := make([]*ctypes.ResultTx, 0, pageSize)
	for i := skipCount; i < skipCount+pageSize; i++ {
		r := results[i]

		// add by seanxu. check the data include user's address
		// 确认Result 中是否包含对应的钱包地址， 如果没有，直接忽略。
		// 对于 tx.hash=‘*******’ 查询， 查询过程是忽略其他选项的， 故这里要进一步验证
		findAddress := true

		if authorized {
			findAddress = false
			for k := 0; k < len(r.Result.Events); k++ {
				for k1 := 0; k1 < len(r.Result.Events[k].Attributes); k1++ {
					if string(r.Result.Events[k].Attributes[k1].Value) == txSearchQuery_Address {
						findAddress = true
						break
					}
				}

				if findAddress {
					break
				}
			}
		}

		// timeStamp := int64(0)

		if findAddress {
			hash := types.Tx(r.Tx).Hash()
			var proof types.TxProof
			if prove || authorized {
				block := env.BlockStore.LoadBlock(r.Height, authorized)

				//添加时间戳
				timeStamp := block.Header.Time.Unix()
				r.Result.Info = fmt.Sprintf("{\"timeStamp\": %d}", timeStamp)

				if prove {
					proof = block.Data.Txs.Proof(int(r.Index)) // XXX: overflow on 32-bit machines
				}
			}

			if !authorized {
				var txData tx.Tx
				err := txData.Unmarshal(r.Tx)
				if err == nil {
					memo := txData.Body.Memo
					n1 := strings.Index(memo, "***")
					n2 := strings.LastIndex(memo, "***")
					end := len(memo) - 3
					// 检测到敏感词的格式为： ***XXXXXXXX***
					if n1 == 0 && n2 > n1 && n2 == end {
						//获取真实的 hash
						block := env.BlockStore.LoadBlock(r.Height, true)
						for n := 0; n < len(block.Data.Txs); n++ {

							var txData1 tx.Tx
							err := txData1.Unmarshal(block.Data.Txs[n])
							if err == nil {

								// 签名相等
								if len(txData1.Signatures) == len(txData.Signatures) && len(txData1.Signatures) > 0 {
									if bytes.Equal(txData1.Signatures[0], txData.Signatures[0]) {
										hash = types.Tx(block.Data.Txs[n]).Hash()
										break

									}

								}

							}

							// s := string(block.Data.Txs[n])
							// i := strings.Index(s, "/cosmos.bank.v1beta1.MsgSend")
							// if i > 0 {
							// 	hash = types.Tx(block.Data.Txs[n]).Hash()
							// 	break
							// }

						}

					}

				}

			}

			apiResults = append(apiResults, &ctypes.ResultTx{
				Hash:     hash,
				Height:   r.Height,
				Index:    r.Index,
				TxResult: r.Result,
				Tx:       r.Tx,
				Proof:    proof,
			})
		} else {
			totalCount--
		}

	}

	return &ctypes.ResultTxSearch{Txs: apiResults, TotalCount: totalCount}, nil
}
