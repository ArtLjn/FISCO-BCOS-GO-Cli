/*
@Time : 2024/6/12 下午7:22
@Author : ljn
@File : template
@Software: GoLand
*/

package cmd

import (
	"fisco-golang-cli/utils"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"strings"
)

var currentPath string

var apiTemplateCmd = &cobra.Command{
	Use:   "api",
	Short: "generate directory structure",
	Long:  "generate directory structure",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("please input directory name")
			return
		}
		currentPath = args[0]
		createPath(currentPath, filepath.Join(currentPath, "router"),
			filepath.Join(currentPath, "conf"), filepath.Join(currentPath, "internal"),
			filepath.Join(currentPath, "internal", "model"),
			filepath.Join(currentPath, "internal", "service"),
			filepath.Join(currentPath, "internal", "data"),
			filepath.Join(currentPath, "internal", "response"),
			filepath.Join(currentPath, "util"))
		utils.WriteToFile(filepath.Join(currentPath, "router", "router.go"), strings.Replace(router, "{{.Appname}}", currentPath, -1))
		utils.WriteToFile(filepath.Join(currentPath, "util", "writeRequest.go"), writeReqTem)
		utils.WriteToFile(filepath.Join(currentPath, "conf", "conf.go"), strings.Replace(confTem, "{{.Appname}}", currentPath, -1))
		utils.WriteToFile(filepath.Join(currentPath, "conf", "conf.json"), confJson)
		utils.WriteToFile(filepath.Join(currentPath, "internal", "data", "data.go"), strings.Replace(dataTemplate, "{{.Appname}}", currentPath, -1))
		utils.WriteToFile(filepath.Join(currentPath, "main.go"), strings.Replace(mainTemplate, "{{.Appname}}", currentPath, -1))
		utils.WriteToFile(filepath.Join(currentPath, "internal", "data", "account.go"), strings.Replace(accountDataTem, "{{.Appname}}", currentPath, -1))
		utils.WriteToFile(filepath.Join(currentPath, "internal", "response", "response.go"), responseTem)
		utils.WriteToFile(filepath.Join(currentPath, "internal", "model", "Account.go"), AccountModel)
		utils.WriteToFile(filepath.Join(currentPath, "internal", "service", "account.go"), strings.Replace(accountServiceTem, "{{.Appname}}", currentPath, -1))
		utils.WriteToFile(filepath.Join(currentPath, "go.mod"), strings.Replace(goMod, "{{.Appname}}", currentPath, -1))
		fmt.Println("Build successfully Run \"go mod tidy\" To make sure the program is allowed properly")
	},
}

func createPath(path ...string) {
	for _, v := range path {
		// 创建目录
		if err := os.MkdirAll(v, os.ModePerm); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}
}

var router = `package router

import (
	"github.com/gin-gonic/gin"
	"{{.Appname}}/internal/service"
)

func InitRouter(r *gin.Engine, accountService *service.AccountService) {
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"msg": "hello world",
		})
	})
	group := r.Group("/api")
	accGroup := group.Group("/account")
	{
		accGroup.POST("/login", accountService.Login)
	}
}
`

var writeReqTem = `package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/thedevsaddam/gojsonq"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

type CommonRequest struct {
	User            string 
	ContractName    string 
	ContractAddress string 
	Abi             string 
	Url             string 
	ParsePut        string 
}

func (c *CommonRequest) CommonEq(funcName string, funcParam []interface{}) string {
	requestData := map[string]interface{}{
		"user":            c.User,
		"contractName":    c.ContractName,
		"contractAddress": c.ContractAddress,
		"funcName":        funcName,
		"contractAbi":     json.RawMessage(c.Abi),
		"funcParam":       funcParam,
		"groupId":         1,
		"useCns":          false,
		"useAes":          false,
		"cnsName":         c.ContractName,
		"version":         "",
	}
	requestDataBytes, _ := json.Marshal(requestData)
	req, err := http.NewRequest(http.MethodPost, c.Url, bytes.NewBuffer(requestDataBytes))
	if err != nil {
		fmt.Println("创建HTTP请求错误:", err)
		return ""
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("发送HTTP请求错误:", err)
		return ""
	}
	defer func(Body io.ReadCloser) {
		err = Body.Close()
		if err != nil {
			fmt.Println("关闭响应主体错")
		}
	}(resp.Body)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应主体错误:", err)
		return ""
	}
	return string(body)
}

func (c *CommonRequest) ParsePutResult(body, funcName string) (interface{}, error) {
	requestData := map[string]interface{}{
		"abiList":    json.RawMessage(c.Abi),
		"methodName": funcName,
		// decodeType为1表示解析input输入的参数，为2表示解析output输出的参数
		"decodeType": 2,
		"output":     gojsonq.New().JSONString(body).Find("output"),
	}
	requestDataBytes, _ := json.Marshal(requestData)
	req, err := http.NewRequest(http.MethodPost, c.ParsePut, bytes.NewBuffer(requestDataBytes))
	if err != nil {
		fmt.Println("创建HTTP请求错误:", err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("发送HTTP请求错误:", err)
		return nil, err
	}
	defer resp.Body.Close()
	d, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应主体错误:", err)
	}
	var data map[string]interface{}
	err = json.Unmarshal(d, &data)
	if err != nil {
		fmt.Println("json解析错误:", err)
	}
	var result interface{}
	for k, _ := range data {
		if len(k) != 0 {
			result = k[1 : len(k)-1]
		}
	}
	if result == nil {
		return nil, err
	}
	return result, nil
}

func (c *CommonRequest) IsSuccess(body string) bool {
	data := gojsonq.New().JSONString(body)
	val := data.Find("message")
	if val == "Success" {
		return true
	}
	log.Println(data.Find("errorMessage"))
	return false
}
`

var confTem = `
package conf

import "{{.Appname}}/util"

type Conf struct {
	Server struct {
		Host string 
		Port string 
	} 
	CommonRequest util.CommonRequest 
	Database      struct {
		Host     string 
		Port     string 
		User     string 
		Password string 
		DbName   string 
	} 

	Redis struct {
		Addr     string 
		Password string 
		Db       int    
	} 
}
`

var confJson = `{
  "server": {
    "host": "127.0.0.1",
    "port": "8080"
  },
  "commonRequest": {
    "user": "0x29e2db8ad37fb85a2466db8517d380dc98c2d51c",
    "contractName": "Heritage",
    "contractAddress": "0x15550d1b05605ee6091c4341f9bac54447b96180",
    "contractAbi":"[]",
    "url": "http://localhost:5002/WeBASE-Front/trans/handle",
    "parsePut": "http://127.0.0.1:5002/WeBASE-Front/tool/decode"
  },
  "database": {
    "host": "localhost",
    "port": "3306",
    "user": "root",
    "password": "123456",
    "dbName": "dbname"
  },
  "redis": {
    "addr": "127.0.0.1:6379",
    "password":"",
    "db": 0
  }
}`

var dataTemplate = `package data

import (
	"fmt"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"{{.Appname}}/conf"
)

type Data struct {
	c   *conf.Conf
	db  *gorm.DB
	rdb *redis.Client
}

func NewData(c *conf.Conf) *Data {
	return &Data{
		c:   c,
		//db:  NewDB(c),
		//rdb: NewRDB(c),
	}
}

func NewDB(conf *conf.Conf) *gorm.DB {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local", conf.Database.User, conf.Database.Password, conf.Database.Host, conf.Database.Port, conf.Database.DbName)
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		panic("failed to connect database")
	}
	return db
}

func NewRDB(conf *conf.Conf) *redis.Client {
	return redis.NewClient(
		&redis.Options{
			Addr:     conf.Redis.Addr,
			DB:       conf.Redis.Db,
			Password: conf.Redis.Password,
		},
	)
}

`
var mainTemplate = `package main

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"log"
	"{{.Appname}}/conf"
	"{{.Appname}}/internal/data"
	"{{.Appname}}/internal/service"
	"{{.Appname}}/router"
)

func main() {
	r := gin.Default()
	var c conf.Conf
	wireApp(&c, r)

	err := r.Run(":8080")
	if err != nil {
		panic(err)
	}
}

func wireApp(c *conf.Conf, r *gin.Engine) {
	file, err := ioutil.ReadFile("conf/conf.json")
	if err != nil {
		log.Fatal(err)
	}
	if err = json.Unmarshal(file, &c); err != nil {
		return
	}
	dataData := data.NewData(c)
	accountRepo := data.NewAccountRepo(dataData)
	accountService := service.NewAccountService(accountRepo)
	router.InitRouter(r, accountService)
}`

var accountDataTem = `package data

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"log"
	"{{.Appname}}/internal/model"
	"{{.Appname}}/internal/service"
)

type accountRepo struct {
	data *Data
}

func NewAccountRepo(data *Data) service.AccountRepo {
	return &accountRepo{data: data}
}

func (a accountRepo) Login(login model.AccountLogin) (data []interface{}, err error) {
	// TODO
	return nil, fmt.Errorf("success")
}

func GenerateAccount() map[string]string {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	privateKeyBytes := crypto.FromECDSA(privateKey)

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	_ = crypto.FromECDSAPub(publicKeyECDSA)

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	data := map[string]string{
		"address":    address,
		"privateKey": hexutil.Encode(privateKeyBytes)[2:],
	}
	return data
}
`
var AccountModel = `package model

type AccountLogin struct {
	Address  string 
	Password string 
}
`
var responseTem = `package response

import "github.com/gin-gonic/gin"

type BuildResponse interface {
	SetCode(code int) BuildResponse
	SetMsg(msg string) BuildResponse
	SetData(data ...interface{}) BuildResponse
	Build(ctx *gin.Context)
}

type ResponseBuild struct {
	code int
	msg  string
	data []interface{}
}

func NewResponseBuild() ResponseBuild {
	return ResponseBuild{}
}
func (r *ResponseBuild) SetCode(code int) BuildResponse {
	r.code = code
	return r
}

func (r *ResponseBuild) SetMsg(msg string) BuildResponse {
	r.msg = msg
	return r
}

func (r *ResponseBuild) SetData(data ...interface{}) BuildResponse {
	r.data = data
	return r
}

func (r *ResponseBuild) Build(ctx *gin.Context) {
	ctx.JSON(r.code, gin.H{"code": r.code, "msg": r.msg, "data": r.data})
}

func (r *ResponseBuild) NewBuildJsonError(ctx *gin.Context) {
	r.SetCode(400).SetMsg("json error").SetData(nil).Build(ctx)
}

func (r *ResponseBuild) NewBuildSuccess(ctx *gin.Context) {
	r.SetCode(200).SetMsg("success").SetData(nil).Build(ctx)
}
`

var accountServiceTem = `package service

import (
	"github.com/gin-gonic/gin"
	"{{.Appname}}/internal/model"
	"{{.Appname}}/internal/response"
)

type AccountRepo interface {
	Login(login model.AccountLogin) (data []interface{}, err error)
}

type AccountService struct {
	repo AccountRepo
	r    response.ResponseBuild
}

func NewAccountService(repo AccountRepo) *AccountService {
	return &AccountService{repo: repo}
}
func (a *AccountService) Login(ctx *gin.Context) {
	a.r = response.NewResponseBuild()
	acc := model.AccountLogin{}
	if err := ctx.ShouldBind(&acc); err != nil {
		a.r.NewBuildJsonError(ctx)
		return
	}
	data, err := a.repo.Login(acc)
	if err != nil {
		a.r.SetCode(400).SetMsg("登录失败").SetData(nil).Build(ctx)
		return
	}
	a.r.SetCode(200).SetMsg("success").SetData(data).Build(ctx)
	return
}
`
var goMod = `module {{.Appname}}

go 1.22

require (
	github.com/ethereum/go-ethereum v1.14.5
	github.com/gin-gonic/gin v1.10.0
	github.com/redis/go-redis/v9 v9.5.3
	github.com/thedevsaddam/gojsonq v2.3.0+incompatible
	gorm.io/driver/mysql v1.5.7
	gorm.io/gorm v1.25.10
)

require (
	github.com/btcsuite/btcd/btcec/v2 v2.2.0 // indirect
	github.com/bytedance/sonic v1.11.6 // indirect
	github.com/bytedance/sonic/loader v0.1.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudwego/base64x v0.1.4 // indirect
	github.com/cloudwego/iasm v0.2.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/gabriel-vasile/mimetype v1.4.3 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.20.0 // indirect
	github.com/go-sql-driver/mysql v1.7.0 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/holiman/uint256 v1.2.4 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.2.7 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pelletier/go-toml/v2 v2.2.2 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.2.12 // indirect
	golang.org/x/arch v0.8.0 // indirect
	golang.org/x/crypto v0.23.0 // indirect
	golang.org/x/net v0.25.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
	golang.org/x/text v0.15.0 // indirect
	google.golang.org/protobuf v1.34.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
`
