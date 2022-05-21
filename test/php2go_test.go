package test

import (
	"github.com/cexll/php2go"
	"log"
	"testing"
)

type JsonOptions struct {
	Data    any    `json:"data"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func TestPhp2Go(t *testing.T) {
	path := php2go.GetEnv("PATH")
	log.Println(path)
	dir, _ := php2go.ScanDir(".")
	log.Println(dir)

	log.Println(php2go.MbStrPos("12345abc123456", "ab"))

	log.Println(php2go.DirName("."))

	hash, _ := php2go.PasswordHash("123456")
	log.Println(hash)
	log.Println(php2go.PasswordVerify("123456", hash))

	json, _ := php2go.JsonEncode(JsonOptions{
		Data:    "123",
		Code:    100,
		Message: "hello",
	})
	log.Println(json)
	option, _ := php2go.JsonDecode(json)
	log.Println(option)

	log.Println(php2go.NumberFormat(1234.56, 2, ",", " "))

	log.Println(php2go.MicroTime())

	log.Println(php2go.System("ls ."))

	log.Println(php2go.Uniqid("kd"))

	log.Println(php2go.IsNumeric("100ac"))

	b64enc := php2go.Base64Encode("123456")
	log.Println(b64enc)
	d, _ := php2go.Base64Decode(b64enc)
	log.Println(d)

	log.Println(php2go.Rand(100, 200))

	php2go.TimeNanoSleep(1)
	log.Println("halo")

	log.Println(php2go.StrReplace("cexll", "imorta", "https://cexll.cn"))

	log.Println(php2go.Date(""))

	log.Println(php2go.Time())

	log.Println(php2go.StrToTime("2022-05-21 15:46:10"))

	log.Println(php2go.Explode("a b c d e f g h", " "))

	arr := make([]string, 0)
	arr = append(arr, "10")
	arr = append(arr, "9")
	arr = append(arr, "8")
	arr = append(arr, "7")
	log.Println(php2go.Implode(" ", arr))

	php2go.VarDump("123123123123")

	log.Println(php2go.Md5("123123123"))

	php2go.Echo("asddd")
}
