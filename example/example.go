package main

import (
	"fmt"

	sdk "github.com/0xff-dev/wx-crypto-sdk"
)

func main() {
	key := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	token := "spamtest"
	appid := "wx2c2769f8efd9abc2"
	wx, err := sdk.NewWxCrypt(key, token, appid)
	if err != nil {
		panic(err)
	}

	timestamp := "1734596597"
	nonce := "1320562132"

	toXml := ` <xml><ToUserName><![CDATA[oia2TjjewbmiOUlr6X-1crbLOvLw]]></ToUserName><FromUserName><![CDATA[gh_7f083739789a]]></FromUserName><CreateTime>1407743423</CreateTime><MsgType>  <![CDATA[video]]></MsgType><Video><MediaId><![CDATA[eYJ1MbwPRJtOvIEabaxHs7TX2D-HV71s79GUxqdUkjm6Gs2Ed1KF3ulAOA9H1xG0]]></MediaId><Title><![CDATA[testCallBackReplyVideo]]></Title><Descript  ion><![CDATA[testCallBackReplyVideo]]></Description></Video></xml>`
	res, signature, err := wx.EncryptMsg(toXml, nonce, timestamp)
	if err != nil {
		panic(err)
	}
	fmt.Println("res: ", res)
	got, err := wx.DecryptMsg(res, signature, timestamp, nonce)
	if err != nil {
		panic(err)
	}
	if got != toXml {
		panic("the encrypted and decrypted contents are inconsistent")
	}
	fmt.Println("Done")
}
