package crypt

import (
	"testing"
)

func TestOfficialExample(t *testing.T) {
	aesKey := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	toXml := ` <xml><ToUserName><![CDATA[oia2TjjewbmiOUlr6X-1crbLOvLw]]></ToUserName><FromUserName><![CDATA[gh_7f083739789a]]></FromUserName><CreateTime>1407743423</CreateTime><MsgType>  <![CDATA[video]]></MsgType><Video><MediaId><![CDATA[eYJ1MbwPRJtOvIEabaxHs7TX2D-HV71s79GUxqdUkjm6Gs2Ed1KF3ulAOA9H1xG0]]></MediaId><Title><![CDATA[testCallBackReplyVideo]]></Title><Descript  ion><![CDATA[testCallBackReplyVideo]]></Description></Video></xml>`
	token := "spamtest"

	timestamp := "1734596597"
	nonce := "1320562132"
	appid := "wx2c2769f8efd9abc2"
	exp := `<xml>
<Encrypt><![CDATA[LtpU/O8r0TJyCZZMp5EStFYznG4Z/5jhAg52xVFLqf8MxTZ/Wr7ZmpsyAQUUQOV4uXNQG2ME7fJixR8oTABSk5/nAUGanTgnWkwyJiviHw7kEqeaFUcMRAoPm5oPHkFSL2dju7IgOjc34fj29tbnE2ulsuq6rWPBHp6n0WdLJjGq5KRPQcYBN+gI+qtfKUKm1TBS6pm7+fprDOvzihVOJ+U2QUqM5/rk6IR5wewCHqp2auCNkuKzZ+l18JfmPjILeqjL7cJmQ9pSzSnv1dPkJP7hvaT0hVuAfTF+cc7kxz0f2EAvqjwZ8sRuxv5D07QDbVPWOsZq97vDYU/O637ewnHEpSQaPcTnlRoKiAPL8rerV+9jRW1CmY7dRi6ET2olvwnO1SOXVuRx4BIJOShbWldDKm3KtXi6+SFFeF/3aw0MHLDD1mBVpbu/Z7W6ni0eUNx94wtU82Um1IGpngOMWK0u1S5UW3v25xiizXYbKebBgTJ/WfXrWy+uXQUMlL3P6DTl1FhgC7IDeSpk9U32TSysWWgfiWrb9ppkGIsjoOcEe0yYrfZaAEdp0gwjZAjAYDAiSvN7H/cGmlE/aOcHvzF91/OeEVMjgpFUUgRQzPUjtbIpiVGoQ6Yv2ETGBv8O]]></Encrypt>
<MsgSignature><![CDATA[793f867b5e38770bafff6e4481040f0028ce1e9c]]></MsgSignature>
<TimeStamp>1734596597</TimeStamp>
<Nonce><![CDATA[1320562132]]></Nonce>
</xml>`
	wx, _ := NewWxCrypt(aesKey, token, appid)
	encryptRes, _, err := wx.EncryptMsg(toXml, nonce, timestamp)
	if err != nil {
		t.Fatalf("faield to enrypt msg: %s", err)
	}
	if encryptRes != exp {
		t.Fatalf("encrypt expect xml %s, got %s", exp, encryptRes)
	}

	timestamp = "1409735669"
	msg_sign := "5d197aaffba7e9b25a30732f161a50dee96bd5fa"
	fromXML := `<xml><ToUserName><![CDATA[gh_10f6c3c3ac5a]]></ToUserName><FromUserName><![CDATA[oyORnuP8q7ou2gfYjqLzSIWZf0rs]]></FromUserName><CreateTime>1409735668</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[abcdteT]]></Content><MsgId>6054768590064713728</MsgId><Encrypt><![CDATA[hyzAe4OzmOMbd6TvGdIOO6uBmdJoD0Fk53REIHvxYtJlE2B655HuD0m8KUePWB3+LrPXo87wzQ1QLvbeUgmBM4x6F8PGHQHFVAFmOD2LdJF9FrXpbUAh0B5GIItb52sn896wVsMSHGuPE328HnRGBcrS7C41IzDWyWNlZkyyXwon8T332jisa+h6tEDYsVticbSnyU8dKOIbgU6ux5VTjg3yt+WGzjlpKn6NPhRjpA912xMezR4kw6KWwMrCVKSVCZciVGCgavjIQ6X8tCOp3yZbGpy0VxpAe+77TszTfRd5RJSVO/HTnifJpXgCSUdUue1v6h0EIBYYI1BD1DlD+C0CR8e6OewpusjZ4uBl9FyJvnhvQl+q5rv1ixrcpCumEPo5MJSgM9ehVsNPfUM669WuMyVWQLCzpu9GhglF2PE=]]></Encrypt></xml>`
	exp = `<xml><ToUserName><![CDATA[gh_10f6c3c3ac5a]]></ToUserName>
<FromUserName><![CDATA[oyORnuP8q7ou2gfYjqLzSIWZf0rs]]></FromUserName>
<CreateTime>1409735668</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[abcdteT]]></Content>
<MsgId>6054768590064713728</MsgId>
</xml>`

	retXml, err := wx.DecryptMsg(fromXML, msg_sign, timestamp, nonce)
	if err != nil {
		t.Fatalf("failed to decrypt msg: %s", err)
	}
	if retXml != exp {
		t.Fatalf("expect decrypt xml %s, got %s", exp, retXml)
	}
}
