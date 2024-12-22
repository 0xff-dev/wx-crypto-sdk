package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"log"
	mr "math/rand"
	"os"
	"sort"
	"strings"
)

const (
	asciiLetters               = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits                     = "0123456789"
	AES_TEXT_RESPONSE_TEMPLATE = `<xml>
<Encrypt><![CDATA[%s]]></Encrypt>
<MsgSignature><![CDATA[%s]]></MsgSignature>
<TimeStamp>%s</TimeStamp>
<Nonce><![CDATA[%s]]></Nonce>
</xml>`
)

type EncryptedData struct {
	XMLName xml.Name `xml:"xml"`
	AppId   string   `xml:"AppId"`
	Encrypt string   `xml:"Encrypt"`
}

type WXMsgCrypt struct {
	key []byte

	token, appid string
	letters      string
}

func (w *WXMsgCrypt) rand16bytes() string {
	l := len(w.letters)
	bs := make([]byte, 16)
	for i := range 16 {
		bs[i] = w.letters[mr.Intn(l)]
	}
	return string(bs)
}

func (w *WXMsgCrypt) sha1(timestamp, nonce, encrypt string) (string, error) {
	list := []string{w.token, timestamp, nonce, encrypt}
	sort.Strings(list)
	str := strings.Join(list, "")
	sha := sha1.New()
	_, err := sha.Write([]byte(str))
	if err != nil {
		log.Printf("[sha1] failed wirte str: %s, error %s", str, err)
		return "", WXBizMsgCrypt_ComputeSignature_Error
	}
	return fmt.Sprintf("%x", sha.Sum(nil)), WXBizMsgCrypt_OK
}

func (w *WXMsgCrypt) prpEncrypt(text string) (string, error) {
	length := uint32(len(text))
	buf := make([]byte, 4)

	binary.BigEndian.PutUint32(buf, length)
	randStr := w.rand16bytes()
	if os.Getenv("TEST_WX_CRYPTO") == "true" {
		//when you test the code, please fixed the random prefix
		randStr = "abcdabcdabcdabcd"
	}
	newText := randStr + string(buf) + text + w.appid

	block, err := aes.NewCipher(w.key)
	if err != nil {
		log.Printf("[prpEncrypt] fail newcipher, error %s", err)
		return "", WXBizMsgCrypt_DecryptAES_Error
	}
	paddingText := w.PKCS7Padding([]byte(newText), block.BlockSize())
	ciphertext := make([]byte, len(paddingText))
	mode := cipher.NewCBCEncrypter(block, w.key[:16])
	mode.CryptBlocks(ciphertext, paddingText)
	return base64.StdEncoding.EncodeToString(ciphertext), WXBizMsgCrypt_OK
}

func (w *WXMsgCrypt) prpDecrypt(b64EncrypedText string) (string, error) {
	block, err := aes.NewCipher(w.key)
	if err != nil {
		log.Printf("[prpDecrypt] fail newcipher, error %s", err)
		return "", WXBizMsgCrypt_DecryptAES_Error
	}

	encrypted, err := base64.StdEncoding.DecodeString(b64EncrypedText)
	if err != nil {
		log.Printf("[prpDecrypt] failed to do base64 decode error %s", err)
		return "", WXBizMsgCrypt_DecodeBase64_Error
	}

	if len(encrypted)%block.BlockSize() != 0 {
		return "", fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(encrypted))
	mode := cipher.NewCBCDecrypter(block, w.key[:16])
	mode.CryptBlocks(plaintext, encrypted)

	l := len(plaintext)
	pad := int(plaintext[l-1])
	content := plaintext[16 : l-pad]
	network := binary.LittleEndian.Uint32(content[:4])
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, network)
	xmlLen := binary.LittleEndian.Uint32(data)
	xmlContent := content[4 : xmlLen+4]
	fromAppID := content[xmlLen+4:]
	if string(fromAppID) != w.appid {
		return "", WXBizMsgCrypt_ValidateAppid_Error
	}
	return string(xmlContent), WXBizMsgCrypt_OK
}

func (w *WXMsgCrypt) EncryptMsg(replayMsg, nonce, timestamp string) (string, string, error) {
	ret, err := w.prpEncrypt(replayMsg)
	if err != nil {
		return "", "", err
	}

	sig, err := w.sha1(timestamp, nonce, ret)
	if err != nil {
		return "", "", err
	}

	return fmt.Sprintf(AES_TEXT_RESPONSE_TEMPLATE, ret, sig, timestamp, nonce), sig, WXBizMsgCrypt_OK
}

func (w *WXMsgCrypt) DecryptMsg(postData, msgSignature, timestamp, nonce string) (string, error) {
	var encryped EncryptedData
	if err := xml.Unmarshal([]byte(postData), &encryped); err != nil {
		return "", WXBizMsgCrypt_ParseXml_Error
	}
	signature, err := w.sha1(timestamp, nonce, encryped.Encrypt)
	if err != nil {
		return "", err
	}
	if signature != msgSignature {
		log.Printf("[DecryptMsg] mismatch signature calculated: %s, expect %s", signature, msgSignature)
		return "", WXBizMsgCrypt_ValidateSignature_Error
	}

	return w.prpDecrypt(encryped.Encrypt)
}

// blockSize is 32
// PKCS7Padding adds padding to the plaintext
func (w *WXMsgCrypt) PKCS7Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

// PKCS7UnPadding removes padding from the plaintext
func (w *WXMsgCrypt) PKCS7UnPadding(plaintext []byte) []byte {
	length := len(plaintext)
	unpadding := int(plaintext[length-1])
	return plaintext[:(length - unpadding)]
}

func NewWxCrypt(key, token, appid string) (*WXMsgCrypt, error) {
	k, err := base64.StdEncoding.DecodeString(key + "=")
	if err != nil {
		return nil, WXBizMsgCrypt_DecodeBase64_Error
	}
	return &WXMsgCrypt{
		key:     []byte(k),
		token:   token,
		appid:   appid,
		letters: asciiLetters + digits,
	}, nil
}
