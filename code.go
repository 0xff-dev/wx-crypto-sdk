package crypt

import "errors"

var (
	WXBizMsgCrypt_OK                      error = nil
	WXBizMsgCrypt_ValidateSignature_Error       = errors.New("-40001 ValidateSignature Error")
	WXBizMsgCrypt_ParseXml_Error                = errors.New("-40002 ParseXml Error")
	WXBizMsgCrypt_ComputeSignature_Error        = errors.New("-40003 ComputeSignature Error")
	WXBizMsgCrypt_IllegalAesKey                 = errors.New("-40004 IllegalAesKey")
	WXBizMsgCrypt_ValidateAppid_Error           = errors.New("-40005 ValidateAppid Error")
	WXBizMsgCrypt_EncryptAES_Error              = errors.New("-40006 EncryptAES Error")
	WXBizMsgCrypt_DecryptAES_Error              = errors.New("-40007 DecryptAES Error")
	WXBizMsgCrypt_IllegalBuffer                 = errors.New("-40008 IllegalBuffer")
	WXBizMsgCrypt_EncodeBase64_Error            = errors.New("-40009 EncodeBase64 Error")
	WXBizMsgCrypt_DecodeBase64_Error            = errors.New("-40010 DecodeBase64 Error")
	WXBizMsgCrypt_GenReturnXml_Error            = errors.New("-40011 GenReturnXml Error")
)
