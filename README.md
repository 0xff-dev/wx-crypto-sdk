# wx-crypto-sdk

WeChat third-party platform message encryption and decryption implementation


# Installation

```shell
go get github.com/0xff-dev/wx-crypto-sdk
```

# Run test case

Because the encrypted data has a randomly generated 16-bit string, the direct test will not pass, and the random string needs to be fixed through environment variables.

```
TEST_WX_CRYPTO=true go test -v .
```

# How to use it

[Example](./example/example.go)

# Contributing code

If you find any issues, please submit a Pull Request.
