# go-kms-hdwallet-example

> Example how to use AWS KMS to store entropy and sign messages using an ethereum HD wallet.

## Example

```bash
go run main.go
```

The example does the following

1. Authenticate with AWS.
2. Create a KMS key if there are none.
3. Generate random 256 bit entropy.
4. Encrypt entropy with KMS.
5. Decrypt the encrypted entropy with KMS.
6. Generate mnemonic based on decrypted entropy.
7. Create an HD wallet from the mnemonic.
8. Derive an account from HD wallet the given an HD path.
9. Sign a message with the derived account private key.
10. Print all the steps.

## License

[MIT](LICENSE)
