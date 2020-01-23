package main

import (
	"fmt"
	"log"

	aws "github.com/aws/aws-sdk-go/aws"
	awsSession "github.com/aws/aws-sdk-go/aws/session"
	awsKms "github.com/aws/aws-sdk-go/service/kms"
	"github.com/ethereum/go-ethereum/crypto"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
)

func main() {
	// Authenticate with AWS
	sess, err := awsSession.NewSessionWithOptions(awsSession.Options{
		SharedConfigState: awsSession.SharedConfigEnable,
	})
	if err != nil {
		panic(err)
	}

	kms := awsKms.New(sess, aws.NewConfig().WithRegion("us-east-1"))

	listOutput, err := kms.ListKeys(&awsKms.ListKeysInput{})
	if err != nil {
		panic(err)
	}

	// Create KMS key if none
	if len(listOutput.Keys) == 0 {
		_, err := kms.CreateKey(&awsKms.CreateKeyInput{})
		if err != nil {
			panic(err)
		}
	}

	listOutput, err = kms.ListKeys(&awsKms.ListKeysInput{})
	if err != nil {
		panic(err)
	}

	// Generate random entropy
	entropy, err := hdwallet.NewEntropy(256)
	if err != nil {
		panic(err)
	}

	// You would encrypt this once in practice
	keyID := listOutput.Keys[len(listOutput.Keys)-1].KeyId
	encryptOutput, err := kms.Encrypt(&awsKms.EncryptInput{
		KeyId:     keyID,
		Plaintext: entropy,
	})
	if err != nil {
		panic(err)
	}

	// You would fetch this from the database in practice
	encrypted := encryptOutput.CiphertextBlob
	decryptOutput, err := kms.Decrypt(&awsKms.DecryptInput{
		KeyId:          keyID,
		CiphertextBlob: encrypted,
	})
	if err != nil {
		panic(err)
	}

	// This is user defined path
	hdPath := "m/44'/60'/0'/0/0"

	decrypted := decryptOutput.Plaintext
	mnemonic, err := hdwallet.NewMnemonicFromEntropy(decrypted)
	if err != nil {
		panic(err)
	}

	wallet, err := hdwallet.NewFromMnemonic(mnemonic)
	if err != nil {
		log.Fatal(err)
	}

	path := hdwallet.MustParseDerivationPath(hdPath)
	account, err := wallet.Derive(path, true)
	if err != nil {
		log.Fatal(err)
	}

	// This is user defined message
	message := "hello world"

	// Sign message
	hash := crypto.Keccak256Hash([]byte(message))
	signature, err := wallet.SignHash(account, hash.Bytes())
	if err != nil {
		panic(err)
	}

	fmt.Printf("entropy: %x\n", string(entropy))
	fmt.Printf("mnemonic: %s\n", mnemonic)
	fmt.Printf("hdpath: %s\n", hdPath)
	fmt.Printf("account: 0x%s\n", account.Address.Hex())
	fmt.Printf("message: %s\n", message)
	fmt.Printf("signature: 0x%x\n", signature)
}
