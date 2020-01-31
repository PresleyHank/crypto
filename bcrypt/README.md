# Updated bcyrpt

## Introduction

I've updated bcyrpt so that it can be used with AES to encyrpt and decrypt data.
The key changes was to make the private function for bcrypt as a public function and create a new generate from password function that returns a Salt with the Hash.

GenerateFromPasswordReturnSalt is different from GenerateFromPassword in that it returns the true hash without the header and salt, the salt is returned from this function so that it can be stored when using it with AES.

## How to use with AES

I've include 2 functions below that I have used to encrypt and decrypt with bcrypt.

```
Import (
  	"crypto/aes"
	  "crypto/cipher"
    "github.com/jbramsden/crypto/bcrypt"
  )
```

```
//Encrypt - Takes data and a passphrase and returns an encrypted byte slice and salt.
func Encrypt(data []byte, passphrase string) (ciphertext []byte, s []byte, err error) {
	var h []byte

	if len(data)%aes.BlockSize != 0 {
		err = fmt.Errorf("data is not at the correct block size %d", aes.BlockSize)
	}

	h, s, err = bcrypt.GenerateFromPasswordReturnSalt([]byte(passphrase), bcrypt.DefaultCost)
	if err != nil {
		return
	}

	block, err := aes.NewCipher(h[:32])
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return
	}

	ciphertext = gcm.Seal(nonce, nonce, data, nil)
	return
}

//Decrypt - Takes encrypted data with a passphrase and salt, and decrypts it.
func Decrypt(data []byte, passphrase string, salt []byte) (plaintext []byte, err error) {
	var h []byte

	h, err = bcrypt.Bcrypt([]byte(passphrase), bcrypt.DefaultCost, salt)
	if err != nil {
		return
	}

	key := h
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		err = fmt.Errorf("Failed to generate new cipher with key beacuase %s:%v", err.Error(), key[:32])
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		err = fmt.Errorf("Failed to create new cipher block because %s", err.Error())
		return
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		err = fmt.Errorf("Failed to decrypt becuase %s", err.Error())
		return
	}
	return
}
```

## Test use for these functions

```
func TestDecrypt(t *testing.T) {
	hash, salt, err := Encrypt([]byte("Hello"), "Happy Times")
	if err != nil {
		t.Errorf("Failed to encrypt because %v", err)
	}
	txt, err := Decrypt(hash, "Happy Times", salt)
	if err != nil {
		t.Errorf("Failed to decrypt because %v", err)
	}
	if string(txt) != "Hello" {
		t.Errorf("Expected 'Hello' got '%s'", txt)
	}

}
```

To be able to use this with files the salt needs to be added to the begining or end of the file. Here is an example functions for writing to and reading from a file.

```
//WriteEncrypt - Use as a replacement for OS (*File) Write.
//				 Provide the filehandler from os.Create or os.NewFile or os.Open or OpenFile.
//				 And also the data as a byte slice with the passphrase to encyrpt the data
func WriteEncrypt(filehandler *os.File, data []byte, passphrase string) (n int, err error) {
	ct, s, err := Encrypt(data, passphrase)
	if err != nil {
		return
	}

	ct = append([]byte(ct), s...)
	n, err = filehandler.Write(ct)
	return
}

//DecryptFile - Provide a filename and a passphrase and this function will decrypt the file and return the data
func DecryptFile(filename string, passphrase string) (ue []byte, err error) {
	data, err := ioutil.ReadFile(filename)
	salt := data[len(data)-22:]
	data = data[:len(data)-22]
	if err != nil {
		return
	}
	ue, err = Decrypt(data, passphrase, salt)
	return
}
```


