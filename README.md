# simple go crypto framework

[![Go](https://github.com/dhcgn/crypto/actions/workflows/go.yml/badge.svg)](https://github.com/dhcgn/crypto/actions/workflows/go.yml)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=dhcgn_crypto&metric=security_rating)](https://sonarcloud.io/dashboard?id=dhcgn_crypto)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=dhcgn_crypto&metric=sqale_index)](https://sonarcloud.io/dashboard?id=dhcgn_crypto)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=dhcgn_crypto&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=dhcgn_crypto)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=dhcgn_crypto&metric=bugs)](https://sonarcloud.io/dashboard?id=dhcgn_crypto)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=dhcgn_crypto&metric=code_smells)](https://sonarcloud.io/dashboard?id=dhcgn_crypto)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=dhcgn_crypto&metric=coverage)](https://sonarcloud.io/dashboard?id=dhcgn_crypto)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=dhcgn_crypto&metric=ncloc)](https://sonarcloud.io/dashboard?id=dhcgn_crypto)

## Samples
### Simple Encryption

Uses AES-256-GCM (an authenticated encryption mode) to encrypt and decrypt data, password will be derived with PBKDF2 and 100.000 iterations. Because of this high iteration count the encryption and decryption process takes a minimum of around 200ms.

```go
cipherstring, err := simple.Encrypt("my secret password", []byte("my-secret-data"))

encrypted, err := simple.Decrypt("my secret password", "CSv1.443MMQSEWDPHEYKVS42FWJN633PS4EQIOFXDGMJOM2ON4ACJ.CIG44UL5BXWJU6JSW2BQ.KIORDLXAIJAT7NCTJHWYCE273Q")
```