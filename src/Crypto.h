#ifndef CRYPTOFS_CRYPTO_H
#define CRYPTOFS_CRYPTO_H

#include <iostream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/sha.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

namespace Crypto {
    struct Keys {
        SecByteBlock symmetricKey;
        SecByteBlock IV;
        SecByteBlock publicKey;
        SecByteBlock privateKey;
    };

    struct Methods {
        void (*symmetricEncrypt) (const byte *, int, SecByteBlock, SecByteBlock, byte *); // plainText, key, IV, cipherText
        void (*symmetricDecrypt) (const byte *, int, SecByteBlock, SecByteBlock, byte *); // cipherText, key, IV, plainText
        void (*hashsum) (const byte *, int, byte *);
    };

    struct Configs {
        int symmetricKeyLength;
        int symmetricBlockLength;
        int hashDigestLength;
        int publicKeyLength;
        int privateKeyLength;
    };

    static void AESEncrypt(const byte *input, int len, SecByteBlock key, SecByteBlock iv, byte *output) {
        CFB_Mode<AES>::Encryption cfbEncryption(key, key.size(), iv);
        cfbEncryption.ProcessData(output, input, len);
    }

    static void AESDecrypt(const byte *input, int len, SecByteBlock key, SecByteBlock iv, byte *output) {
        CFB_Mode<AES>::Decryption cfbDecryption(key, key.size(), iv);
        cfbDecryption.ProcessData(output, input, len);
    }

    static void SHA256Hash(const byte *input, int len, byte *output) {
        SHA256().CalculateDigest(output, input, len);
    }

    static std::string byteToHex (const byte *input, int len) {
        HexEncoder encoder(NULL, false);
        std::string output;

        encoder.Attach( new StringSink (output) );
        encoder.Put(input, len);
        encoder.MessageEnd();

        return output;
    }

    SecByteBlock generateKey(int keyLen) {
        AutoSeededRandomPool rnd;
        SecByteBlock key(0x00, keyLen);
        rnd.GenerateBlock (key, key.size());
        return key;
    }

    class Crypto {
    public:
        Crypto (Configs configs, Methods methods): configs(configs), methods(methods) {}
        Crypto () {
            configs.symmetricKeyLength = AES::DEFAULT_KEYLENGTH;
            configs.symmetricBlockLength = AES::BLOCKSIZE;
            configs.hashDigestLength = SHA256::DIGESTSIZE;
            methods.symmetricEncrypt = AESEncrypt;
            methods.symmetricDecrypt = AESDecrypt;
            methods.hashsum = SHA256Hash;
        }

        void generateKeys () {
            keys.symmetricKey = generateKey (configs.symmetricKeyLength);
            keys.IV = generateKey (configs.symmetricBlockLength);
        }

        void encrypt(const byte *input, int len, byte *output) {
            methods.symmetricEncrypt(input, len, keys.symmetricKey, keys.IV, output);
        }

        void decrypt(const byte *input, int len, byte *output) {
            methods.symmetricDecrypt(input, len, keys.symmetricKey, keys.IV, output);
        }

        void hashsum(const byte *input, int len, byte *output) {
            methods.hashsum(input, len, output);
        }

        std::string hashsum(const byte *input, int len) {
            byte *digest = new byte [configs.hashDigestLength];
            hashsum(input, len, digest);
            std::string ret = byteToHex (digest, configs.hashDigestLength);
            delete [] digest;
            return ret;
        }
    private:
        Configs configs;
        Methods methods;
        Keys keys;
    };
}

#endif
