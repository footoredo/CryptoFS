#ifndef CRYPTOFS_CRYPTO_H
#define CRYPTOFS_CRYPTO_H

#include <iostream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>

using namespace CryptoPP;

namespace Crypto {
  struct Keys {
    const byte *symmetricKey;
    const byte *publicKey;
    const byte *privateKey;
  };

  struct CryptoMethods {
    int (*symmetricEncrypt) (const byte *, int, const byte *, int, byte *); // plainText, key, cipherText
    int (*symmetricDecrypt) (const byte *, int, const byte *, int, byte *); // cipherText, key, plainText
  };

  static int AESEncrypt(const byte *input, int len, const byte *key, int keyLen, byte *output) {
      SecByteBlock aesKey(key, keyLen);
      SecByteBlock iv(AES::BLOCKSIZE);

      CFB_Mode<AES>::Encryption cfbEncryption(aesKey, aesKey.size(), iv);
      cfbEncryption.ProcessData(output, input, len);

      return 0;
  }

  static int AESDecrypt(const byte *input, int len, const byte *key, int keyLen, byte *output) {
      SecByteBlock aesKey(key, keyLen);
      SecByteBlock iv(AES::BLOCKSIZE);

      CFB_Mode<AES>::Decryption cfbDecryption(aesKey, aesKey.size(), iv);
      cfbDecryption.ProcessData(output, input, len);

      return 0;
  }

  struct CryptoConfigs {
    int symmetricKeyLength;
    int publicKeyLength;
    int privateKeyLength;
    CryptoMethods cryptoMethods;
  };

  class Crypto {
  public:
    Crypto (CryptoConfigs configs): configs(configs) {
    }
  private:
    CryptoConfigs configs;
    Keys keys;
  };
}

#endif
