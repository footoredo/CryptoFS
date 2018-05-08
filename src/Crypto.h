#ifndef CRYPTOFS_CRYPTO_H
#define CRYPTOFS_CRYPTO_H

#include <iostream>
#include <string>

namespace Crypto {
  struct Keys {
    byte symmetricKey [];
    byte publicKey [];
    byte privateKey [];
  };

  struct CryptoMethods {
    int (*symmetricEncrypt) (const byte *, const byte *, byte *); // plainText, key, cipherText
    int (*symmetricDecrypt) (const byte *, const byte *, byte *); // cipherText, key, plainText
  };

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
