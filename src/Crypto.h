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
#include <cctype>

using namespace CryptoPP;

namespace Crypto {

    static std::string byteToHex (const byte *input, int len) {
        HexEncoder encoder(NULL, false);
        std::string output;

        encoder.Attach( new StringSink (output) );
        encoder.Put(input, len);
        encoder.MessageEnd();

        return output;
    }

    static std::string byteToHex(SecByteBlock input) {
        return byteToHex(input.BytePtr(), input.size());
    }

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

        int getKeyFileLength() {
            return symmetricKeyLength + symmetricBlockLength/* + publicKeyLength + privateKeyLength*/;
        }
    };

    struct Keys {
        SecByteBlock symmetricKey;
        SecByteBlock IV;
        SecByteBlock publicKey;
        SecByteBlock privateKey;

        void init(const byte *buffer, Configs configs) {
            symmetricKey = SecByteBlock(buffer, configs.symmetricKeyLength);
            IV = SecByteBlock(buffer + configs.symmetricKeyLength, configs.symmetricBlockLength);
            // std::cout << byteToHex(buffer, configs.getKeyFileLength()) << std::endl;
        }

        void saveTo(byte *buffer) {
            memcpy(buffer, symmetricKey.BytePtr(), symmetricKey.size());
            memcpy(buffer + symmetricKey.size(), IV.BytePtr(), IV.size());
            // std::cout << byteToHex(buffer, symmetricKey.size() + IV.size()) << std::endl;
        }
    };

    static void AESEncrypt(const byte *input, int len, SecByteBlock key, SecByteBlock iv, byte *output) {
        CFB_Mode<AES>::Encryption cfbEncryption(key, key.size(), iv, 1);
        cfbEncryption.ProcessData(output, input, len);
        // std::cout << "        AES   Encrypt    " << byteToHex(key) << " " << byteToHex(iv) << " " << len << " " << byteToHex(output, len) << std::endl;
    }

    static void AESDecrypt(const byte *input, int len, SecByteBlock key, SecByteBlock iv, byte *output) {
        // std::cout << "        AES   Decrypt    " << byteToHex(key) << " " << byteToHex(iv) << " " << len << " " << byteToHex(input, len) << std::endl;
        CFB_Mode<AES>::Decryption cfbDecryption(key, key.size(), iv, 1);
        cfbDecryption.ProcessData(output, input, len);
        // std::cout << "        AES   Decrypt    " << byteToHex(key) << " " << byteToHex(iv) << " " << len << " " << byteToHex(output, len) << std::endl;
    }

    static void SHA256Hash(const byte *input, int len, byte *output) {
        SHA256().CalculateDigest(output, input, len);
    }

    SecByteBlock generateKey(int keyLen) {
        AutoSeededRandomPool rnd;
        SecByteBlock key(0x00, keyLen);
        rnd.GenerateBlock (key, key.size());
        return key;
    }

    class Crypto {
    public:
        // Crypto (Configs configs, Methods methods): configs(configs), methods(methods), machineIdentifier("") {}
        Crypto () {
            // std::cout << AES::DEFAULT_KEYLENGTH << " " << AES::BLOCKSIZE << " " << SHA256::DIGESTSIZE;
            configs.symmetricKeyLength = AES::DEFAULT_KEYLENGTH;
            configs.symmetricBlockLength = AES::BLOCKSIZE;
            configs.hashDigestLength = SHA256::DIGESTSIZE;
            methods.symmetricEncrypt = AESEncrypt;
            methods.symmetricDecrypt = AESDecrypt;
            methods.hashsum = SHA256Hash;
            machineIdentifier = "";
        }

        void generateKeys () {
            keys.symmetricKey = generateKey (configs.symmetricKeyLength);
            keys.IV = generateKey (configs.symmetricBlockLength);
        }

        void encrypt(const byte *input, int len, SecByteBlock key, SecByteBlock IV, byte *output) {
            methods.symmetricEncrypt(input, len, key, IV, output);
        }

        void encrypt(const byte *input, int len, byte *output) {
            encrypt(input, len, keys.symmetricKey, keys.IV, output);
        }

        void decrypt(const byte *input, int len, SecByteBlock key, SecByteBlock IV, byte *output) {
            methods.symmetricDecrypt(input, len, key, IV, output);
        }

        void decrypt(const byte *input, int len, byte *output) {
            decrypt(input, len, keys.symmetricKey, keys.IV, output);
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

        std::string hashsum(std::string input) {
            return hashsum((byte *)input.c_str(), input.length());
        }

        void loadKeys(std::string keysPath) {
            while (true) {
                std::cout << "Enter your passphrase: ";
                std::string passphrase;
                std::cin >> passphrase;

                int keyFileLength = configs.getKeyFileLength();
                byte *keysGroup = new byte[keyFileLength];
                if (loadKeyFile(keysPath, passphrase, keysGroup, keyFileLength)) {
                    std::cout << "keyFileLength: " << keyFileLength << std::endl;
                    // keys.symmetricKey = SecByteBlock(1);
                    keys.init(keysGroup, configs);
                    delete [] keysGroup;
                    break;
                }
                else {
                    std::cout << "Wrong passphrase!" << std::endl;
                }
            }
        }

        void saveKeys(std::string keysPath) {
            std::cout << "Enter your passphrase: ";
            std::string passphrase;
            std::cin >> passphrase;
            saveKeyFile(keysPath, passphrase);
        }

        void displayKeys() {
            std::cout << "symmetricKey: " << byteToHex(keys.symmetricKey) << std::endl;
            std::cout << "IV: " << byteToHex(keys.IV) << std::endl;
        }

    private:
        // ::Configs *globalConfigs;
        Configs configs;
        Methods methods;
        Keys keys;
        std::string machineIdentifier;

        bool loadKeyFile(std::string keyPath, std::string passphrase, byte *content, int maxLen) {
            std::string realContent = getMachineIdentifier() + ":" + passphrase;
            // std::cout << realContent << std::endl;

            byte *hash1 = new byte [configs.hashDigestLength];
            hashsum((byte *)(realContent.c_str()), realContent.length (), hash1);
            assert (configs.symmetricKeyLength + configs.symmetricBlockLength <= configs.hashDigestLength);
            SecByteBlock symmetricKey(hash1, configs.symmetricKeyLength);
            SecByteBlock IV(hash1 + configs.symmetricKeyLength, configs.symmetricBlockLength);

            std::string hash2 = hashsum(hash1, configs.hashDigestLength);
            delete [] hash1;
            std::string path = Util::combinePath(keyPath, hash2.substr(0, 2) + "/" + hash2.substr(2, 10) + ".key");

            std::cerr << "path: " + path << std::endl;

            byte *buffer = new byte [maxLen];
            if (Util::readBinary(path.c_str(), buffer, maxLen)) {
                // std::cout << byteToHex(buffer, maxLen) << std::endl;
                // std::cout << maxLen << std::endl;
                // std::cout << byteToHex(symmetricKey) << " " << byteToHex(IV) << std::endl;
                decrypt(buffer, maxLen, symmetricKey, IV, content);

                std::cout << byteToHex(content, maxLen) << std::endl;
                delete [] buffer;
                return true;
            }
            else {
                delete [] buffer;
                return false;
            }
        }

        void saveKeyFile(std::string keyPath, std::string passphrase) {
            std::string realContent = getMachineIdentifier() + ":" + passphrase;
            // std::cout << realContent << std::endl;

            byte *hash1 = new byte [configs.hashDigestLength];
            hashsum((byte *)(realContent.c_str()), realContent.length (), hash1);
            assert (configs.symmetricKeyLength + configs.symmetricBlockLength <= configs.hashDigestLength);
            SecByteBlock symmetricKey(hash1, configs.symmetricKeyLength);
            SecByteBlock IV(hash1 + configs.symmetricKeyLength, configs.symmetricBlockLength);

            std::string hash2 = hashsum(hash1, configs.hashDigestLength);
            delete [] hash1;
            std::string path = Util::combinePath(keyPath, hash2.substr(0, 2) + "/" + hash2.substr(2, 10) + ".key");

            Util::mkdir(Util::combinePath(keyPath, hash2.substr(0, 2)));

            // std::cerr << "path: " + path << std::endl;

            int len = configs.getKeyFileLength();
            byte *buffer = new byte [len];
            keys.saveTo(buffer);
            std::cout << byteToHex(buffer, len) << std::endl;
            byte *content = new byte [len];
            // std::cout << "keyFileLength: " << len << std::endl;
            encrypt(buffer, len, symmetricKey, IV, content);
            // std::cout << byteToHex(symmetricKey) << " " << byteToHex(IV) << std::endl;
            delete [] buffer;
            std::cout << byteToHex(content, len) << std::endl;
            Util::writeBinary(path.c_str(), content, len);
            delete [] content;
        }

        std::string getMachineIdentifier() {
            if (machineIdentifier.size() > 0) {
                return machineIdentifier;
            }
            else {
                char tmp[64];
                memset(tmp, 0, sizeof tmp);
                Util::readText("/etc/machine-id", tmp, 64);
                for (int i = 63; isspace(tmp[i]) || tmp[i] == 0; -- i) tmp[i] = 0;
                machineIdentifier = tmp;
                return machineIdentifier;
            }
        }
    };
}

#endif
