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
#include <cryptopp/rsa.h>
#include <cryptopp/pssr.h>
#include <cctype>

using namespace CryptoPP;

namespace Crypto {

    static void SecByteBlockToByteArray(SecByteBlock source, byte *dest) {
        memcpy(dest, source.BytePtr(), source.size());
    }

    static std::string byteToHex (const byte *input, size_t len) {
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
        void (*symmetricEncrypt) (const byte *, size_t, SecByteBlock, SecByteBlock, byte *); // plainText, key, IV, cipherText
        void (*symmetricDecrypt) (const byte *, size_t, SecByteBlock, SecByteBlock, byte *); // cipherText, key, IV, plainText
        void (*hashsum) (const byte *, size_t, byte *);
    };

    struct Configs {
        int symmetricKeyLength;
        int symmetricBlockLength;
        int hashDigestLength;
        int RSAKeyLength;

        int getKeyFileLength() {
            return symmetricKeyLength + symmetricBlockLength + RSAKeyLength * 2 + RSAKeyLength * 8;
        }
    };

    struct Keys {
        SecByteBlock symmetricKey;
        SecByteBlock IV;
        RSA::PublicKey publicKey;
        RSA::PrivateKey privateKey;

        void init(const byte *buffer, Configs configs) {
            // std::cerr << "!! init" << std::endl;

            symmetricKey = SecByteBlock(buffer, configs.symmetricKeyLength);
            buffer += configs.symmetricKeyLength;
            IV = SecByteBlock(buffer, configs.symmetricBlockLength);
            buffer += configs.symmetricBlockLength;

            // std::cout << (int)(*buffer) << ' ' << (int)(*(buffer + 1)) << std::endl;
            size_t length = *(buffer) ^ ((*(buffer + 1)) << 8); buffer += 2;
            // std::cout << "length 1: " << length << std::endl;
            ArraySource publiKeySource (buffer, length, true);
            buffer += length;
            publicKey.BERDecode(publiKeySource);

            length = *(buffer) ^ ((*(buffer + 1)) << 8); buffer += 2;
            // std::cout << "length 2: " << length << std::endl;
            ArraySource privateKeySource (buffer, length, true);
            buffer += length;
            privateKey.BERDecode(privateKeySource);

            // std::cout << byteToHex(buffer, configs.getKeyFileLength()) << std::endl;
        }

        void saveTo(byte *buffer, Configs configs) {
            memset (buffer, 0x00, configs.getKeyFileLength());

            SecByteBlockToByteArray(symmetricKey, buffer);
            buffer += configs.symmetricKeyLength;
            SecByteBlockToByteArray(IV, buffer);
            buffer += configs.symmetricBlockLength;

            // std::cerr << "!" << std::endl;

            byte *tmp = new byte [configs.RSAKeyLength * 8];
            ArraySink publicKeySink (tmp, configs.RSAKeyLength * 2);
            publicKey.DEREncode(publicKeySink);
            size_t length = publicKeySink.TotalPutLength();
            *((int *)buffer) = length;
            // std::cout << (int)(*buffer) << ' ' << (int)(*(buffer + 1)) << std::endl;
            memcpy (buffer += 2, tmp, length);
            buffer += length;

            // std::cerr << "length 1: " << length << std::endl;

            // std::cerr << "!!" << std::endl;

            ArraySink privateKeySink (tmp, configs.RSAKeyLength * 8);
            privateKey.DEREncode(privateKeySink);
            length = privateKeySink.TotalPutLength();
            *((int *)buffer) = length;
            memcpy (buffer += 2, tmp, length);
            buffer += length;

            // std::cerr << "length 2: " << length << std::endl;

            delete [] tmp;

            // std::cerr << "!!!" << std::endl;

            // std::cout << byteToHex(buffer, symmetricKey.size() + IV.size()) << std::endl;
        }
    };

    static void AESEncrypt(const byte *input, size_t len, SecByteBlock key, SecByteBlock iv, byte *output) {
        CFB_Mode<AES>::Encryption cfbEncryption(key, key.size(), iv, 1);
        cfbEncryption.ProcessData(output, input, len);
        // std::cout << "        AES   Encrypt    " << byteToHex(key) << " " << byteToHex(iv) << " " << len << " " << byteToHex(output, len) << std::endl;
    }

    static void AESDecrypt(const byte *input, size_t len, SecByteBlock key, SecByteBlock iv, byte *output) {
        // std::cout << "        AES   Decrypt    " << byteToHex(key) << " " << byteToHex(iv) << " " << len << " " << byteToHex(input, len) << std::endl;
        CFB_Mode<AES>::Decryption cfbDecryption(key, key.size(), iv, 1);
        cfbDecryption.ProcessData(output, input, len);
        // std::cout << "        AES   Decrypt    " << byteToHex(key) << " " << byteToHex(iv) << " " << len << " " << byteToHex(output, len) << std::endl;
    }

    static void SHA256Hash(const byte *input, size_t len, byte *output) {
        SHA256().CalculateDigest(output, input, len);
    }

    SecByteBlock generateKey(AutoSeededRandomPool& rnd, int keyLen) {
        SecByteBlock key(0x00, keyLen);
        rnd.GenerateBlock (key, key.size());
        return key;
    }

    std::string publicKeyToString(RSA::PublicKey publicKey) {
        byte buffer[548];
        ArraySink publicKeySink (buffer, 548);
        publicKey.DEREncode(publicKeySink);
        return byteToHex(buffer, 548);
    }

    std::string privateKeyToString(RSA::PrivateKey privateKey) {
        byte buffer[548];
        ArraySink privateKeySink (buffer, 548);
        privateKey.DEREncode(privateKeySink);
        return byteToHex(buffer, 548);
    }

    class Crypto {
    public:
        // Crypto (Configs configs, Methods methods): configs(configs), methods(methods), machineIdentifier("") {}
        Crypto () {
            // std::cout << AES::DEFAULT_KEYLENGTH << " " << AES::BLOCKSIZE << " " << SHA256::DIGESTSIZE;
            configs.symmetricKeyLength = AES::DEFAULT_KEYLENGTH;
            configs.symmetricBlockLength = AES::BLOCKSIZE;
            configs.hashDigestLength = SHA256::DIGESTSIZE;
            configs.RSAKeyLength = 384;
            methods.symmetricEncrypt = AESEncrypt;
            methods.symmetricDecrypt = AESDecrypt;
            methods.hashsum = SHA256Hash;
            machineIdentifier = "";
        }

        void generateKeys () {
            keys.symmetricKey = generateKey (rnd, configs.symmetricKeyLength);
            keys.IV = generateKey (rnd, configs.symmetricBlockLength);

            InvertibleRSAFunction params;
            params.GenerateRandomWithKeySize(rnd, configs.RSAKeyLength * 8);

            keys.publicKey = RSA::PublicKey(params);
            keys.privateKey = RSA::PrivateKey(params);
        }

        void encrypt(const byte *input, size_t len, SecByteBlock key, SecByteBlock IV, byte *output) {
            // std::cerr << "encrypt" << std::endl;
            methods.symmetricEncrypt(input, len, key, IV, output);
            // std::cerr << "encrypt done" << std::endl;
        }

        void encrypt(const byte *input, size_t len, byte *output) {
            encrypt(input, len, keys.symmetricKey, keys.IV, output);
        }

        void decrypt(const byte *input, size_t len, SecByteBlock key, SecByteBlock IV, byte *output) {
            methods.symmetricDecrypt(input, len, key, IV, output);
        }

        void decrypt(const byte *input, size_t len, byte *output) {
            decrypt(input, len, keys.symmetricKey, keys.IV, output);
        }

        void hashsum(const byte *input, size_t len, byte *output) {
            methods.hashsum(input, len, output);
        }

        int sign(const byte *input, size_t len, byte *output) {
            RSASS<PSS, SHA256>::Signer signer(keys.privateKey);
            size_t maxLen = signer.MaxSignatureLength ();
            SecByteBlock signature(maxLen);

            size_t sigLen = signer.SignMessage (rnd, input, len, signature);
            signature.resize(sigLen);

            SecByteBlockToByteArray(signature, output);
            return sigLen;
        }

        bool verify(const byte *text, size_t len, const byte *signature, size_t sigLen) {
            RSASS<PSS, SHA256>::Verifier verifier(keys.publicKey);

            SecByteBlock sig (signature, sigLen);
            bool result = verifier.VerifyMessage (text, len, sig, sigLen);

            return result;
        }

        // bool verify(const byte *input,)

        std::string hashsum(const byte *input, size_t len) {
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
                    // std::cout << "keyFileLength: " << keyFileLength << std::endl;
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
            std::cout << "PublicKey: " << publicKeyToString(keys.publicKey) << std::endl;
            std::cout << "PrivateKey: " << privateKeyToString(keys.privateKey) << std::endl;
        }

        void saveSec(std::string path, const byte *content) {

        }

    private:
        // ::Configs *globalConfigs;
        Configs configs;
        Methods methods;
        Keys keys;
        std::string machineIdentifier;
        AutoSeededRandomPool rnd;

        bool loadKeyFile(std::string keyPath, std::string passphrase, byte *content, size_t maxLen) {
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

            // std::cerr << "path: " + path << std::endl;

            byte *buffer = new byte [maxLen];
            if (Util::readBinary(path.c_str(), buffer, maxLen)) {
                // std::cout << byteToHex(buffer, maxLen) << std::endl;
                // std::cout << maxLen << std::endl;
                // std::cout << byteToHex(symmetricKey) << " " << byteToHex(IV) << std::endl;
                decrypt(buffer, maxLen, symmetricKey, IV, content);
                // std::cout << byteToHex(content, maxLen) << std::endl;

                // std::cout << byteToHex(content, maxLen) << std::endl;
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

            size_t len = configs.getKeyFileLength();
            byte *buffer = new byte [len];
            keys.saveTo(buffer, configs);
            // std::cerr << "asdas" << std::endl;
            // std::cout << byteToHex(buffer, len) << std::endl;
            // std::cerr << len << std::endl;
            // std::cout << byteToHex(buffer, len) << std::endl;
            byte *content = new byte [len];
            // std::cerr << len << std::endl;
            // std::cout << "keyFileLength: " << len << std::endl;
            encrypt(buffer, len, symmetricKey, IV, content);
            // std::cout << byteToHex(symmetricKey) << " " << byteToHex(IV) << std::endl;
            delete [] buffer;
            // std::cerr << "done" << std::endl;
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
