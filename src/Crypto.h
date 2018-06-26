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
#include <random>
#include "Util.h"

using namespace CryptoPP;

namespace Crypto {
    static std::string _generateSalt (size_t saltLength) {
        static const std::string alphabet = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678";
        static const size_t sigma = alphabet.length();
        static std::random_device rd;
        std::string salt = "";
        for (size_t i = 0; i < saltLength; ++ i)
            salt += alphabet[rd() % sigma];
        return salt;
    }

    static SecByteBlock stringToSecByteBlock (std::string str) {
        return SecByteBlock((const unsigned char *)str.data(), str.size());
    }

    static void SecByteBlockToByteArray(SecByteBlock source, byte *dest) {
        memcpy(dest, source.BytePtr(), source.size());
    }

    static void writeInt(byte *pos, int x) {
        *pos = x >> 24;
        *(pos + 1) = x >> 16;
        *(pos + 2) = x >> 8;
        *(pos + 3) = x;
    }

    static int readInt(const byte *pos) {
        return ((*pos) << 24) ^ (*(pos + 1) << 16) ^ (*(pos + 2) << 8) ^ *(pos + 3);
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
        size_t symmetricKeyLength;
        size_t symmetricBlockLength;
        size_t hashDigestLength;
        size_t RSAKeyLength;
        size_t saltLength;

        size_t getKeyFileLength() {
            return symmetricKeyLength + symmetricBlockLength + RSAKeyLength * 2 + RSAKeyLength * 8 + 8 + saltLength;
        }
    };

    struct Keys {
        SecByteBlock symmetricKey;
        SecByteBlock IV;
        RSA::PublicKey publicKey;
        RSA::PrivateKey privateKey;
        std::string structureSalt;

        void init(const byte *buffer, Configs configs) {
            // std::cerr << "!! init" << std::endl;

            symmetricKey = SecByteBlock(buffer, configs.symmetricKeyLength);
            buffer += configs.symmetricKeyLength;
            IV = SecByteBlock(buffer, configs.symmetricBlockLength);
            buffer += configs.symmetricBlockLength;

            // std::cout << (int)(*buffer) << ' ' << (int)(*(buffer + 1)) << std::endl;
            size_t length = readInt(buffer); buffer += 4;
            // std::cout << "length 1: " << length << std::endl;
            ArraySource publiKeySource (buffer, length, true);
            buffer += length;
            publicKey.BERDecode(publiKeySource);

            length = readInt(buffer); buffer += 4;
            // std::cout << "length 2: " << length << std::endl;
            ArraySource privateKeySource (buffer, length, true);
            buffer += length;
            privateKey.BERDecode(privateKeySource);

            // std::cout << byteToHex(buffer, configs.getKeyFileLength()) << std::endl;

            structureSalt = std::string (buffer, buffer + configs.saltLength);
//            std::cout << "loading structure salt: " + structureSalt << std::endl;
        }

        void saveTo(byte *buffer, Configs configs) {
            memset (buffer, 0x00, configs.getKeyFileLength());

            SecByteBlockToByteArray(symmetricKey, buffer);
            buffer += configs.symmetricKeyLength;
            SecByteBlockToByteArray(IV, buffer);
            buffer += configs.symmetricBlockLength;

            // std::cerr << "!" << std::endl;

            byte *tmp = new byte [configs.RSAKeyLength * 8];
            ArraySink publicKeySink (tmp, configs.RSAKeyLength * 4);
            publicKey.DEREncode(publicKeySink);
            size_t length = publicKeySink.TotalPutLength();
            writeInt(buffer, length);
            // std::cout << (int)(*buffer) << ' ' << (int)(*(buffer + 1)) << std::endl;
            memcpy (buffer += 4, tmp, length);
            buffer += length;

            // std::cerr << "length 1: " << length << std::endl;

            // std::cerr << "!!" << std::endl;

            ArraySink privateKeySink (tmp, configs.RSAKeyLength * 8);
            privateKey.DEREncode(privateKeySink);
            length = privateKeySink.TotalPutLength();
            writeInt(buffer, length);
            memcpy (buffer += 4, tmp, length);
            buffer += length;

            // std::cerr << "length 2: " << length << std::endl;

//            std::cout << "saving structure salt: " + structureSalt << std::endl;
            memcpy (buffer, structureSalt.data(), structureSalt.length());

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
            configs.saltLength = 8;
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

            keys.structureSalt = _generateSalt (configs.saltLength);
//            std::cout << "generating " << keys.structureSalt << std::endl;
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
//passphrase = "123";
            Util::mkdir(".keys");
            saveKeyFile(keysPath, passphrase);
        }

        void displayKeys() {
            std::cout << "symmetricKey: " << byteToHex(keys.symmetricKey) << std::endl;
            std::cout << "IV: " << byteToHex(keys.IV) << std::endl;
            std::cout << "PublicKey: " << publicKeyToString(keys.publicKey) << std::endl;
            std::cout << "PrivateKey: " << privateKeyToString(keys.privateKey) << std::endl;
        }

        void saveSec (std::string rawPath, std::string salt, size_t rawLen, std::string secPath) {
            byte *content = new byte[rawLen];
            Util::readBinary (rawPath.c_str(), content, rawLen);
            saveSec (secPath, salt, content, rawLen);
        }

        bool loadSec(std::string sec_path, std::string salt, std::string raw_path, size_t rawLen) {
            byte *content = new byte [rawLen];
            bool ret = loadSec (sec_path, salt, content, rawLen);
            Util::writeBinary (raw_path.c_str(), content, rawLen);
            delete [] content;
            return ret;
        }

        std::string getStructureSalt () {
            return keys.structureSalt;
        }

        std::string generateSalt () {
            return _generateSalt (configs.saltLength);
        }

		void runTest () {
			generateKeys();

			std::string salt = "12345";

			const byte *input = (byte *)"fuck123123123123123123123 u";

			std::cout << "  -- Test for basic symmetric encryption/decryption --" << std::endl;

			int len = strlen((char *)input);
			// std::cout << len << std::endl;
			byte *output = new byte[len + 1 + 16];
			encrypt(salt, input, len, output);
			byte *recovered = new byte[len + 1 + 16];
			memset(recovered, 0, len + 1);
			decrypt(salt, output, len, recovered);

			// std::cout << (char *)recovered << std::endl;
			assert (strcmp((char *)input, (char *)recovered) == 0);                     // Testcase for symmetric encryption
			std::cout << "  -- Test passed! --" << std::endl << std::endl;

			std::cout << "  -- Test for hashsum --" << std::endl;

			std::string hexHash = hashsum(input, len);
			Util::writeBinary("input.bin", input, len);

			// std::cout << exec ("sha256sum -b input.bin | awk '{print $1;}' | head -n1") << std::endl;
			assert (hexHash == Util::exec ("sha256sum -b input.bin | head -n1 | awk '{printf $1;}'"));    // Testcase for hash
			std::cout << "  -- Test passed! --" << std::endl << std::endl;

			std::cout << "  -- Test for digital signature --" << std::endl;

			byte *signature = new byte [384];
			int sigLen = sign(input, len, signature);
			// signature[0] ^= 0x10;
			assert (verify(input, len, signature, sigLen));
			std::cout << "  -- Test passed! --" << std::endl << std::endl;

			std::cout << "  -- Test for .keys files --" << std::endl;

			// crypto.displayKeys();
			saveKeys(".keys");
			std::cout << "save ok" << std::endl;
			loadKeys(".keys");
			//    return 0;
			// crypto.displayKeys();

			memset(recovered, 0, len + 1);
			decrypt(salt, output, len, recovered);

			// std::cout << (char *) recovered << std::endl;
			assert (strcmp((char *)input, (char *)recovered) == 0);                     // Testcase for symmetric encryption
			std::cout << "  -- Test passed! --" << std::endl << std::endl;

			std::cout << "  -- Test for .keys files --" << std::endl;
			saveSec("tmp.sec", salt, input, len);
			memset (recovered, 0x00, len + 1);
			// std::cerr << len << std::endl;
			assert (loadSec("tmp.sec", salt, recovered, len));
			// std::cerr << "123123" << std::endl;
			/* for (int i = 0; i < len; ++ i)
			   std::cout << (char)(recovered[i]);*/
			// std::cerr << (char *) recovered << std::endl;
			assert (strcmp ((char *) input, (char *)recovered) == 0);
			std::cout << "  -- Test passed! --" << std::endl << std::endl;

			// delete [] input;
			delete [] output;
			delete [] recovered;
			delete [] signature;
        }

    private:
        // ::Configs *globalConfigs;
        Configs configs;
        Methods methods;
        Keys keys;
        std::string machineIdentifier;
        AutoSeededRandomPool rnd;

        SecByteBlock addSalt(SecByteBlock _key, std::string _salt) {
            assert (configs.hashDigestLength >= configs.symmetricKeyLength);

            SecByteBlock salt = stringToSecByteBlock(_salt);
            SecByteBlock raw_key = _key + salt;
            byte *digest = new byte [configs.hashDigestLength];
            hashsum(raw_key.data(), raw_key.size(), digest);
            return SecByteBlock(digest, configs.symmetricKeyLength);
        }

        bool loadKeyFile(std::string keyPath, std::string passphrase, byte *content, size_t maxLen) {
//std::cerr << keyPath << " " << passphrase << " " << content << " " << maxLen << std::endl;
            std::string realContent = getMachineIdentifier() + ":" + passphrase;
            // std::cout << realContent << std::endl;

            byte *hash1 = new byte [configs.hashDigestLength];
            hashsum((byte *)(realContent.c_str()), realContent.length (), hash1);
            assert (configs.symmetricKeyLength + configs.symmetricBlockLength <= configs.hashDigestLength);
            SecByteBlock symmetricKey(hash1, configs.symmetricKeyLength);
            SecByteBlock IV(hash1 + configs.symmetricKeyLength, configs.symmetricBlockLength);
            std::string hash2 = hashsum(hash1, configs.hashDigestLength);
            delete [] hash1;
            std::string path = Util::combinePath(keyPath, hash2.substr(0, 12) + ".key");

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
            std::string path = Util::combinePath(keyPath, hash2.substr(0, 12) + ".key");

            // Util::mkdir(Util::combinePath(keyPath, hash2.substr(0, 2)));

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

        void encrypt(const byte *input, size_t len, SecByteBlock key, SecByteBlock IV, byte *output) {
            methods.symmetricEncrypt(input, len, key, IV, output);
        }

        void encrypt(std::string salt, const byte *input, size_t len, SecByteBlock key, SecByteBlock IV, byte *output) {
            encrypt(input, len, addSalt(key, salt), IV, output);
        }

        void encrypt(std::string salt, const byte *input, size_t len, byte *output) {
            encrypt(salt, input, len, keys.symmetricKey, keys.IV, output);
        }

        void decrypt(const byte *input, size_t len, SecByteBlock key, SecByteBlock IV, byte *output) {
            methods.symmetricDecrypt(input, len, key, IV, output);
        }

        void decrypt(std::string salt, const byte *input, size_t len, SecByteBlock key, SecByteBlock IV, byte *output) {
            decrypt(input, len, addSalt (key, salt), IV, output);
        }

        void decrypt(std::string salt, const byte *input, size_t len, byte *output) {
            decrypt(salt, input, len, keys.symmetricKey, keys.IV, output);
        }

        void hashsum(const byte *input, size_t len, byte *output) {
            methods.hashsum(input, len, output);
        }

        size_t sign(const byte *input, size_t len, byte *output) {
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

        std::string hashsum(const byte *input, size_t len) {
            byte *digest = new byte [configs.hashDigestLength];
            hashsum(input, len, digest);
            std::string ret = byteToHex (digest, configs.hashDigestLength);
            delete [] digest;
            return ret;
        }

        void saveSec(std::string path, std::string salt, const byte *content, size_t len) {
            byte *signature = new byte [configs.RSAKeyLength];
            size_t sigLen = sign (content, len, signature);
            size_t totLen = 4 + sigLen + len;

            byte *raw = new byte [totLen];
            writeInt(raw, sigLen);
            // std::cout << (int)(raw[0]) << " " << byteToHex(raw, 4) << std::endl;

            memcpy (raw + 4, signature, sigLen);
            // std::cerr << "sig: " << byteToHex(signature, sigLen) << std::endl;
            delete [] signature;

            memcpy (raw + 4 + sigLen, content, len);

            byte *encrypted = new byte [totLen];
            encrypt(salt, raw, totLen, encrypted);
            delete [] raw;

            Util::writeBinary(path.c_str(), encrypted, totLen);
            // std::cout << byteToHex(encrypted, totLen) << std::endl;
            delete [] encrypted;
            // std::cout << totLen << std::endl;
        }

        bool loadSec(std::string path, std::string salt, byte *content, size_t rawLen) {
            rawLen = rawLen + 4 + configs.RSAKeyLength;
            // std::cout << rawLen << std::endl;
            byte *encrypted = new byte [rawLen];
            // memset (encrypted, 0x00, rawLen + 1);
            size_t len = Util::readBinary(path.c_str(), encrypted, rawLen);
            // std::cerr << "! " << len << std::endl;

            byte *decrypted = new byte [len];
            decrypt(salt, encrypted, len, decrypted);
            // std::cout << byteToHex(decrypted, 4) << std::endl;
            delete [] encrypted;
            size_t sigLen = readInt(decrypted);
            // std::cerr << sigLen << std::endl;

            byte *signature = new byte [sigLen];
            memcpy (signature, decrypted + 4, sigLen);
            // std::cerr << "sig: " << byteToHex(signature, sigLen) << std::endl;

            size_t remLen = len - 4 - sigLen;
            if (!verify(decrypted + 4 + sigLen, remLen, signature, sigLen))
                return false;
            delete [] signature;

            // std::cerr << remLen << std::endl;
            // std::cerr << (char)decrypted[26] << std::endl;
            memcpy (content, decrypted + 4 + sigLen, remLen);
            delete [] decrypted;
            // std::cerr << "done" << std::endl;

            return true;
        }

    };
}

#endif
