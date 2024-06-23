#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string>


void generateKeys(const std::string& privateKeyPath, const std::string& publicKeyPath) {
    int keyLength = 2048;
    unsigned long exp = RSA_F4;

    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, exp);

    RSA_generate_key_ex(rsa, keyLength, bn, NULL);

    // Save private key
    FILE* privateKeyFile;
    fopen_s(&privateKeyFile, privateKeyPath.c_str(), "wb");
    if (privateKeyFile) {
        PEM_write_RSAPrivateKey(privateKeyFile, rsa, NULL, NULL, 0, NULL, NULL);
        fclose(privateKeyFile);
    }
    else {
        std::cerr << "Unable to open private key file for writing." << std::endl;
    }

    // Save public key
    FILE* publicKeyFile;
    fopen_s(&publicKeyFile, publicKeyPath.c_str(), "wb");
    if (publicKeyFile) {
        PEM_write_RSA_PUBKEY(publicKeyFile, rsa);
        fclose(publicKeyFile);
    }
    else {
        std::cerr << "Unable to open public key file for writing." << std::endl;
    }

    RSA_free(rsa);
    BN_free(bn);
}
