#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <chrono>
#include <ctime>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "Crypt32.lib")

using namespace std;

#define PORT 8080
const std::string PUBLIC_KEY_FILE = "D:\\Visual Studio\\repos\\laba9\\RSAkeys\\public_key.pem";

void initializeWinsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed: " << result << std::endl;
        exit(1);
    }
}

SOCKET createSocket() {
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed: " << WSAGetLastError() << std::endl;
        WSACleanup();
        exit(1);
    }
    return clientSocket;
}

void connectToServer(SOCKET clientSocket) {
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr);
    serverAddress.sin_port = htons(PORT);

    if (connect(clientSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        std::cerr << "Connection failed: " << WSAGetLastError() << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        exit(1);
    }
}

EVP_PKEY* loadPublicKey(const std::string& filename) {
    FILE* file;
    fopen_s(&file, filename.c_str(), "rb");
    if (!file) {
        std::cerr << "Unable to open public key file." << std::endl;
        return nullptr;
    }
    EVP_PKEY* pkey = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
    fclose(file);
    return pkey;
}

int encryptRSA(const std::string& plaintext, unsigned char* ciphertext, EVP_PKEY* pkey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) return -1;
    if (EVP_PKEY_encrypt_init(ctx) <= 0) return -1;

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, (const unsigned char*)plaintext.c_str(), plaintext.size()) <= 0) return -1;
    if (EVP_PKEY_encrypt(ctx, ciphertext, &outlen, (const unsigned char*)plaintext.c_str(), plaintext.size()) <= 0) return -1;

    EVP_PKEY_CTX_free(ctx);
    return outlen;
}

void sendEncryptedAESKey(SOCKET clientSocket, EVP_PKEY* pkey, unsigned char* aesKey, unsigned char* iv) {
    std::string keyIv(reinterpret_cast<char*>(aesKey), 16);
    keyIv += std::string(reinterpret_cast<char*>(iv), 16);

    unsigned char encryptedKeyIv[256];
    int encryptedLen = encryptRSA(keyIv, encryptedKeyIv, pkey);
    if (encryptedLen > 0) {
        send(clientSocket, (char*)encryptedKeyIv, encryptedLen, 0);
    }
}

void sendCredentials(SOCKET clientSocket, unsigned char* aesKey, unsigned char* iv, const std::string& username, const std::string& password) {
    std::string credentials = username + ":" + password;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;
    unsigned char ciphertext[128];

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aesKey, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        std::cerr << "EVP_EncryptInit_ex failed" << std::endl;
        return;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)credentials.c_str(), credentials.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        std::cerr << "EVP_EncryptUpdate failed" << std::endl;
        return;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        std::cerr << "EVP_EncryptFinal_ex failed" << std::endl;
        return;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    send(clientSocket, (char*)ciphertext, ciphertext_len, 0);
}

void receiveAndPrint(SOCKET clientSocket) {
    char buffer[1024];
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

    if (bytesReceived > 0) {
        buffer[bytesReceived] = '\0';
        std::cout << buffer;
    }
    else {
        std::cerr << "Failed to receive data from server." << std::endl;
    }
}

void sendOption(SOCKET clientSocket, int option) {
    std::string message = std::to_string(option) + "\n";
    send(clientSocket, message.c_str(), message.length(), 0);
}

int main() {
    initializeWinsock();
    OpenSSL_add_all_algorithms();

    EVP_PKEY* pkey = loadPublicKey(PUBLIC_KEY_FILE);
    if (!pkey) {
        std::cerr << "Failed to load public key." << std::endl;
        return 1;
    }

    SOCKET clientSocket = createSocket();

    connectToServer(clientSocket);

    unsigned char aesKey[16];
    unsigned char iv[16];
    if (!RAND_bytes(aesKey, sizeof(aesKey)) || !RAND_bytes(iv, sizeof(iv))) {
        std::cerr << "Failed to generate AES key or IV." << std::endl;
        return 1;
    }

    sendEncryptedAESKey(clientSocket, pkey, aesKey, iv);


    std::string username, password;
    std::cout << "Enter username: ";
    std::cin >> username;
    std::cout << "Enter password: ";
    std::cin >> password;

    sendCredentials(clientSocket, aesKey, iv, username, password);


    receiveAndPrint(clientSocket); // menu
    receiveAndPrint(clientSocket);

    int option;
    do {
        std::cout << "Enter option: ";
        std::cin >> option;
        sendOption(clientSocket, option);
        receiveAndPrint(clientSocket);
    } while (option != 4);

    closesocket(clientSocket);
    EVP_PKEY_free(pkey);
    EVP_cleanup();
    WSACleanup();
    return 0;
}
