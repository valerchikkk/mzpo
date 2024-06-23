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
const string PRIVATE_KEY_FILE = "D:\\Visual Studio\\repos\\laba9\\RSAkeys\\private_key.pem";

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
        cerr << "Socket creation failed: " << WSAGetLastError() << endl;
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
        cerr << "Connection failed: " << WSAGetLastError() << endl;
        closesocket(clientSocket);
        WSACleanup();
        exit(1);
    }
}

EVP_PKEY* loadPrivateKey(const std::string& filename) {
    FILE* file;
    fopen_s(&file, filename.c_str(), "rb");
    if (!file) {
        cerr << "Unable to open private key file." << endl;
        return nullptr;
    }
    EVP_PKEY* pkey = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    return pkey;
}

int decryptRSA(unsigned char* ciphertext, int ciphertext_len, unsigned char* plaintext, EVP_PKEY* pkey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) return -1;
    if (EVP_PKEY_decrypt_init(ctx) <= 0) return -1;

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext, ciphertext_len) <= 0) return -1;
    if (EVP_PKEY_decrypt(ctx, plaintext, &outlen, ciphertext, ciphertext_len) <= 0) return -1;

    EVP_PKEY_CTX_free(ctx);
    return outlen;
}

void receiveAESKey(SOCKET clientSocket, EVP_PKEY* pkey, unsigned char* aesKey, unsigned char* iv) {
    unsigned char encryptedKeyIv[256];
    int bytesReceived = recv(clientSocket, (char*)encryptedKeyIv, sizeof(encryptedKeyIv), 0);
    if (bytesReceived <= 0) {
        cerr << "Failed to receive encrypted AES key." << endl;
        return;
    }

    unsigned char decryptedKeyIv[32];
    int decryptedLen = decryptRSA(encryptedKeyIv, bytesReceived, decryptedKeyIv, pkey);
    if (decryptedLen != 32) {
        cerr << "Failed to decrypt AES key and IV." << endl;
        return;
    }

    memcpy(aesKey, decryptedKeyIv, 16);
    memcpy(iv, decryptedKeyIv + 16, 16);
}

void sendCredentials(SOCKET clientSocket, unsigned char* aesKey, unsigned char* iv, const std::string& username, const std::string& password) {
    string credentials = username + ":" + password;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;
    unsigned char ciphertext[128];

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aesKey, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "EVP_EncryptInit_ex failed" << endl;
        return;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)credentials.c_str(), credentials.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "EVP_EncryptUpdate failed" << endl;
        return;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "EVP_EncryptFinal_ex failed" << endl;
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
        cout << buffer;
    }
    else {
        cerr << "Failed to receive data from server." << endl;
    }
}

void sendOption(SOCKET clientSocket, int option) {
    string message = to_string(option) + "\n";
    send(clientSocket, message.c_str(), message.length(), 0);
}

int main() {
    initializeWinsock();
    OpenSSL_add_all_algorithms();

    EVP_PKEY* pkey = loadPrivateKey(PRIVATE_KEY_FILE);
    if (!pkey) {
        cerr << "Failed to load private key." << endl;
        return 1;
    }

    SOCKET clientSocket = createSocket();

    connectToServer(clientSocket);

    unsigned char aesKey[16];
    unsigned char iv[16];
    receiveAESKey(clientSocket, pkey, aesKey, iv);

    string username, password;
    cout << "Enter username: ";
    cin >> username;
    cout << "Enter password: ";
    cin >> password;

    sendCredentials(clientSocket, aesKey, iv, username, password);

    receiveAndPrint(clientSocket); // Log successful или ошибка
    receiveAndPrint(clientSocket); // Меню

    int option;
    do {
        cout << "Enter option: ";
        cin >> option;
        sendOption(clientSocket, option);
        receiveAndPrint(clientSocket);
    } while (option != 4);

    closesocket(clientSocket);
    EVP_cleanup();
    WSACleanup();
    return 0;
}
