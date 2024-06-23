#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <chrono>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "Crypt32.lib")

using namespace std;

#define PORT 8080
#define MAX_CONNECTIONS 1

const string USERNAME = "user";
const string PASSWORD = "pass";
const string PUBLIC_KEY_FILE = "D:\\Visual Studio\\repos\\laba9\\RSAkeys\\public_key.pem";

void initializeWinsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        cerr << "WSAStartup failed: " << result << endl;
        exit(1);
    }
}

SOCKET createSocket() {
    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket == INVALID_SOCKET) {
        cerr << "Socket creation failed: " << WSAGetLastError() << endl;
        WSACleanup();
        exit(1);
    }
    return listenSocket;
}

void bindSocket(SOCKET listenSocket) {
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr);
    serverAddress.sin_port = htons(PORT);

    if (bind(listenSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        cerr << "Bind failed: " << WSAGetLastError() << endl;
        closesocket(listenSocket);
        WSACleanup();
        exit(1);
    }
}

void listenOnSocket(SOCKET listenSocket) {
    if (listen(listenSocket, MAX_CONNECTIONS) == SOCKET_ERROR) {
        cerr << "Listen failed: " << WSAGetLastError() << endl;
        closesocket(listenSocket);
        WSACleanup();
        exit(1);
    }
}

SOCKET acceptConnection(SOCKET listenSocket) {
    SOCKET clientSocket = accept(listenSocket, nullptr, nullptr);
    if (clientSocket == INVALID_SOCKET) {
        cerr << "Accept failed: " << WSAGetLastError() << endl;
        closesocket(listenSocket);
        WSACleanup();
        exit(1);
    }
    return clientSocket;
}

EVP_PKEY* loadPublicKey(const string& filename) {
    FILE* file;
    fopen_s(&file, filename.c_str(), "rb");
    if (!file) {
        cerr << "Unable to open public key file." << endl;
        return nullptr;
    }
    EVP_PKEY* pkey = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
    fclose(file);
    return pkey;
}

int encryptRSA(unsigned char* plaintext, int plaintext_len, unsigned char* ciphertext, EVP_PKEY* pkey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) return -1;
    if (EVP_PKEY_encrypt_init(ctx) <= 0) return -1;

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, plaintext, plaintext_len) <= 0) return -1;
    if (EVP_PKEY_encrypt(ctx, ciphertext, &outlen, plaintext, plaintext_len) <= 0) return -1;

    EVP_PKEY_CTX_free(ctx);
    return outlen;
}

void sendAESKey(SOCKET clientSocket, EVP_PKEY* pkey, unsigned char* aesKey, unsigned char* iv) {
    unsigned char keyIv[32];
    memcpy(keyIv, aesKey, 16);
    memcpy(keyIv + 16, iv, 16);

    unsigned char encryptedKeyIv[256];
    int encryptedLen = encryptRSA(keyIv, 32, encryptedKeyIv, pkey);
    if (encryptedLen > 0) {
        send(clientSocket, (char*)encryptedKeyIv, encryptedLen, 0);
    }
}

int decryptAES(unsigned char* ciphertext, int ciphertext_len, unsigned char* plaintext, unsigned char* aesKey, unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aesKey, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "EVP_DecryptInit_ex failed" << endl;
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "EVP_DecryptUpdate failed" << endl;
        return -1;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "EVP_DecryptFinal_ex failed" << endl;
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

bool authenticateClient(SOCKET clientSocket, unsigned char* aesKey, unsigned char* iv) {
    unsigned char buffer[1024];
    int bytesReceived = recv(clientSocket, (char*)buffer, sizeof(buffer), 0);
    if (bytesReceived <= 0) {
        cerr << "Failed to receive credentials." << endl;
        return false;
    }

    unsigned char decrypted[1024];
    int decrypted_len = decryptAES(buffer, bytesReceived, decrypted, aesKey, iv);
    if (decrypted_len <= 0) {
        cerr << "Failed to decrypt credentials." << endl;
        return false;
    }
    decrypted[decrypted_len] = '\0';

    string receivedData((char*)decrypted);
    size_t delimiterPos = receivedData.find(':');
    if (delimiterPos == string::npos) {
        cerr << "Failed to parse credentials." << endl;
        return false;
    }
    string username = receivedData.substr(0, delimiterPos);
    string password = receivedData.substr(delimiterPos + 1);
    return username == USERNAME && password == PASSWORD;
}

void handleClient(SOCKET clientSocket, EVP_PKEY* pkey) {
    unsigned char aesKey[16];
    unsigned char iv[16];
    if (!RAND_bytes(aesKey, sizeof(aesKey)) || !RAND_bytes(iv, sizeof(iv))) {
        cerr << "Failed to generate AES key or IV." << endl;
        closesocket(clientSocket);
        return;
    }

    sendAESKey(clientSocket, pkey, aesKey, iv);

    if (!authenticateClient(clientSocket, aesKey, iv)) {
        const char* authFailedMessage = "Authentication failed\n";
        send(clientSocket, authFailedMessage, strlen(authFailedMessage), 0);
        closesocket(clientSocket);
        return;
    }

    const char* loginSuccessMessage = "Login successful\n";
    send(clientSocket, loginSuccessMessage, strlen(loginSuccessMessage), 0);
    const char* menu = "Menu:\n1. Option 1\n2. Option 2\n3. Option 3\n4. Exit\n";
    send(clientSocket, menu, strlen(menu), 0);

    char buffer[1024];
    while (true) {
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

        if (bytesReceived == SOCKET_ERROR || bytesReceived == 0) {
            cout << bytesReceived << endl;
            break;
        }
        buffer[bytesReceived] = '\0';
        int option = atoi(buffer);

        string response;
        switch (option) {
        case 1:
            response = "You choose option 1\n";
            break;
        case 2:
            response = "You choose option 2\n";
            break;
        case 3:
            response = "You choose option 3\n";
            break;
        case 4:
            response = "Session ended\n";
            send(clientSocket, response.c_str(), response.length(), 0);
            closesocket(clientSocket);
            return;
        default:
            response = "Invalid option\n";
            break;
        }
        send(clientSocket, response.c_str(), response.length(), 0);
    }
    closesocket(clientSocket);
}

int main() {
    initializeWinsock();
    OpenSSL_add_all_algorithms();

    EVP_PKEY* pkey = loadPublicKey(PUBLIC_KEY_FILE);
    if (!pkey) {
        cerr << "Failed to load public key." << endl;
        return 1;
    }

    SOCKET listenSocket = createSocket();
    bindSocket(listenSocket);
    listenOnSocket(listenSocket);

    cout << "Server is listening on port " << PORT << endl;

    while (true) {
        SOCKET clientSocket = acceptConnection(listenSocket);
        handleClient(clientSocket, pkey);
    }

    closesocket(listenSocket);
    EVP_PKEY_free(pkey);
    EVP_cleanup();
    WSACleanup();
    return 0;
}
