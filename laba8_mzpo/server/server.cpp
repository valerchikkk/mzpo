#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")

#pragma comment(lib, "Crypt32.lib")

using namespace std;

#define PORT 8080
#define MAX_CONNECTIONS 1

const string USERNAME = "user";
const string PASSWORD = "pass";
const string KEY = "0123456789abcdef";  
const string IV = "abcdef9876543210";   

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

int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
    unsigned char* iv, unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        return -1;

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return -1;
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        return -1;
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

bool authenticateClient(SOCKET clientSocket) {
    unsigned char buffer[1024];
    int bytesReceived = recv(clientSocket, (char*)buffer, sizeof(buffer), 0);
    if (bytesReceived <= 0) {
        return false;
    }

    unsigned char decrypted[1024];
    int decrypted_len = decrypt(buffer, bytesReceived, (unsigned char*)KEY.c_str(), (unsigned char*)IV.c_str(), decrypted);
    if (decrypted_len <= 0) {
        return false;
    }

    decrypted[decrypted_len] = '\0';
    string receivedData((char*)decrypted);
    size_t delimiterPos = receivedData.find(':');
    if (delimiterPos == string::npos) {
        return false;
    }
    string username = receivedData.substr(0, delimiterPos);
    string password = receivedData.substr(delimiterPos + 1);
    return username == USERNAME && password == PASSWORD;
}

void handleClient(SOCKET clientSocket) {
    if (!authenticateClient(clientSocket)) {
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

    SOCKET listenSocket = createSocket();
    bindSocket(listenSocket);
    listenOnSocket(listenSocket);

    cout << "Server is listening on port " << PORT << endl;

    while (true) {
        SOCKET clientSocket = acceptConnection(listenSocket);
        handleClient(clientSocket);
    }

    closesocket(listenSocket);
    EVP_cleanup();
    WSACleanup();
    return 0;
}
