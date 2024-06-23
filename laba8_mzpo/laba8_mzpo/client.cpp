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

int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
    unsigned char* iv, unsigned char* ciphertext) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        return -1;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return -1;
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return -1;
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

void sendCredentials(SOCKET clientSocket) {
    string username, password;
    cout << "Enter username: ";
    cin >> username;
    cout << "Enter password: ";
    cin >> password;
    string credentials = username + ":" + password;
    unsigned char ciphertext[128];
    int ciphertext_len = encrypt((unsigned char*)credentials.c_str(), credentials.length(), 
        (unsigned char*)KEY.c_str(), (unsigned char*)IV.c_str(), ciphertext);
    if (ciphertext_len > 0) {
        send(clientSocket, (char*)ciphertext, ciphertext_len, 0);
    }
}

void receiveAndPrint(SOCKET clientSocket) {
    char buffer[1024];
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (bytesReceived > 0) {
        buffer[bytesReceived] = '\0';
        cout << buffer;
    }
}

void sendOption(SOCKET clientSocket, int option) {
    string message = to_string(option) + "\n";
    send(clientSocket, message.c_str(), message.length(), 0);
}

int main() {
    initializeWinsock();
    OpenSSL_add_all_algorithms();

    SOCKET clientSocket = createSocket();
    connectToServer(clientSocket);

    sendCredentials(clientSocket);
    receiveAndPrint(clientSocket); // Login successful или Authentication failed message

    receiveAndPrint(clientSocket); // ћеню

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
