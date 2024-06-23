#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

#define PORT 8080
#define MAX_CONNECTIONS 1

void initializeWinsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed: " << result << std::endl;
        exit(1);
    }
}

SOCKET createSocket() {
    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed: " << WSAGetLastError() << std::endl;
        WSACleanup();
        exit(1);
    }
    return listenSocket;
}

void bindSocket(SOCKET listenSocket) {
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    InetPton(AF_INET, "127.0.0.1", &serverAddress.sin_addr.s_addr);
    serverAddress.sin_port = htons(PORT);

    if (bind(listenSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        std::cerr << "Bind failed: " << WSAGetLastError() << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        exit(1);
    }
}

void listenSocket(SOCKET listenSocket) {
    if (listen(listenSocket, MAX_CONNECTIONS) == SOCKET_ERROR) {
        std::cerr << "Listen failed: " << WSAGetLastError() << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        exit(1);
    }
}

SOCKET acceptConnection(SOCKET listenSocket) {
    SOCKET clientSocket = accept(listenSocket, nullptr, nullptr);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Accept failed: " << WSAGetLastError() << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        exit(1);
    }
    return clientSocket;
}

void handleClient(SOCKET clientSocket) {
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

        std::string response;
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

    SOCKET listenSocket = createSocket();
    bindSocket(listenSocket);
    listenSocket(listenSocket);

    std::cout << "Server is listening on port " << PORT << std::endl;

    SOCKET clientSocket = acceptConnection(listenSocket);
    handleClient(clientSocket);

    closesocket(listenSocket);
    WSACleanup();
    return 0;
}
