#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

#define PORT 8080

using namespace std;

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

void sendCredentials(SOCKET clientSocket) {
    string username, password;
    cout << "Enter username: ";
    cin >> username;
    cout << "Enter password: ";
    cin >> password;
    string credentials = username + ":" + password;
    send(clientSocket, credentials.c_str(), credentials.length(), 0);
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

    SOCKET clientSocket = createSocket();
    connectToServer(clientSocket);

    sendCredentials(clientSocket);
    receiveAndPrint(clientSocket); // Login successful или Authentication failed message

    receiveAndPrint(clientSocket); // Вывод меню

    int option;
    do {
        cout << "Enter option: ";
        cin >> option;
        sendOption(clientSocket, option);
        receiveAndPrint(clientSocket);
    } while (option != 4);

    closesocket(clientSocket);
    WSACleanup();
    return 0;
}
