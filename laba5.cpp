#include <iostream>
#include <unordered_map>
#include <string>
#include <vector>
#include "filters.h"
#include "hex.h"
#include <fstream>
#include <sstream>
#include <conio.h>
#include <algorithm>
#include "md5.h"

using namespace CryptoPP;
using namespace std;

struct User {
    string password;
    bool isBlocked = false;
    bool passwordRestrictions = false;
};

// ������� ��� �������� ���� ������
string hashPassword(const string& password) {
    MD5 md5;
    string hashedPassword;
    StringSource(password, true,
        new HashFilter(md5,
            new HexEncoder(
                new StringSink(hashedPassword)
            )
        )
    );
    return hashedPassword;
}

string adminPassword = hashPassword("adminpass");

unordered_map<string, User> users;

const string usersFile = "users.dat";

string inputPassword() {
    string password;
    char ch;
    while ((ch = _getch()) != 13) {
        if (ch == 8 && !password.empty()) {
            cout << "\b \b";
            password.pop_back();
        }
        else if (ch != 8) {
            cout << '*';
            password.push_back(ch);
        }
    }
    cout << endl;
    return password;
}

void loadUsers() {
    ifstream file(usersFile);
    string line;
    while (getline(file, line)) {
        istringstream iss(line);
        string username, password;
        bool isBlocked, passwordRestrictions;
        iss >> username;
        if (iss.peek() == ' ') iss.ignore();
        getline(iss, password, ' ');
        iss >> isBlocked >> passwordRestrictions;
        users[username] = { password, isBlocked, passwordRestrictions };
    }
}

void saveUsers() {
    ofstream file(usersFile);
    for (const auto& pair : users) {
        file << pair.first << " " << pair.second.password << " "
            << pair.second.isBlocked << " " << pair.second.passwordRestrictions << "\n";
    }
}


bool changePassword(const string& username) {
    cout << "������� ������ ������: ";
    string oldPassword = inputPassword();
    if (users[username].password == hashPassword(oldPassword)) {
        string newPassword, confirmPassword;
        cout << "����� ������: ";
        newPassword = inputPassword();
        cout << "��������� ����� ������: ";
        confirmPassword = inputPassword();
        if (newPassword == confirmPassword) {
            if (users[username].passwordRestrictions && newPassword.length() < 8) {
                cout << "����������� ����� ������ - 8 ��������.\n";
                return false;
            }
            users[username].password = hashPassword(newPassword);
            saveUsers();
            cout << "������ ������.\n";
            return true;
        }
        else {
            cout << "������ �� ���������.\n";
        }
    }
    else if(username == "admin" && hashPassword(oldPassword) == adminPassword) {
        string newPassword, confirmPassword;
        cout << "����� ������: ";
        newPassword = inputPassword();
        cout << "��������� ����� ������: ";
        confirmPassword = inputPassword();
        if (newPassword == confirmPassword) {
            adminPassword = hashPassword(newPassword);
            cout << "������ ������.\n";
        }
        else {
            cout << "������ �� ���������.\n";
        }
    }
    else {
        cout << "������������ ������ ������.\n";
    }
        
    
    return false;
}

void passwordNewUser(const string& username) {
    string newPassword, confirmPassword;
    cout << "����� ������: ";
    newPassword = inputPassword();
    cout << "��������� ����� ������: ";
    confirmPassword = inputPassword();
    if (newPassword == confirmPassword) {
        if (users[username].passwordRestrictions && newPassword.length() < 8) {
            cout << "����������� ����� ������ - 8 ��������.\n";
            passwordNewUser(username);
        }
        else {
            users[username].password = hashPassword(newPassword);
            saveUsers();
            cout << "������ ������.\n";
        }
    }
    else {
        cout << "������ �� ���������.\n";
        passwordNewUser(username);
    }
}

void showUsers() {
    for (const auto& pair : users) {
        cout << "��� ������������: " << pair.first << " | ������������: " << pair.second.isBlocked
            << " | ����������� �� ������: " << pair.second.passwordRestrictions << "\n";
    }
}

void addUser(const string& username) {
    if (users.find(username) == users.end()) {
        users[username] = { "", false, false };
        saveUsers();
        cout << "������������ ��������.\n";
    }
    else {
        cout << "������������ ��� ����������.\n";
    }
}

void blockUnblockUser(const string& username) {
    if (users.find(username) != users.end()) {
        users[username].isBlocked = !users[username].isBlocked;
        if (users[username].isBlocked == true)
        {
            cout << "������������ ������������.\n";
        }
        else
        {
            cout << "������������ �������������.\n";
        }
        saveUsers();
        
    }
    else {
        cout << "������������ �� ����������.\n";
    }
}

void OnOffPasswordRestrictions(const string& username) {
    if (users.find(username) != users.end()) {
        users[username].passwordRestrictions = !users[username].passwordRestrictions;
        if (users[username].passwordRestrictions == true)
        {
            cout << "����������� �� ������ ��������.\n";
        }
        else
        {
            cout << "����������� �� ������ ���������.\n";
        }
        saveUsers();
        
    }
    else {
        cout << "������������ �� ����������.\n";
    }
}

void adminMenu() {
    while (true) {
        cout << "1. ������� ������ ��������������\n";
        cout << "2. ����������� ������ �������������\n";
        cout << "3. �������� ������ ������������\n";
        cout << "4. �������������/�������������� ������������\n";
        cout << "5. ����������/������ ����������� �� ������ ������������\n";
        cout << "6. �����\n";
        int choice;
        cin >> choice;
        cin.ignore();
        if (choice == 1) {
            changePassword("admin");
        }
        else if (choice == 2) {
            showUsers();
        }
        else if (choice == 3) {
            string username;
            cout << "������� ��� ������������: ";
            getline(cin, username);
            addUser(username);
        }
        else if (choice == 4) {
            string username;
            cout << "������� ��� ������������: ";
            getline(cin, username);
            blockUnblockUser(username);
        }
        else if (choice == 5) {
            string username;
            cout << "������� ��� ������������: ";
            getline(cin, username);
            OnOffPasswordRestrictions(username);
        }
        else if (choice == 6) {
            break;
        }
    }
}

void userMenu(const string& username) {
    while (true) {
        cout << "1. ����� ������\n";
        cout << "2. �����\n";
        int choice;
        cin >> choice;
        cin.ignore();
        if (choice == 1) {
            changePassword(username);
        }
        else if (choice == 2) {
            break;
        }
    }
}

int main() {
    setlocale(LC_ALL, "ru");
    loadUsers();
    string username, password;
    int attempts;
    while (true) {
        cout << "������� ��� ������������: ";
        getline(cin, username);
        attempts = 3;

        while (true) {
            if (username == "admin") {
                cout << "������� ������: ";
                password = inputPassword();
                if (hashPassword(password) == adminPassword) {
                    adminMenu();
                    break;
                }
                else {
                    cout << "�������� ������.\n";
                    attempts -= 1;
                    cout << "�������� �������: " << attempts << endl;
                    if (attempts == 0) {
                        cout << "��������� ������� �����.\n";
                        return 0;
                    }
                }
            }
            else if (users.find(username) != users.end()) {
                if (users[username].password.empty()) {
                    cout << "��� ���������� ������ ����� ������.\n";
                    passwordNewUser(username);
                }
                else {
                    cout << "������� ������: ";
                    password = inputPassword();
                    if (users[username].isBlocked) {
                        cout << "������������ ������������.\n";
                        break;
                    }
                    else if (users[username].password == hashPassword(password)) {
                        userMenu(username);
                        break;
                    }
                    else {
                        cout << "�������� ������.\n";
                        attempts -= 1;
                        cout << "�������� �������: " << attempts << endl;
                        if (attempts == 0) {
                            cout << "��������� ������� �����.\n";
                            return 0;
                        }
                    }
                }
            }
            else {
                cout << "������������ �� ����������.\n";
                char choice;
                cout << "����������� ����� (y/n)? ";
                cin >> choice;
                cin.ignore();
                if (choice == 'n' || choice == 'N') {
                    return 0;
                }
                else {
                    break;
                }
            }
        }
    }
    return 0;
}