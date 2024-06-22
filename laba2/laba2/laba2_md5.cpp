#include <iostream>
#include "md5.h"
#include "hex.h"
#include "filters.h"
#include <fstream>
#include <string>
#include <windows.h>
using namespace CryptoPP;
using namespace std;

// ������� ��� �������� ������������� ������ � �����
bool checkExistingLogin(const string& login) {
    ifstream infile("users_md5.txt");
    if (infile.is_open()) {
        string storedLogin, storedPassword;
        while (infile >> storedLogin >> storedPassword) {
            if (login == storedLogin) {
                infile.close();
                return true;
            }
        }
        infile.close();
    }
    return false;
}

// ������� ��� ����������� ������
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

// ������� ��� ����������� ����� �������������
void registration_md5() {
    cout << "���������� �����: ";
    string login;
    getline(cin, login);

    // ���������, ���������� �� ��� ��������� �����
    if (checkExistingLogin(login)) {
        cout << "������������ � ����� ������� ��� ����������." << endl;
        return;
    }
    cout << "���������� ������: ";
    string password;
    getline(cin, password);

    // ��� ������
    string hashedPassword = hashPassword(password);

    // ����� � ��� ������ � ����
    ofstream outfile("users_md5.txt", ios::app);
    if (outfile.is_open()) {
        outfile << login << " " << hashedPassword << endl;
        outfile.close();
        cout << "������������ ���������������." << endl;
    }
    else {
        cout << "������ ��� �������� ����� ��� ������." << endl;
    }
}

// ������� ��� �������������� �������������
void authentication_md5() {
    cout << "������� �����: ";
    string login;
    getline(cin, login);

    cout << "������� ������: ";
    string password;
    getline(cin, password);

    // ��� ���������� ������
    string hashedPassword = hashPassword(password);

    // �������� ������� ������ � ���� ������ � �����
    ifstream infile("users_md5.txt");
    if (infile.is_open()) {
        string line;
        bool authenticated = false;
        while (getline(infile, line)) {
            size_t pos = line.find(" ");
            if (pos != string::npos) {
                string storedLogin = line.substr(0, pos);
                string storedHashedPassword = line.substr(pos + 1);
                if (login == storedLogin && hashedPassword == storedHashedPassword) {
                    authenticated = true;
                    break;
                }
            }
        }
        infile.close();
        if (authenticated) {
            cout << "����������� �������." << endl;
        }
        else {
            cout << "�������� ����� ��� ������." << endl;
        }
    }
    else {
        cout << "������ ��� �������� ����� ��� ������." << endl;
    }
}

int main() {
    setlocale(LC_ALL, "ru");
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);
    bool flag = true;
    while (flag) {
        cout << "�������� ��������:\n1. �����������\n2. �����������\n3. �����\n";
        int choice;
        cin >> choice;
        cin.ignore();
        switch (choice) {
        case 1:
            registration_md5();
            break;
        case 2:
            authentication_md5();
            break;
        case 3:
            cout << "�� ��������!\n";
            return 0;
        default:
            cout << "�������� ����. ���������� ��� ���.\n";
        }
        flag = false;
    }
    return 0;
}