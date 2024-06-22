#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
using namespace std;

// ������� ��� �������� ������������� ������ � �����
bool checkExistingLogin(const string& login) {
    ifstream infile("users_numbers.txt");
    if (infile.is_open()) {
        string storedLogin, storedPassword;
        while (infile >> storedLogin >> storedPassword) {
            if (login == storedLogin) {
                infile.close();
                return true; // ����� ������
            }
        }
        infile.close();
    }
    return false; // ����� �� ������
}

// ������� ��� ����������� ����� �������������
void registration_numbers() {
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

    int sum = 0;
    int totalChars = login.length() + password.length(); // ����� ���������� ��������
    for (char ch : login) {
        sum += static_cast<int>(ch) * totalChars;
    }
    for (char ch : password) {
        sum += static_cast<int>(ch) * totalChars;
    }


    // ���������� ����� � ������ � ����
    ofstream outfile("users_numbers.txt", ios::app);
    if (outfile.is_open()) {
        outfile << login << " " << sum << endl;
        outfile.close();
        cout << "������������ ���������������." << endl;
    }
    else {
        cout << "������ ��� �������� ����� ��� ������." << endl;
    }
}

// ������� ��� �������������� �������������
void authentication_numbers() {
    cout << "������� �����: ";
    string login;
    getline(cin, login);

    cout << "������� ������: ";
    string password;
    getline(cin, password);

    int sum = 0;
    int totalChars = login.length() + password.length(); 
    for (char ch : login) {
        sum += static_cast<int>(ch) * totalChars;
    }
    for (char ch : password) {
        sum += static_cast<int>(ch) * totalChars;
    }


    // ��������� ������� ������ � ������ � �����
    ifstream infile("users_numbers.txt");
    if (infile.is_open()) {
        string storedLogin, storedPassword;
        bool authenticated = false;
        while (infile >> storedLogin >> storedPassword) {
            if (login == storedLogin && to_string(sum) == storedPassword) {
                authenticated = true;
                break;
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
        cin.ignore(); // ������� ������ �����

        switch (choice) {
        case 1:
            registration_numbers();
            break;
        case 2:
            authentication_numbers();
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


    