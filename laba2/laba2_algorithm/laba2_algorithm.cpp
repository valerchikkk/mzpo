#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <windows.h>

using namespace std;
//��� ������� ��� ��������� �������������
string unshiftString(const string& str, int offset) {

    string shifted = str;
    int length = str.length();
    offset = (length - offset) % length;
    char temp;
    for (int j = 0; j < offset; j++)
    {
        temp = shifted[shifted.length() - 1];
        for (int i = shifted.length(); i >= 1; i--)
            shifted[i] = shifted[i - 1];
        shifted[0] = temp;
    }
    return shifted;
}

string unshuffleString(const string& str) {

    int length = str.length();
    string result = str;
    int middle = length / 2;
    for (int i = 0; i < middle; ++i) {
        char temp = result[i];
        result[i] = result[middle + length % 2 + i];
        result[middle + length % 2 + i] = temp;
    }
    return unshiftString(result, 4);
}

bool checkExistingLogin(const string& login) {
    string check_login = login;

    ifstream infile("users_algorithm.txt");
    if (infile.is_open()) {
        string strLogin;
        bool user_exist = false;
        while (infile >> strLogin) {
            string unshuffle = unshuffleString(strLogin);
            size_t index = unshuffle.find("$");
            strLogin = unshuffle.substr(0, index);
            if (check_login == strLogin) {
                user_exist = true;
                break;
            }
        }
        infile.close();
        if (user_exist) {
            return true;
        }
        else {
            return false;
        }
    }
}

// ������� ��� ������ ������ �� 4
string shiftString(const string& str, int offset) {
    string shifted = str;
    int length = shifted.length();
    offset = offset % length; // ����� ��� � �������� ����� ������

    char temp;
    for (int j = 0; j < offset; j++)
    {
        temp = shifted[shifted.length() - 1];
        for (int i = shifted.length(); i >= 1; i--)
            shifted[i] = shifted[i - 1];
        shifted[0] = temp;
    }
    return shifted;
}

// ������� ��� ������������� ������
string shuffleString(const string& str) {
    string shifted = shiftString(str, 4); // �������� ������ �� 4 �������
    int length = shifted.length();
    string result = shifted;
    int middle = length / 2;
    // ������ ������� ������� �� ������������ ������� � ��������� ����� ������������
    for (int i = 0; i < middle; ++i) {
        char temp = result[i];
        result[i] = result[middle + length % 2 + i];
        result[middle + length % 2 + i] = temp;
    }

    return result;
}

// ������� ��� ����������� ����� �������������
void registration_encrypted() {
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

    // ���������� ������ ��� ������
    string combined = login + "$" + password;
    // ������������ ������
    string encrypted = shuffleString(combined);

    // ���������� ����� � ������ � ����
    ofstream outfile("users_algorithm.txt", ios::app);
    if (outfile.is_open()) {
        outfile << encrypted << endl;
        outfile.close();
        cout << "������������ ���������������." << endl;
    }
    else {
        cout << "������ ��� �������� ����� ��� ������." << endl;
    }
}

void authentication_algorithm() {

    cout << "������� �����: ";
    string login;
    getline(cin, login);

    cout << "������� ������: ";
    string password;
    getline(cin, password);

    string combined = login + "$" + password;

    string str_searching = shuffleString(combined);

    // �������� ������� ������ � ������ � �����
    ifstream infile("users_algorithm.txt");
    if (infile.is_open()) {
        string strLoginPassword;
        bool authenticated = false;
        while (infile >> strLoginPassword) {
            if (str_searching == strLoginPassword) {
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
            registration_encrypted();
            break;
        case 2:
            authentication_algorithm();
            break;
        case 3:
            cout << "�� ��������!\n";
            break;
        default:
            cout << "�������� ����. ���������� ��� ���.\n";
        }
        flag = false;
    }

    return 0;
}