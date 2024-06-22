#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include "D:\obfuscator\cpp-obfuscator-master\obfuscator.hpp"

using namespace std;
template <char key>
constexpr char xor_(char c) {
    return c ^ key;
}

template <char Key>
constexpr char add(char c) {
    return c + Key;
}

template <char(*f)(char), char(*g)(char)>
constexpr char comp(char c) {
    return f(g(c));
}


bool checkExistingLogin(const string& login) {

    ifstream infile(obfs::make_string<xor_<0x50>, xor_<0x50>>("users_opentext.txt").decode());
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

void root() {
    using table = obfs::make_table<
        obfs::encoder_seq<xor_<0x50>, add<10>, comp<xor_<0x50>, add<10>>>,
        obfs::decoder_seq<xor_<0x50>, add<-10>, comp<add<-10>, xor_<0x50>>>>;
    cout << obfs::make_string<xor_<0x50>, xor_<0x50>>("������� ����� ��������������: ").decode();
    string login;
    getline(cin, login);

    cout << obfs::make_string<xor_<0x50>, xor_<0x50>>("������� ������ ��������������: ").decode();
    string password;
    getline(cin, password);

    MAKE_STRING(root_pass, "rootadmin", table);
    MAKE_STRING(root_login, "rootlogin", table);
    if (login == root_login.decode() && password == root_pass.decode()) {

        cout << "����������� ��� ������� ������� �������������� �������." << endl;
    }

    else {
        cout << "�������� ����� ��� ������." << endl;
    }

}
void registration_opentext() {
    cout << obfs::make_string<xor_<0x50>, xor_<0x50>>("���������� �����: ").decode();
    string login;
    getline(cin, login);
    if (checkExistingLogin(login)) {
        cout << obfs::make_string<xor_<0x50>, xor_<0x50>>("������������ � ����� ������� ��� ����������.").decode();
        return;
    }
    cout << obfs::make_string<xor_<0x50>, xor_<0x50>>("���������� ������: ").decode();
    string password;
    getline(cin, password);

    ofstream outfile(obfs::make_string<xor_<0x50>, xor_<0x50>>("users_opentext.txt").decode(), ios::app);
    if (outfile.is_open()) {
        outfile << login << " " << password << endl;
        outfile.close();
        cout << obfs::make_string<xor_<0x50>, xor_<0x50>>("������������ ���������������.").decode();
    }
    else {
        cout << obfs::make_string<xor_<0x50>, xor_<0x50>>("������ ��� �������� ����� ��� ������.").decode();
    }
}

void authentication_opentext() {
    cout << obfs::make_string<xor_<0x50>, xor_<0x50>>("������� �����: ").decode();

    string login;
    getline(cin, login);

    cout << obfs::make_string<xor_<0x50>, xor_<0x50>>("������� ������: ").decode();
    string password;
    getline(cin, password);

    ifstream infile(obfs::make_string<xor_<0x50>, xor_<0x50>>("users_opentext.txt").decode());
    if (infile.is_open()) {
        string storedLogin, storedPassword;
        bool authenticated = false;
        while (infile >> storedLogin >> storedPassword) {
            if (login == storedLogin && password == storedPassword) {
                authenticated = true;
                break;
            }
        }
        infile.close();
        if (authenticated) {
            cout << obfs::make_string<xor_<0x50>, xor_<0x50>>("����������� �������.").decode();

        }
        else {
            cout << obfs::make_string<xor_<0x50>, xor_<0x50>>("�������� ����� ��� ������.").decode();

        }
    }
    else {
        cout << obfs::make_string<xor_<0x50>, xor_<0x50>>("������ ��� �������� ����� ��� ������.").decode();

    }
}
int main() {
    setlocale(LC_ALL, "ru");
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);
    bool flag = true;
    while (flag) {
        cout << obfs::make_string<xor_<0x50>, xor_<0x50>>("�������� ��������:\n1. �����������\n2. �����������\n3. ���� ��� ��������������\n4. �����\n").decode();
        int choice;
        cin >> choice;
        cin.ignore(); 

        switch (choice) {
        case 1:
            registration_opentext();
            break;
        case 2:
            authentication_opentext();
            break;
        case 3:
            root();
            break;
        case 4:
            cout << obfs::make_string<xor_<0x50>, xor_<0x50>>("�� ��������!\n").decode();
            return 0;
        default:
            cout << obfs::make_string<xor_<0x50>, xor_<0x50>>("�������� ����. ���������� ��� ���.\n").decode();
        }
        flag = false; //����� ������ return 0;}
    }
    return 0;
}
