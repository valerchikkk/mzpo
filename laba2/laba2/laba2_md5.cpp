#include <iostream>
#include "md5.h"
#include "hex.h"
#include "filters.h"
#include <fstream>
#include <string>
#include <windows.h>
using namespace CryptoPP;
using namespace std;

// Функция для проверки существования логина в файле
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

// Функция для хеширования пароля
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

// Функция для регистрации новых пользователей
void registration_md5() {
    cout << "Придумайте логин: ";
    string login;
    getline(cin, login);

    // Проверяем, существует ли уже введенный логин
    if (checkExistingLogin(login)) {
        cout << "Пользователь с таким логином уже существует." << endl;
        return;
    }
    cout << "Придумайте пароль: ";
    string password;
    getline(cin, password);

    // Хеш пароля
    string hashedPassword = hashPassword(password);

    // логин и хеш пароля в файл
    ofstream outfile("users_md5.txt", ios::app);
    if (outfile.is_open()) {
        outfile << login << " " << hashedPassword << endl;
        outfile.close();
        cout << "Пользователь зарегистрирован." << endl;
    }
    else {
        cout << "Ошибка при открытии файла для записи." << endl;
    }
}

// Функция для аутентификации пользователей
void authentication_md5() {
    cout << "Введите логин: ";
    string login;
    getline(cin, login);

    cout << "Введите пароль: ";
    string password;
    getline(cin, password);

    // Хеш введенного пароля
    string hashedPassword = hashPassword(password);

    // Проверка наличия логина и хеша пароля в файле
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
            cout << "Авторизация успешна." << endl;
        }
        else {
            cout << "Неверный логин или пароль." << endl;
        }
    }
    else {
        cout << "Ошибка при открытии файла для чтения." << endl;
    }
}

int main() {
    setlocale(LC_ALL, "ru");
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);
    bool flag = true;
    while (flag) {
        cout << "Выберите действие:\n1. Регистрация\n2. Авторизация\n3. Выход\n";
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
            cout << "До свидания!\n";
            return 0;
        default:
            cout << "Неверный ввод. Попробуйте еще раз.\n";
        }
        flag = false;
    }
    return 0;
}