#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <windows.h>

using namespace std;
//Две функции для обратного перемешивания
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

// Функция для сдвига строки на 4
string shiftString(const string& str, int offset) {
    string shifted = str;
    int length = shifted.length();
    offset = offset % length; // сдвиг был в пределах длины строки

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

// Функция для перемешивания строки
string shuffleString(const string& str) {
    string shifted = shiftString(str, 4); // Сдвигаем строку на 4 символа
    int length = shifted.length();
    string result = shifted;
    int middle = length / 2;
    // Меняем местами символы до центрального символа с символами после центрального
    for (int i = 0; i < middle; ++i) {
        char temp = result[i];
        result[i] = result[middle + length % 2 + i];
        result[middle + length % 2 + i] = temp;
    }

    return result;
}

// Функция для регистрации новых пользователей
void registration_encrypted() {
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

    // Составляем строку для записи
    string combined = login + "$" + password;
    // Перемешиваем строку
    string encrypted = shuffleString(combined);

    // Записываем логин и пароль в файл
    ofstream outfile("users_algorithm.txt", ios::app);
    if (outfile.is_open()) {
        outfile << encrypted << endl;
        outfile.close();
        cout << "Пользователь зарегистрирован." << endl;
    }
    else {
        cout << "Ошибка при открытии файла для записи." << endl;
    }
}

void authentication_algorithm() {

    cout << "Введите логин: ";
    string login;
    getline(cin, login);

    cout << "Введите пароль: ";
    string password;
    getline(cin, password);

    string combined = login + "$" + password;

    string str_searching = shuffleString(combined);

    // Проверка наличия логина и пароля в файле
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
        cin.ignore(); // Очистка буфера ввода

        switch (choice) {
        case 1:
            registration_encrypted();
            break;
        case 2:
            authentication_algorithm();
            break;
        case 3:
            cout << "До свидания!\n";
            break;
        default:
            cout << "Неверный ввод. Попробуйте еще раз.\n";
        }
        flag = false;
    }

    return 0;
}