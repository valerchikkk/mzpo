#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
using namespace std;

// Функция для проверки существования логина в файле
bool checkExistingLogin(const string& login) {
    ifstream infile("users_numbers.txt");
    if (infile.is_open()) {
        string storedLogin, storedPassword;
        while (infile >> storedLogin >> storedPassword) {
            if (login == storedLogin) {
                infile.close();
                return true; // Логин найден
            }
        }
        infile.close();
    }
    return false; // Логин не найден
}

// Функция для регистрации новых пользователей
void registration_numbers() {
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

    int sum = 0;
    int totalChars = login.length() + password.length(); // общее количество символов
    for (char ch : login) {
        sum += static_cast<int>(ch) * totalChars;
    }
    for (char ch : password) {
        sum += static_cast<int>(ch) * totalChars;
    }


    // Записываем логин и пароль в файл
    ofstream outfile("users_numbers.txt", ios::app);
    if (outfile.is_open()) {
        outfile << login << " " << sum << endl;
        outfile.close();
        cout << "Пользователь зарегистрирован." << endl;
    }
    else {
        cout << "Ошибка при открытии файла для записи." << endl;
    }
}

// Функция для аутентификации пользователей
void authentication_numbers() {
    cout << "Введите логин: ";
    string login;
    getline(cin, login);

    cout << "Введите пароль: ";
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


    // Проверяем наличие логина и пароля в файле
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
            registration_numbers();
            break;
        case 2:
            authentication_numbers();
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


    