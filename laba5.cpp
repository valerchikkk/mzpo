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

// Функция для создания хеша пароля
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
    cout << "Введите старый пароль: ";
    string oldPassword = inputPassword();
    if (users[username].password == hashPassword(oldPassword)) {
        string newPassword, confirmPassword;
        cout << "Новый пароль: ";
        newPassword = inputPassword();
        cout << "Повторите новый пароль: ";
        confirmPassword = inputPassword();
        if (newPassword == confirmPassword) {
            if (users[username].passwordRestrictions && newPassword.length() < 8) {
                cout << "Минимальная длина пароля - 8 символов.\n";
                return false;
            }
            users[username].password = hashPassword(newPassword);
            saveUsers();
            cout << "Пароль изменён.\n";
            return true;
        }
        else {
            cout << "Пароли не совпадают.\n";
        }
    }
    else if(username == "admin" && hashPassword(oldPassword) == adminPassword) {
        string newPassword, confirmPassword;
        cout << "Новый пароль: ";
        newPassword = inputPassword();
        cout << "Повторите новый пароль: ";
        confirmPassword = inputPassword();
        if (newPassword == confirmPassword) {
            adminPassword = hashPassword(newPassword);
            cout << "Пароль изменён.\n";
        }
        else {
            cout << "Пароли не совпадают.\n";
        }
    }
    else {
        cout << "Неправильный старый пароль.\n";
    }
        
    
    return false;
}

void passwordNewUser(const string& username) {
    string newPassword, confirmPassword;
    cout << "Новый пароль: ";
    newPassword = inputPassword();
    cout << "Повторите новый пароль: ";
    confirmPassword = inputPassword();
    if (newPassword == confirmPassword) {
        if (users[username].passwordRestrictions && newPassword.length() < 8) {
            cout << "Минимальная длина пароля - 8 символов.\n";
            passwordNewUser(username);
        }
        else {
            users[username].password = hashPassword(newPassword);
            saveUsers();
            cout << "Пароль изменён.\n";
        }
    }
    else {
        cout << "Пароли не совпадают.\n";
        passwordNewUser(username);
    }
}

void showUsers() {
    for (const auto& pair : users) {
        cout << "Имя пользователя: " << pair.first << " | Заблокирован: " << pair.second.isBlocked
            << " | Ограничения на пароль: " << pair.second.passwordRestrictions << "\n";
    }
}

void addUser(const string& username) {
    if (users.find(username) == users.end()) {
        users[username] = { "", false, false };
        saveUsers();
        cout << "Пользователь добавлен.\n";
    }
    else {
        cout << "Пользователь уже существует.\n";
    }
}

void blockUnblockUser(const string& username) {
    if (users.find(username) != users.end()) {
        users[username].isBlocked = !users[username].isBlocked;
        if (users[username].isBlocked == true)
        {
            cout << "Пользователь заблокирован.\n";
        }
        else
        {
            cout << "Пользователь разблокирован.\n";
        }
        saveUsers();
        
    }
    else {
        cout << "Пользователь не существует.\n";
    }
}

void OnOffPasswordRestrictions(const string& username) {
    if (users.find(username) != users.end()) {
        users[username].passwordRestrictions = !users[username].passwordRestrictions;
        if (users[username].passwordRestrictions == true)
        {
            cout << "Ограничения на пароль включены.\n";
        }
        else
        {
            cout << "Ограничения на пароль выключены.\n";
        }
        saveUsers();
        
    }
    else {
        cout << "Пользователь не существует.\n";
    }
}

void adminMenu() {
    while (true) {
        cout << "1. Сменить пароль администратора\n";
        cout << "2. Просмотреть список пользователей\n";
        cout << "3. Добавить нового пользователя\n";
        cout << "4. Заблокировать/разблокировать пользователя\n";
        cout << "5. Ограничить/убрать ограничения на пароль пользователя\n";
        cout << "6. Выход\n";
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
            cout << "Введите имя пользователя: ";
            getline(cin, username);
            addUser(username);
        }
        else if (choice == 4) {
            string username;
            cout << "Введите имя пользователя: ";
            getline(cin, username);
            blockUnblockUser(username);
        }
        else if (choice == 5) {
            string username;
            cout << "Введите имя пользователя: ";
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
        cout << "1. Смена пароля\n";
        cout << "2. Выход\n";
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
        cout << "Введите имя пользователя: ";
        getline(cin, username);
        attempts = 3;

        while (true) {
            if (username == "admin") {
                cout << "Введите пароль: ";
                password = inputPassword();
                if (hashPassword(password) == adminPassword) {
                    adminMenu();
                    break;
                }
                else {
                    cout << "Неверный пароль.\n";
                    attempts -= 1;
                    cout << "Осталось попыток: " << attempts << endl;
                    if (attempts == 0) {
                        cout << "Неудачная попытка входа.\n";
                        return 0;
                    }
                }
            }
            else if (users.find(username) != users.end()) {
                if (users[username].password.empty()) {
                    cout << "Вам необходимо задать новый пароль.\n";
                    passwordNewUser(username);
                }
                else {
                    cout << "Введите пароль: ";
                    password = inputPassword();
                    if (users[username].isBlocked) {
                        cout << "Пользователь заблокирован.\n";
                        break;
                    }
                    else if (users[username].password == hashPassword(password)) {
                        userMenu(username);
                        break;
                    }
                    else {
                        cout << "Неверный пароль.\n";
                        attempts -= 1;
                        cout << "Осталось попыток: " << attempts << endl;
                        if (attempts == 0) {
                            cout << "Неудачная попытка входа.\n";
                            return 0;
                        }
                    }
                }
            }
            else {
                cout << "Пользователь не существует.\n";
                char choice;
                cout << "Попробовать снова (y/n)? ";
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