#include <iostream>
#include <string>
#include <conio.h>
#include <algorithm>

using namespace std;

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