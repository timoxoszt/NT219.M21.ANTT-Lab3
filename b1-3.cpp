#include <iostream>
using namespace std;

int cal(int a, int x, int p)      // a * b ≡ [(a mod n) * (b mod n)] mod n
{
    int res = 1;
    while (x > 0)
    {
        res *= a;
        res %= p;
        x--;
    }
    return res;
}


int main()
{
    int a, x, p;
    cout << "Nhap a, x, p: ";   cin >> a >> x >> p;
    cout << "a^x mod p = " << cal(a, x, p) << endl;
}
