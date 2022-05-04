#include<iostream>
#include<math.h>
using namespace std;
// find gcd
int gcd(int a, int b) {
    int t;
    while (1) {
        t = a % b;
        if (t == 0)
            return b;
        a = b;
        b = t;
    }
}
int main()
{
    double message;
    cout << "Nhap message: ";
    cin >> message;
    //p, q, e de cho
    double p = 11;
    double q=17;
    double e = 7;
    double n = p * q;//calculate n
    cout << "\nGia tri n = " << n;
    double track;
    double phi = (p - 1) * (q - 1);//calculate phi
    cout << "\nphi = " << phi;
    //public key
    //for checking that 1 < e < phi(n) and gcd(e, phi(n)) = 1; i.e., e and phi(n) are coprime.
    while (e < phi)
    {
        track = gcd(e, phi);
        if (track == 1)
            break;
        else
            e++;
    }
    //private key
    //d stands for decrypt
    //choosing d such that it satisfies d*e = 1 mod phi(n)
    double d = 23;
    double c = pow(message, e); //encrypt the message
    double m = pow(c, d);
    c = fmod(c, n);
    m = fmod(m, n);
    cout << "\n" << "d = " << d;
    cout << "\n" << "Encrypted message = " << c;
    cout << "\n" << "Decrypted message = " << m << "\n";
    return 0;
}