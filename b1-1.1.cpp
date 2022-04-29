#include <iostream>
#include <cstdlib>
#include <math.h>
using namespace std;

//Ham random so
string randomnum(int bytes)
{
	string num;
	int len = log10(pow(2, bytes * 8)) + 1;

	for (int i = 0; i < len; i++)
	{
		int randnum = rand() % 10;
		if (i == 0) 
		{
			while (randnum == 0)
			{
				randnum = rand() % 10;
			}
		}
		num = num + (char)(randnum + 48);

	}
	return num;
}

int main()
{
	cout << "4 bytes number: " << randomnum(4) << "\n";
	cout << "8 bytes number: " << randomnum(8) << "\n";
	cout << "32 bytes number: " << randomnum(32) << "\n";
	return 0;
}