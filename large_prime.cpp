#include <iostream>
#include<stdlib.h>
#include <random>
#include <boost/multiprecision/cpp_int.hpp>
// sudo apt-get install libboost-all-dev
using namespace boost::multiprecision;
using namespace std;

int128_t mySignedInt128 = -1;
uint128_t myUnsignedInt128 = 2;
int256_t mySignedInt256 = -3;
uint256_t myUnsignedInt256 = 4;
int512_t mySignedInt512 = -5;
uint512_t myUnsignedInt512 = 6;
int1024_t mySignedInt1024 = -7;
uint1024_t myUnsignedInt1024 = 8;

#define ll long long
using namespace std;

ll gcdExtended(ll a, unsigned  long long b, ll* x, ll* y)
{
	// Base Case
	if (a == 0) 
	{
		*x = 0;
		*y = 1;
		return b;
	}
	ll x1, y1; // To store results of recursive call
	ll gcd = gcdExtended(b % a, a, &x1, &y1);
	// Update x and y using results of recursive
	// call
	*x = y1 - (b / a) * x1;
	*y = x1;
	return gcd;
}

ll mulmod(ll a, ll b, ll m){
  ll x = 0,y = a % m;
  while (b > 0) {
    if (b % 2 == 1) {
      x = (x + y) % m;
    }
    y = (y * 2) % m;
    b /= 2;
  }
  return x % m;
}

ll modulo(ll base, ll e, ll m) {
  ll x = 1;
  ll y = base;
  while (e > 0) {
    if (e % 2 == 1)
      x = (x * y) % m;
      y = (y * y) % m;
      e = e / 2;
   }
  return x % m;
}

bool Miller(ll p, int iteration) {
  if (p < 2) {
    return false;
  }
  if (p != 2 && p % 2==0) {
    return false;
  }
  ll s = p - 1;
  while (s % 2 == 0) {
    s /= 2;
  }
  for (int i = 0; i < iteration; i++) {
    ll a = rand() % (p - 1) + 1, temp = s;
    ll mod = modulo(a, temp, p);
    while (temp != p - 1 && mod != 1 && mod != p - 1) {
      mod = mulmod(mod, mod, p);
      temp *= 2;
    }
    if (mod != p - 1 && temp % 2 == 0) {
      return false;
    }
  }
  return true;
}



ll return_prime(){
	  /* Seed */
  std::random_device rd;

  /* Random number generator */
  std::default_random_engine generator(rd());

  /* Distribution on which to apply the generator */
  /* 2 byte */
  std::uniform_int_distribution<long long unsigned> distribution2byte(-8000,8000);
  /* 8 byte*/
  std::uniform_int_distribution<long long unsigned> distribution8byte(-8000000000000000,8000000000000000);
  /*32 byte*/
  //std::uniform_int_distribution<int256_t> distribution32byte(-1000000000000000000,100000000000000000000000000000);
 for (int i=0;;++i){
	ll num2byte1 = distribution2byte(generator);
  ll num2byte2 = distribution2byte(generator);
    int iteration = 10;
    if (Miller(num2byte1, iteration) && Miller(num2byte2, iteration) ){
      cout <<"2 byte prime number 1: " <<num2byte1<<endl;
      cout <<"2 byte prime number 2: " <<num2byte2<<endl;      	
      break;
    }
  }

   for (int i=0;;++i){
	ll num8byte1 = distribution8byte(generator);
	ll num8byte2 = distribution8byte(generator);
    int iteration = 10;
     if (Miller(num8byte1, iteration) && Miller(num8byte2, iteration) ){
      cout <<"8 byte prime number 1: " <<num8byte1<<endl;
      cout <<"8 byte prime number 2: " <<num8byte2<<endl;
      break;
    }
  }
  return 0;
}


int main(){
  return_prime();    
  ll num1,num2;
  cout << "num 1: ";
  cin>>num1;
  cout<<"num2: ";
  cin>>num2;
   ll z, u;
  	      cout << "gcd:  " << gcdExtended(num1, num2, &z, &u) << endl;
	      cout << endl;
  return 0;
}