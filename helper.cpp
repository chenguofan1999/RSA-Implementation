#include "include/BigInt.hpp"
#include "include/effolkronium/random.hpp"
#include <iostream>
using namespace std;


typedef struct EX_GCD {
	BigInt s;
	BigInt t;
	BigInt gcd;
}EX_GCD;

// Extended Euclidean algorithm
EX_GCD extended_euclidean(BigInt a, BigInt b) {
	EX_GCD ex_gcd;
	if (b == 0) 
    { 
		ex_gcd.s = 1;
		ex_gcd.t = 0;
		ex_gcd.gcd = 0;
		return ex_gcd;
	}
	BigInt old_r = a, r = b;
	BigInt old_s = 1, s = 0;
	BigInt old_t = 0, t = 1;
	while (r != 0) 
    { 
		BigInt q = old_r / r;
		BigInt temp = old_r;
		old_r = r;
		r = temp - q * r;
		temp = old_s;
		old_s = s;
		s = temp - q * s;
		temp = old_t;
		old_t = t;
		t = temp - q * t;
	}
	ex_gcd.s = old_s;
	ex_gcd.t = old_t;
	ex_gcd.gcd = old_r;
	return ex_gcd;
}

// Calculate a ^ b mod m
BigInt bigPowMod(BigInt a, BigInt b, BigInt m)
{
    a %= m;
    BigInt ans = 1;
    while(b > 0)
    {
        if(b % 2 == 1) ans = ans * a % m;
        a = a * a % m;
        b /= 2;
    }
    return ans;
}


// octet string to BigInt
BigInt stringToBigInt(string octets)
{
	BigInt ans = 0;
	for(char c : octets)
    {
        BigInt curr;
        if(c >= '0' && c <= '9') curr = c - '0';
        else curr = 10 + c - 'A';
        ans = ans * 16 + curr;
    }
	return ans;
}

// BigInt to octet string
string bigIntToString(BigInt num)
{
	string ans;
	while(num > 0)
	{
		int curr = (num % 16).to_int();
		ans += (curr < 10? '0' + curr : 'A' + curr -10);
		num /= 16;
	}
	return string(ans.rbegin(), ans.rend());
}