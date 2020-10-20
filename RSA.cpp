#include "helper.cpp"
using Random = effolkronium::random_static;


////////////////////////////////////////////////////////////////////////////
/**                                                                       //
 * The following part is the encoding and decoding part                   //
 * Encoding: expand original plain message to the same length of n        //
 * Decoding: recover the plain message from the translated cipher message //
 */                                                                       //
////////////////////////////////////////////////////////////////////////////

/**
 * Encoding
 * M: plain text
 * n: modulus
 */
string Encoding(string M, BigInt n)
{
    // receiving octet string, convert to BigInt
    BigInt IM = stringToBigInt(M);
    
    // check length : message can't be too long
    BigInt t;
    t = IM;
    int bytesOfM = 1;
    while(t > 256) { t /= 256; bytesOfM ++;}

    t = n;
    int bytesOfN = 1;
    while(t > 256) { t /= 256; bytesOfN ++;}

    if(bytesOfM > bytesOfN - 11) throw invalid_argument("message too long");

    // EM: initially 0x00 || 0x02, which is 0x0002 = 2
    string EM = "";
    EM += "00";
    EM += "02";

    // PS: randomly generated Padding String
    string PS = "";
    int bytesOfPS = bytesOfN - bytesOfM - 3;
    for(int i = 0; i < bytesOfPS; i++)
    {
        // randByte: a random number in [1,255], representing a byte
        // notice: start from 1, as each byte is not allowed to be 0
        int randByte = Random::get(1,255); 
        int first = randByte / 16;
        int second = randByte % 16;
        PS += (first < 10 ? '0' + first : 'A' + first - 10);
        PS += (second < 10 ? '0' + second : 'A' + second - 10);
    }
    EM += PS;

    // EM: finally 0x00 || 0x02 || PS || 0x00 || M
    EM += "00";
    EM += M;
    

    return EM;
}

string Decoding(string EM)
{
    string ans;
    int pos = 2;
    while(pos + 2 < EM.length())
    {
        string thisOct = EM.substr(pos, 2);
        if(thisOct == "00")
        {
            ans = EM.substr(pos + 2, EM.length() - pos - 2);
            break;
        }
        pos += 2;
    }
    return ans;
}

//////////////////////////////////////////////////////////
/**                                                     //
 *  The following part is the Key Generation section    //
 *  p and q are fixed as two 132-bit prime number       //
 *  public key (exponent) e is fixed as 65537           //
 */                                                     //
//////////////////////////////////////////////////////////

typedef struct KeySet{
    BigInt e; // also the public key, recommended as 3(openssl) or 65537(PKCS#1) 
    BigInt d; // also the privare key
    BigInt n; // also the modulus, product of p and q
}KeySet;

typedef struct PrivateKey{
    BigInt d;
    BigInt n;
}PrivateKey;

typedef struct PublicKey{
    BigInt e;
    BigInt n;
}PublicKey;

KeySet GenerateKey()
{
    BigInt p("3615415881585117908550243505309785526231"); // a 132-bit prime
    BigInt q("4384165182867240584805930970951575013697"); // a 132-bit prime
    BigInt n = p * q;
    BigInt m = (p-1) * (q-1);

    KeySet ans;
    ans.n = n;
    ans.e = 65537; // choose e as 65537 (2 ^ 16 + 1)

    // getting private key d using EX_GCD
    EX_GCD ex_gcd = extended_euclidean(ans.e, m);
    ans.d = ex_gcd.s;

    // in case d is negative
    while(ans.d < 0) ans.d += m;
    return ans;
}


//////////////////////////////////////////////////////////////////
/**                                                             //
 *  The following part is the encryption and decryption section //
 */                                                             //
//////////////////////////////////////////////////////////////////

string encryption(PublicKey pk, string M)
{
    // do Encoding, remember length check
    string EM;
    try
    {
        EM = Encoding(M, pk.n);
    }
    catch(string e)
    {
        cerr << e << endl;
    }

    // convert octet string to BigInt
    BigInt m = stringToBigInt(EM);

    // do encryption
    BigInt c = bigPowMod(m, pk.e, pk.n);

    // convert to octed string
    string C = bigIntToString(c);

    return C;
}

string decryption(PrivateKey pk, string C)
{
    // convert octet string to BigInt
    BigInt c = stringToBigInt(C);

    // do decryption
    BigInt m = bigPowMod(c, pk.d, pk.n);

    // convert BigInt to octet string
    string EM = "000" + bigIntToString(m);

    // decode
    string M = Decoding(EM);
    
    return M;
}

