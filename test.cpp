#include "RSA.cpp"
using namespace std;

void test(string M, const KeySet& keys)
{
    PublicKey public_key = {keys.e, keys.n};
    PrivateKey private_key = {keys.d, keys.n};
    
    string plain = M;
    cout << "Original : " << plain << endl;

    string C = encryption(public_key, plain);
    cout << "Cipher : "<< C << endl;

    string R = decryption(private_key, C);
    cout << "Translated : " << R << endl;

    if(plain == R) cout<<"Translate success"<<endl;
    else cout<<"Translate failure"<<endl;
    
    cout<<endl;
}


void tests()
{
    KeySet keys = GenerateKey();

    cout<<"Start testing, each test may take a few seconds.\n"<<endl;
    cout<<"Public  Key : (e, n) = (" << keys.e << ", "<<keys.n<<")"<<endl;
    cout<<"Private Key : (d, n) = (" << keys.d << ", \n\t\t\t"<<keys.n<<")"<<endl;

    string testCases[] = {"0", "1", "2A", "1FA", "5ABCD8", "BBBBBBBB",
                        "10000DDD00", "80000000000000000000000000CCC",
                        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "1234567890ABCD1234567890ABCD123456"};

    for(string m : testCases)
    {
        test(m, keys);
    }

    cout << "The last test should terminate with an error : message too long:" << endl;
    string toLongCase = "9999999999999999999999999999999999999999999999999999";
    test(toLongCase, keys);
}

void randomTest()
{
    KeySet keys = GenerateKey();

    cout<<"Start random testing, each test may take a few seconds.\n"<<endl;
    cout<<"Public  Key : (e, n) = (" << keys.e << ", "<<keys.n<<")"<<endl;
    cout<<"Private Key : (d, n) = (" << keys.d << ", \n\t\t\t"<<keys.n<<")"<<endl;


    int numberOfBits = 8;
    int testCaseNumber = 10;

    for(int i = 0; i < testCaseNumber; i++)
    {
        string s = "";
        for(int j = 0; j < numberOfBits; j++)
        {
            int t = Random::get(0, 15);
            char c = t < 10 ? '0' + t : 'A' + t - 10;
            s += c;
        }
        test(s, keys);
    }
}

int main()
{
    // tests();
    randomTest();
}


