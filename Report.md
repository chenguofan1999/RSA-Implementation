# **RSA 设计报告**

# 原理描述

RSA 是一种非对称加密算法，一组 RSA 密钥包含一份私钥 (N, d) 和 公钥 (N, e). 其中公钥可以被公布，而私钥需要被珍藏。

事实上 d 和 e 在某种意义上是“对称”的 —— 你可以将其中任意一个认定为 d ，另一个则为 e 。 

N, e, d 之间有如下的数学关系： 

```
e * d mod ∮(N) = 1
```

对于攻击者而言，e 和 N 是已知的，若得到了∮(N)，则剩下的计算易如反掌。

### 计算 ∮(N)

∮(x) 指欧拉∮函数，表示小于或等于 x 的整数中有多少数与之互质。∮ 函数有如下特点：

- 当 x 为合数时，其计算极其复杂，而当 x 为素数时，∮(x) = x - 1。
- 当 p 和 q 为不同的质数时，∮(p * q) = ∮(p) * ∮(q)
- 亦即，当 p 和 q 为不同的质数时，∮(p * q) = (p - 1) * (q - 1)

因此，计算 ∮(N) 的问题转化为了对 N 进行因式分解，找到两个素数 p 和 q ，使 N = p * q, 则 ∮(N) = (p - 1) * (q - 1) .

而算法的可靠性则来源于，我们在选取 N 的时候是从选取两个极大(数百或数千位)的质数 p 和 q 出发，乘积得到 N ，这使得对 N 进行因式分解有且只有一组解，而这一组解的计算难度，在 N 有高达数百数千甚至上万位的情况下，无限接近于不可能。

### 加密和解密过程

私钥为 (N, d)，公钥为 (N, e)， 原文为 m，密文为 c

加密过程：

    c = m^e mod N

解密过程:

    m = c^d mod N

即发送者用公钥对信息进行加密，接收者用私钥对其进行解密。

加密和解密用到的计算正是该算法巧妙之处，用欧拉定理能简单地证明这两个等式。



# 数据结构设计

## 数据的表示


对于输入和输出的**字节流 (Octet stream)** ，只需要用含 '1' - 'F' 16种字符的 string 来表示。

在加密函数内部，数据之间的计算显然是在整数的形式下进行的，同时 RSA 算法要求能密钥是极大的大整数(数百甚至数千位)，因此需要选用一种能表示无限位数的整数，且要求实现乘法、取模等运算的数据结构。由于本次大整数的实现并非重点，我直接使用了 Github 上的一个用 c++ 实现的大整数，[这里是链接](https://github.com/faheel/BigInt)。

## 其他数据结构

用以下结构表示密钥，其中第一个用于生成密钥的函数的返回。

```cpp
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
```

以下结构表示扩展的欧几里得算法的返回值，用于生成密钥时计算私钥。
```cpp
typedef struct EX_GCD {
	BigInt s;
	BigInt t;
	BigInt gcd;
}EX_GCD;
```



# 密钥生成

密钥生成的函数如下，首先需要找到两个不太相近的极大素数 p 和 q，这里选取了两个 132 位的素数，主要的考量是当密钥长度过长时，解密的过程将十分漫长，不便测试。

由 p 和 q 计算出 N 和 ∮(N) ，这里用 m 表示 ∮(N) 。

公钥中的 e 在实践上有一些推荐的取值，例如 3,5,17,257,65537，选取更大的 e 会对加解密的时间产生细微的影响，使加密时间略微增加，解密时间略微缩短。


```cpp
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
```

确定 e 以后需要用扩展的欧几里得算法来求得私钥中的 d ,以下是该算法的函数：

```cpp
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
```

返回的 EX_GCD 结构中的 s 即满足 e*s mod ∮(N) = 1. 注意此时并不能确定 s 即为 d ，因为 s 可能为负数，由于 

    e * (s+∮(N)) = e*s + e*∮(N) 

与 e*s 模 ∮(N) 显然同余， 故可让 s 增大数个 ∮(N) ，不会影响 e\*s 模 ∮(N)的取值。当 s 变为正数，其值即为 d 。



# 编码和解码

为了抵抗攻击，RSA 算法实践上建议在加密前对数据进行填充，即编码，与之对应，在解密后也需要对数据进行解码。这个实现中使用的填充方案是 `RSAES-PKCS1-v1_5` 。

## 填充过程

M 表示填充前的信息， EM 表示填充后的信息。  
bytesOfM 表示填充前的长度， bytesOfN 表示密钥的 n 的长度，均以字节为单位。

    EM = 00 || 02 || PS || 00 || M

注意 EM 和 M 都是字节流的字符串形式，每一个字符都表示 16 进制的1位，两位一组表示一个字节 (因此也可以视为 256 进制的字节串) 。


PS 表示一定长度的随机数据，用于将 EM 填充至与密钥的 N 等长，由于其前后有三个已经确定的字节，因此 PS 的长度为 *bytesOfN - bytesOfM - 3* .

为了便于解密后去除填充的字符串，PS后有设置一个 0 字节作为标识字节，同时 PS 被要求不能含有 0 字节。

最前方的 0 字节亦有其用途，由于填充后 EM 与 N 等长，最高位字节为 0 保证了填充后的字符串对应的数值不会超过密钥的 N 的数值。

```cpp
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
```

## 解码过程

解码的函数非常简单，从第二个字节开始，遇到 0 字节即可取其后的字符串作为结果。

```cpp
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
```

## 辅助函数

用到了两个简单的辅助函数，用于字符串和大整数形式之间的转换。此后还会用到。
```cpp
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
```


# 加密和解密

## 辅助函数

加密和解密过程均会遇到形如 `a ^ b mod c` 的计算，且 b 的值会极大，若不加以优化此处的用时会成为整个算法的短板。这里的优化会使用到快速幂算法，这里将其实现作为辅助函数：

```cpp
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

```

## 加密

加密过程的输入是**公钥**和明文的**16进制的字符串** M ，返回值为密文的**16进制的字符串** C 。加密的流程如下：

1. 用填充函数 `Encoding` 将输入字符串填充为 N 位的字符串 EM
2. 将该 N 位的字符串转换为大整数 m
3. 计算 m ^ e mod N 得到密文的整数形式 c
4. 将 c 转换为16进制的字符串 C ，输出C

```cpp
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
```

## 解密

解密过程的输入是**私钥**和密文的**16进制的字符串** C ，返回值为明的**16进制的字符串** M 。解密的流程如下：

1. 将输入的16进制字符串 C 转换为对应大整数 c
2. 计算 c ^ d mod N 得到填充后的明文的大整数形式 m
3. 将 m 转换为字符串形式 EM
4. 用解码函数 `Decoding` 将 EM 解码为明文 M ，输出 M 



```cpp

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
```

# 测试

设计了一些具有代表性的边界数据测试，和一个随机的测试函数，详见 [test.cpp](test.cpp) .

注意由于RSA算法比较慢，每一个测例将会跑数秒，具体时间取决于您的电脑的计算能力。

一个测试的示例：
```
Start random testing, each test may take a few seconds.

Public  Key : (e, n) = (65537, 15850580429630744287493165806160404229518542335595893315529154728421396177786007)
Private Key : (d, n) = (3864874426133318487482502854607981134131535975363724712657461600195969519196673,
                        15850580429630744287493165806160404229518542335595893315529154728421396177786007)
Original : DF69249F
Cipher : 20340008FD5EEE62327A378790C8F316B7B03DC969DDC44CF2C12A4F1D84EE2176
Translated : DF69249F
Translate SUCCESS

Original : 7BFC50CE
Cipher : 1B83DE69FD86C5AF770B512647357176EFB591ACFF1C1E1C329E7FE00DA7CE7E02
Translated : 7BFC50CE
Translate SUCCESS

Original : 104462F3
Cipher : 47F3F1161BA2F4BDE32A5869F9CD2BCC922D2943F07E57CD2C4B215A8163579512
Translated : 104462F3
Translate SUCCESS

Original : 6590DDCA
Cipher : 72A68FB69DCBAD42E0D0D5AECD9BED1DB40A0BA76B747EA584EDC8E42C7DF04BED
Translated : 6590DDCA
Translate SUCCESS

Original : 7DFC4D92
Cipher : 7E0952C241319FC950F63A6463650D38184AD2AD61992EDF3ADFC9CDC76ACE293F
Translated : 7DFC4D92
Translate SUCCESS

Original : D3DECA97
Cipher : 8232F2D1C75B01CC2A4C3F8A5D1C2D06D786091D76F0CA509490EDE254672979FD
Translated : D3DECA97
Translate SUCCESS

Original : 756D85F1
Cipher : 4C20F471102A700D62DF27B49A04A17B98ECB2C24128EBCDFD8AD9B3A1370152D3
Translated : 756D85F1
Translate SUCCESS

Original : BB4CA71F
Cipher : 1E7E9D12BC99654D05B8A399840FA237BE20F5F7B2FF889D41D241F6E3C1E4EC21
Translated : BB4CA71F
Translate SUCCESS

Original : 0A355672
Cipher : 378B2A94A61F77648A054DAC9186A1AA84450C8967C596FBC34F43DEA708D0AEDB
Translated : 0A355672
Translate SUCCESS

Original : 6CF90B50
Cipher : 82702063D1757703E6FFA7FFED8C634B78428ECFB0B4DC6C29FE67640F4FCD94A
Translated : 6CF90B50
Translate SUCCESS
```
