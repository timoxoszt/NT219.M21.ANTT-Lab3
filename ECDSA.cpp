/* Source, Sink */
#include <iomanip>
#include "cryptopp/modes.h"
#include <assert.h>
#include <iostream>
using std::endl;
using std::wcin;
using std::wcout;

#include <string>
using std::string;
using std::wstring;
using namespace std;

#include <sstream>
using std::ostringstream;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/integer.h"
#include "cryptopp/nbtheory.h"
using CryptoPP::Integer;

// Hash function
#include "cryptopp/sha.h"
#include "cryptopp/sha3.h"
using CryptoPP::SHA256;
using CryptoPP::SHA512;

// String filter
#include "cryptopp/filters.h"
using CryptoPP::ArraySink;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::SignerFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <ctime>

//Genererate keys
#include "cryptopp/cryptlib.h"
using CryptoPP::DecodingResult;
using CryptoPP::Exception;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;

/*Reading key input from file*/
#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

/* convert string stream */
#include <sstream>
using std::ostringstream;

// ECC crypto
#include "cryptopp/eccrypto.h"
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::ECDSA;
using CryptoPP::ECP;

#include <cryptopp/oids.h> 
namespace ASN1 = CryptoPP::ASN1;
using CryptoPP::OID;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

/* standard curves*/
#include <cryptopp/asn.h>

/*
***************************
*   SUPPORT VIETNAMESE   *
***************************
*/
#include <fcntl.h>
/* Convert string*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;


// Convert
wstring string_to_wstring(const std::string &str);
string wstring_to_string(const std::wstring &str);
wstring integer_to_wstring(const CryptoPP::Integer &t);
string integer_to_string(const CryptoPP::Integer &t);
string integer_to_hex(const CryptoPP::Integer &t);

#include "cryptopp/oids.h"
using CryptoPP::OID;

bool GeneratePrivateKey(const OID &oid, ECDSA<ECP, SHA256>::PrivateKey &key);
bool GeneratePublicKey(const ECDSA<ECP, SHA256>::PrivateKey &privateKey, ECDSA<ECP, SHA256>::PublicKey &publicKey);

void SavePrivateKey(const string &filename, const ECDSA<ECP, SHA256>::PrivateKey &key);
void SavePublicKey(const string &filename, const ECDSA<ECP, SHA256>::PublicKey &key);
void LoadPrivateKey(const string &filename, ECDSA<ECP, SHA256>::PrivateKey &key);
void LoadPublicKey(const string &filename, ECDSA<ECP, SHA256>::PublicKey &key);

void PrintDomainParameters(const ECDSA<ECP, SHA256>::PrivateKey &key);
void PrintDomainParameters(const ECDSA<ECP, SHA256>::PublicKey &key);
void PrintDomainParameters(const DL_GroupParameters_EC<ECP> &params);
void PrintPrivateKey(const ECDSA<ECP, SHA256>::PrivateKey &key);
void PrintPublicKey(const ECDSA<ECP, SHA256>::PublicKey &key);

bool SignMessage(const ECDSA<ECP, SHA256>::PrivateKey &key, const string &message, string &signature);
bool VerifyMessage(const ECDSA<ECP, SHA256>::PublicKey &key, const string &message, const string &signature);

void signingFunction();
void verifyFunction();
//////////////////////////////////////////
// In 2010, use SHA-256 and P-256 curve
//////////////////////////////////////////

int main(int argc, char *argv[])
{
#ifdef __linux__
    setlocale(LC_ALL, "");
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif
    int mode;
    wcout << L"===== Vui lòng chọn chức năng =====" << endl;
    wcout << L" 1.Tạo key \n 2.Tạo chữ kí số \n 3.Kiểm tra chữ kí số \n";
    wcout << L"Chọn: ";
    fflush(stdin);
    wcin >> mode;

    switch (mode)
    {
    case 1:
    {
        wcout << L"---- Tạo key ----" << endl;
        AutoSeededRandomPool prng;

        ECDSA<ECP, SHA256>::PrivateKey privateKey;
        ECDSA<ECP, SHA256>::PublicKey publicKey;

        GeneratePrivateKey(CryptoPP::ASN1::secp256r1(), privateKey);
        GeneratePublicKey(privateKey, publicKey);

        PrintDomainParameters(publicKey);
        PrintPrivateKey(privateKey);
        PrintPublicKey(publicKey);
        SavePrivateKey("ecc.private.der", privateKey);
        SavePublicKey("ecc.public.der", publicKey);
        break;
    }
    case 2:
    {
        wcout  <<  L"---- Tạo chữ kí số ----"  <<  endl;
        signingFunction();       
        break;
    }
    case 3:
    {
        wcout << L"---- Kiểm tra văn bản ----" << endl;
        verifyFunction();
        break;
    }
    default:
        break;
    }
    return 0;
}

bool GeneratePrivateKey(const OID &oid, ECDSA<ECP, SHA256>::PrivateKey &key)
{
    AutoSeededRandomPool prng;

    key.Initialize(prng, oid);
    assert(key.Validate(prng, 3));

    return key.Validate(prng, 3);
}

bool GeneratePublicKey(const ECDSA<ECP, SHA256>::PrivateKey &privateKey, ECDSA<ECP, SHA256>::PublicKey &publicKey)
{
    AutoSeededRandomPool prng;

    // Check key
    assert(privateKey.Validate(prng, 3));

    privateKey.MakePublicKey(publicKey);
    assert(publicKey.Validate(prng, 3));

    return publicKey.Validate(prng, 3);
}

void PrintDomainParameters(const ECDSA<ECP, SHA256>::PrivateKey &key)
{
    PrintDomainParameters(key.GetGroupParameters());
}

void PrintDomainParameters(const ECDSA<ECP, SHA256>::PublicKey &key)
{
    PrintDomainParameters(key.GetGroupParameters());
}

void PrintDomainParameters(const DL_GroupParameters_EC<ECP> &params)
{
    wcout << endl;

    wcout << "Modulus:" << endl;
    wcout << " " << integer_to_wstring(params.GetCurve().GetField().GetModulus()) << endl;

    wcout << "Coefficient A:" << endl;
    wcout << " " << integer_to_wstring(params.GetCurve().GetA()) << endl;

    wcout << "Coefficient B:" << endl;
    wcout << " " << integer_to_wstring(params.GetCurve().GetB()) << endl;

    wcout << "Base Point:" << endl;
    wcout << " X: " << integer_to_wstring(params.GetSubgroupGenerator().x) << endl;
    wcout << " Y: " << integer_to_wstring(params.GetSubgroupGenerator().y) << endl;

    wcout << "Subgroup Order:" << endl;
    wcout << " " << integer_to_wstring(params.GetSubgroupOrder()) << endl;

    wcout << "Cofactor:" << endl;
    wcout << " " << integer_to_wstring(params.GetCofactor()) << endl;
}

void PrintPrivateKey(const ECDSA<ECP, SHA256>::PrivateKey &key)
{
    wcout << endl;
    wcout << "Private Exponent:" << endl;
    wcout << " " << integer_to_wstring(key.GetPrivateExponent()) << endl;
}

void PrintPublicKey(const ECDSA<ECP, SHA256>::PublicKey &key)
{
    wcout << endl;
    wcout << "Public Element:" << endl;
    wcout << " X: " << integer_to_wstring(key.GetPublicElement().x) << endl;
    wcout << " Y: " << integer_to_wstring(key.GetPublicElement().y) << endl;
}

void SavePrivateKey(const string &filename, const ECDSA<ECP, SHA256>::PrivateKey &key)
{
    key.Save(FileSink(filename.c_str(), true /*binary*/).Ref());
}

void SavePublicKey(const string &filename, const ECDSA<ECP, SHA256>::PublicKey &key)
{
    key.Save(FileSink(filename.c_str(), true /*binary*/).Ref());
}

void LoadPrivateKey(const string &filename, ECDSA<ECP, SHA256>::PrivateKey &key)
{
    key.Load(FileSource(filename.c_str(), true /*pump all*/).Ref());
}

void LoadPublicKey(const string &filename, ECDSA<ECP, SHA256>::PublicKey &key)
{
    key.Load(FileSource(filename.c_str(), true /*pump all*/).Ref());
}

bool SignMessage(const ECDSA<ECP, SHA256>::PrivateKey &key, const string &message, string &signature)
{
    AutoSeededRandomPool prng;

    signature.erase();

    StringSource(message, true,
                 new SignerFilter(prng,
                                  ECDSA<ECP, SHA256>::Signer(key),
                                  new StringSink(signature)) // SignerFilter
    );                                                       // StringSource

    return !signature.empty();
}

bool VerifyMessage(const ECDSA<ECP, SHA256>::PublicKey &key, const string &message, const string &signature)
{
    bool result = false;

    StringSource(signature + message, true,
                 new SignatureVerificationFilter(
                     ECDSA<ECP, SHA256>::Verifier(key),
                     new ArraySink((byte *)&result, sizeof(result))) // SignatureVerificationFilter
    );

    return result;
}

/* convert string to wstring */
wstring string_to_wstring(const std::string &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string(const std::wstring &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}
// Conver integer to string and wstring;
wstring integer_to_wstring(const CryptoPP::Integer &t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;
    std::string encoded(oss.str());
    std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(encoded);
}

string integer_to_string(const CryptoPP::Integer &t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;
    std::string encoded(oss.str());
    return encoded;
}

string integer_to_hex(const CryptoPP::Integer &t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << std::hex << t;
    std::string encoded(oss.str());
    return encoded;
}
void signingFunction()
{
    string signature, encode;

    /* load message to sign */
    string message;
    FileSource("message.txt", true, new StringSink(message));
    wcout << L"*** Dữ liệu nhập vào từ file "<< endl;
    wcout << string_to_wstring(message) << endl;

    int message_size = sizeof(message);

    ECDSA<ECP, SHA256>::PrivateKey privateKeys;

    LoadPrivateKey("ecc.private.der", privateKeys);
    //Print system parmeters
    wcout << "Prime number p=" << integer_to_wstring(privateKeys.GetGroupParameters().GetCurve().GetField().GetModulus()) << endl;
    wcout << "Secret key d:" << integer_to_wstring(privateKeys.GetPrivateExponent()) << endl;

    /* Siging message
     - shor-term key (k, k.G);
     - 0 < k < n; kG = (x1, y1), r=x1;
     - compute (r,s)
     s= k^-1(H(m)+ d.r) mod n;
     output (r, s); 
     */
    int start_s = clock();
    for (int i = 0; i < 100; i++)
    {
        AutoSeededRandomPool prng;
        signature.erase();
        StringSource(message, true,
                     new SignerFilter(prng,
                                      ECDSA<ECP, SHA256>::Signer(privateKeys),
                                      new Base64Encoder(new StringSink(signature))));
    }
    int stop_s = clock();
    double total = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 100;
    wcout << "signature (r,s):" << string_to_wstring(signature) << endl;
    wcout << L"Kiểm tra sau 100 lần chạy: " << total << " ms" << endl;
    wcout << L"Thời gian thực thi trung bình: " << total / 100 << " ms" << endl;
}
void verifyFunction()
{
    string signature, encode;
    bool result;
    result = false;
    // Public key variable
    ECDSA<ECP, SHA256>::PublicKey publicKey_r;
    ECDSA<ECP, SHA256>::PrivateKey privateKeys;

    LoadPublicKey("ecc.public.der", publicKey_r);
    // Load public key
    string message_r, signature_r;
    // Message m, sinnature (r,s);
    FileSource("message1.txt", true, new StringSink(message_r));
    AutoSeededRandomPool prng;
    LoadPrivateKey("ecc.private.der", privateKeys);

    string message;
    FileSource("message.txt", true, new StringSink(message));
    signature.erase();
    StringSource(message, true,
                 new SignerFilter(prng,
                                  ECDSA<ECP, SHA256>::Signer(privateKeys),
                                  new Base64Encoder(new StringSink(signature))));
    cout << "Signature on message m=" << signature.data() << endl;

    // Hex decode signature
    StringSource ss(signature, true,
                    new Base64Decoder(
                        new StringSink(signature_r)) // HexDecoder
    );
    int start_s = clock();
    for (int i = 0; i < 100; i++)
    { //
        result = VerifyMessage(publicKey_r, message_r, signature_r);
    }
    int stop_s = clock();
    double total = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;
    
    string check_status;

    if(result == 1){
        wcout << L"Xác minh chữ kí số: Chính xác" << endl;
    } else{
        wcout << L"Xác minh chữ kí số: Không chính xác" << endl;
    }

    wcout << L"Kiểm tra sau 100 lần chạy: " << total << " ms" << endl;
    wcout << L"Thời gian thực thi trung bình: " << total / 100 << " ms" << endl;
}