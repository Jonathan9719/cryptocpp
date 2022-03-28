#include "cryptlib.h"       // encryption library
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"
#include <windows.h>        // For the amount of data used
#include <Psapi.h>          // For the amount of data used
#include <algorithm>        // For the timing process
#include <chrono>           // For the timing process
#include <fstream>          // Read a file
#include <iostream>         
#include <string>
#include "camellia.h"       // The different encryption algorithms
#include "chacha.h"
#include "secblock.h"
#include "rabbit.h"
#include "rc6.h"

using namespace std;
using namespace std::chrono;    // Again for the timer
using namespace CryptoPP;

// Read a file from the name given and give back a string with contents
string readFile(string fileName) {
    string line;
    string text;
    ifstream fin(fileName);

    if (fin.is_open())
    {
        while (getline(fin, line))
        {
            text.append(line);
        }
        fin.close();
    }
    else cout << "Unable to open file" << endl;

    return text;
}

//  The Aes Encryption function. Takes a string encrypts and decrypts it,
//  displays the time taken and storage taken along with some other info
void aesEncryption(string fileName) {
    // Read a file for text to be changing
    string text = readFile(fileName);
    cout << "Running Aes Encryption" << endl;

    // Setup prng, encoder, key, and iv. Along with our memory counter
    PROCESS_MEMORY_COUNTERS memCounter;
    AutoSeededRandomPool prng;
    HexEncoder encoder(new FileSink(std::cout));

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);

    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    // A portion of the starting string set up cipher and recovered 
    // for later display
    string sample = text.substr(0,20);
    string cipher, recovered;

    cout << "plain text: " << sample << endl;

    // Get starting timepoint
    auto start = high_resolution_clock::now();

    // Encrypt the text block
    try
    {
        CBC_Mode< AES >::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        StringSource s(text, true,
            new StreamTransformationFilter(e,
                new StringSink(cipher)
            ) // StreamTransformationFilter
        ); // StringSource
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Get ending timepoint
    auto stop = high_resolution_clock::now();

    // Get the size of data used
    BOOL result = K32GetProcessMemoryInfo(GetCurrentProcess(), &memCounter, sizeof(memCounter));
    cout << "WorkingSetSize " << memCounter.WorkingSetSize << endl;

    // Get the amount of time used
    auto duration = duration_cast<microseconds>(stop - start);

    cout << "Time taken by function: "
        << duration.count() << " microseconds" << endl;

    // Decode the encrypted block
    try
    {
        CBC_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);

        StringSource s(cipher, true,
            new StreamTransformationFilter(d,
                new StringSink(recovered)
            ) // StreamTransformationFilter
        ); // StringSource

        string sample2 = recovered.substr(0, 20);

        cout << "recovered text: " << sample2 << endl << endl;
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}

//  The Camellia Encryption function. Takes a string encrypts and decrypts it,
//  displays the time taken and storage taken along with some other info
void camelliaEncryption(string fileName) {
    // Read a file for text to be changing
    string text = readFile(fileName);
    cout << "Running camellia Encryption" << endl;

    // Setup prng, encoder, key, and iv. Along with our memory counter
    PROCESS_MEMORY_COUNTERS memCounter;
    AutoSeededRandomPool prng;

    SecByteBlock key(Camellia::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    byte iv[Camellia::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    string sample = text.substr(0,20);
    string cipher, encoded, recovered;
    cout << "plain text: " << sample << endl;

    // Get starting timepoint
    auto start = high_resolution_clock::now();

    // Encrypt the text block
    try
    {
        CBC_Mode< Camellia >::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource(text, true,
            new StreamTransformationFilter(e,
                new StringSink(cipher)
            ) // StreamTransformationFilter
        ); // StringSource
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Get ending timepoint
    auto stop = high_resolution_clock::now();

    // Get the size of data used
    BOOL result = K32GetProcessMemoryInfo(GetCurrentProcess(), &memCounter, sizeof(memCounter));
    cout << "WorkingSetSize " << memCounter.WorkingSetSize << std::endl;

    // Get the amount of time used
    auto duration = duration_cast<microseconds>(stop - start);

    cout << "Time taken by function: "
        << duration.count() << " microseconds" << endl;

    // Decode the encrypted block
    try
    {
        CBC_Mode< Camellia >::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
            new StreamTransformationFilter(d,
                new StringSink(recovered)
            ) // StreamTransformationFilter
        ); // StringSource

        string sample2 = recovered.substr(0, 20);
        cout << "recovered text: " << sample2 << endl << endl;
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}

//  The CHaCha Encryption function. Takes a string encrypts and decrypts it,
//  displays the time taken and storage taken along with some other info
void chachaEncryption(string fileName) {
    // Read a file for text to be changing
    string text = readFile(fileName);
    cout << "Running chacha Encryption" << endl;

    // Setup prng, encoder, key, and iv. Along with our memory counter
    HexEncoder encoder(new FileSink(std::cout));

    AutoSeededRandomPool prng;
    PROCESS_MEMORY_COUNTERS memCounter;

    SecByteBlock key(32), iv(8);
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    string sample = text.substr(0, 20);
    string cipher, recover;
    cout << "plain text: " << sample << endl;

    // Get starting timepoint
    auto start = high_resolution_clock::now();

    // Perform the encryption
    try 
    {
        // Encryption object
        ChaCha::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), iv, iv.size());

        // Perform the encryption
        cipher.resize(text.size());
        enc.ProcessData((byte*)&cipher[0], (const byte*)text.data(), text.size());
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Get ending timepoint
    auto stop = high_resolution_clock::now();

    // Get the size of data used
    BOOL result = K32GetProcessMemoryInfo(GetCurrentProcess(), &memCounter, sizeof(memCounter));
    cout << "WorkingSetSize " << memCounter.WorkingSetSize << std::endl;

    // Get the amount of time used
    auto duration = duration_cast<microseconds>(stop - start);

    cout << "Time taken by function: "
        << duration.count() << " microseconds" << endl;


    // perform the decryption
    try
    {
        ChaCha::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv, iv.size());

        // Perform the decryption
        recover.resize(cipher.size());
        dec.ProcessData((byte*)&recover[0], (const byte*)cipher.data(), cipher.size());

        string sample2 = recover.substr(0, 20);
        cout << "Recovered: " << sample2 << endl << endl;
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

}

//  The Rabbit Encryption function. Takes a string encrypts and decrypts it,
//  displays the time taken and storage taken along with some other info
void rabbitEncryption(string fileName)
{
    // Read a file for text to be changing
    string text = readFile(fileName);
    cout << "Running rabbit Encryption" << endl;

    // Setup prng, encoder, key, and iv. Along with our memory counter
    AutoSeededRandomPool prng;
    PROCESS_MEMORY_COUNTERS memCounter;
    HexEncoder encoder(new FileSink(std::cout));

    SecByteBlock key(16), iv(8);
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    string sample = text.substr(0, 20);
    string cipher, recover;
    cout << "plain text: " << sample << endl;

    // Get starting timepoint
    auto start = high_resolution_clock::now();

    // Perform the encryption
    try
    {
        // Encryption object
        RabbitWithIV::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), iv, iv.size());

        // Perform the encryption
        cipher.resize(text.size());
        enc.ProcessData((byte*)&cipher[0], (const byte*)text.data(), text.size());

    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Get ending timepoint
    auto stop = high_resolution_clock::now();

    // Get the size of data used
    BOOL result = K32GetProcessMemoryInfo(GetCurrentProcess(), &memCounter, sizeof(memCounter));
    cout << "WorkingSetSize " << memCounter.WorkingSetSize << std::endl;

    // Get the amount of time used
    auto duration = duration_cast<microseconds>(stop - start);

    cout << "Time taken by function: "
        << duration.count() << " microseconds" << endl;

    // Perform the decryption
    try
    {
        RabbitWithIV::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv, iv.size());

        // Perform the decryption
        recover.resize(cipher.size());
        dec.ProcessData((byte*)&recover[0], (const byte*)cipher.data(), cipher.size());

        string sample2 = recover.substr(0, 20);
        cout << "Recovered: " << sample2 << endl << endl;
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}

void rc6Encryption(string fileName)
{
    // Read a file for text to be changing
    string text = readFile(fileName);

    cout << "Running rc6 Encryption" << endl;

    // Setup prng, encoder, key, and iv. Along with our memory counter
    AutoSeededRandomPool prng;
    PROCESS_MEMORY_COUNTERS memCounter;

    SecByteBlock key(RC6::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    byte iv[RC6::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    string cipher, encoded, recovered;
    
    string sample = text.substr(0, 20);
    cout << "plain text: " << sample << endl;

    // Get starting timepoint
    auto start = high_resolution_clock::now();

    // Perform the encryption
    try
    {

        CBC_Mode< RC6 >::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource(text, true,
            new StreamTransformationFilter(e,
                new StringSink(cipher)
            ) // StreamTransformationFilter
        ); // StringSource
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Get ending timepoint
    auto stop = high_resolution_clock::now();

    // Get the size of data used
    BOOL result = K32GetProcessMemoryInfo(GetCurrentProcess(), &memCounter, sizeof(memCounter));
    cout << "WorkingSetSize " << memCounter.WorkingSetSize << std::endl;

    // Get the amount of time used
    auto duration = duration_cast<microseconds>(stop - start);

    cout << "Time taken by function: "
        << duration.count() << " microseconds" << endl;

    // Perform the decryption
    try
    {
        CBC_Mode< RC6 >::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
            new StreamTransformationFilter(d,
                new StringSink(recovered)
            ) // StreamTransformationFilter
        ); // StringSource

        string sample2 = recovered.substr(0, 20);
        cout << "Recovered: " << sample2 << endl << endl;
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}


// Runs each encryption algorithm with the same text
int main(int argc, char* argv[])
{
    // What the name of the file we're encrypting
    string smallText = "Small.txt";
    string mediumText = "test.txt";
    string largeText = "bible.txt";

    cout << "--------------------------------------------------------" << endl;
    cout << "A test of all the encryptions on a small text" << endl;

    // Run all the programs
    aesEncryption(smallText);
    camelliaEncryption(smallText);
    chachaEncryption(smallText);
    rabbitEncryption(smallText);
    rc6Encryption(smallText);

    cout << "--------------------------------------------------------" << endl;
    cout << "A test of all the encryptions on a medium text" << endl;

    aesEncryption(mediumText);
    camelliaEncryption(mediumText);
    chachaEncryption(mediumText);
    rabbitEncryption(mediumText);
    rc6Encryption(mediumText);

    cout << "--------------------------------------------------------" << endl;
    cout << "A test of all the encryptions on a large text" << endl;

    aesEncryption(largeText);
    camelliaEncryption(largeText);
    chachaEncryption(largeText);
    rabbitEncryption(largeText);
    rc6Encryption(largeText);


    return 0;
}