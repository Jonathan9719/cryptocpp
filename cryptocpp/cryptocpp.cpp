#include "cryptlib.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"

// For the amount of data used
#include <windows.h>
#include <Psapi.h>

// For the timing process
#include <algorithm>
#include <chrono>

// Read a file
#include <fstream>


#include <iostream>
#include <string>

using namespace std;
using namespace std::chrono;    // Again for the timer
using namespace CryptoPP;

string readFile(string fileName) {
    string text;
    ifstream fin(fileName);
    fin >> text;

    if (!fin.fail())
        cout << "Success reading the file!\n";
    else {
        cout << "File read failed. Check filename!\n";
    }

    fin.close();


    return text;
}


int main(int argc, char* argv[])
{
    // Read a file for text to be changing
    string text = readFile("test.txt");

    AutoSeededRandomPool prng;
    HexEncoder encoder(new FileSink(std::cout));

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);
    PROCESS_MEMORY_COUNTERS memCounter;

    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    string plain = "Alright this better be working now!";
    string cipher, recovered;

    cout << "plain text: " << plain << std::endl;

    /*********************************\
    \*********************************/

    // Get starting timepoint
    auto start = high_resolution_clock::now();

    try
    {
        CBC_Mode< AES >::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        StringSource s(plain, true,
            new StreamTransformationFilter(e,
                new StringSink(cipher)
            ) // StreamTransformationFilter
        ); // StringSource
    }
    catch (const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    // Get ending timepoint
    auto stop = high_resolution_clock::now();

    /*********************************\
    \*********************************/

    cout << "key: ";
    encoder.Put(key, key.size());
    encoder.MessageEnd();
    cout << std::endl;

    cout << "iv: ";
    encoder.Put(iv, iv.size());
    encoder.MessageEnd();
    cout << std::endl;

    std::cout << "cipher text: ";
    encoder.Put((const byte*)&cipher[0], cipher.size());
    encoder.MessageEnd();
    cout << std::endl;

    
    // Get the size of data used
    BOOL result = K32GetProcessMemoryInfo(GetCurrentProcess(), &memCounter, sizeof(memCounter));
    cout << "WorkingSetSize " << memCounter.WorkingSetSize << std::endl;

    // Get the amount of time used
    auto duration = duration_cast<microseconds>(stop - start);

    cout << "Time taken by function: "
        << duration.count() << " microseconds" << endl;

    /*********************************\
    \*********************************/

    try
    {
        CBC_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);

        StringSource s(cipher, true,
            new StreamTransformationFilter(d,
                new StringSink(recovered)
            ) // StreamTransformationFilter
        ); // StringSource

        cout << "recovered text: " << recovered << std::endl;
    }
    catch (const Exception& e)
    {
        cerr << e.what() << std::endl;
        exit(1);
    }

    return 0;
}