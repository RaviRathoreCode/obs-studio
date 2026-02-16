#include <obs-module.h>
#include <windows.h>
#include <fstream>
#include <string>
#include <wincrypt.h>

OBS_DECLARE_MODULE()
// OBS_MODULE_USE_DEFAULT_LOCALE("obs-license", "en-US")

#define SECRET_KEY "MY_PRIVATE_SECRET"

std::string sha256(const std::string &data)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32];
    DWORD hashLen = 32;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return "";

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }

    CryptHashData(hHash,
                  reinterpret_cast<const BYTE*>(data.c_str()),
                  static_cast<DWORD>(data.size()),
                  0);

    CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    char output[65] = {0};
    for (int i = 0; i < 32; i++)
        sprintf_s(output + i * 2, 3, "%02x", hash[i]);

    return std::string(output);
}

bool verify_license()
{
    std::ifstream file("C:\\ProgramData\\OBSSample\\license.dat");
    if (!file.is_open())
        return false;

    std::string line1, line2;
    std::getline(file, line1);
    std::getline(file, line2);
    file.close();

    if (!line2.empty() && line2.back() == '\r')
        line2.pop_back();

    std::string expected = sha256(line1 + SECRET_KEY);

    blog(LOG_INFO, "[obs-license] DATA: %s", line1.c_str());
    blog(LOG_INFO, "[obs-license] SIGN: %s", line2.c_str());
    blog(LOG_INFO, "[obs-license] EXPECTED: %s", expected.c_str());

    return expected == line2;
}

bool obs_module_load(void)
{
    blog(LOG_INFO, "[obs-license] Plugin started loading");
    if (!verify_license()) {
        blog(LOG_ERROR, "[obs-license] License invalid");
        MessageBoxA(NULL, "License invalid. Plugin disabled.", "OBS License", MB_ICONERROR);
        return false;
    }

    blog(LOG_INFO, "License valid. Plugin enabled.");
    return true;
}

void obs_module_unload(void)
{
}