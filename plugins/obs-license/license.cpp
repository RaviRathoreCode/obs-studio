#include <obs-module.h>
#include <windows.h>
#include <fstream>
#include <string>
#include <vector>
#include <wincrypt.h>
#include <filesystem>
#include <sstream>
#include <iomanip>

OBS_DECLARE_MODULE()
OBS_MODULE_USE_DEFAULT_LOCALE("obs-license", "en-US")

#define SECRET_KEY "MY_PRIVATE_SECRET"

void force_exit_obs()
{
    blog(LOG_ERROR, "[obs-license] FORCING OBS TO EXIT due to invalid license");

    // Show error message
    MessageBoxA(NULL,
                "LICENSE INVALID!\n\n"
                "This plugin requires a valid license to run OBS.\n"
                "The application will now close.\n\n"
                "Please install a valid license and restart OBS.",
                "OBS License - FATAL ERROR",
                MB_ICONERROR | MB_OK);

    // Get the main OBS window and close it
    HWND hwnd = FindWindowA(NULL, "OBS Studio");
    if (hwnd) {
        PostMessageA(hwnd, WM_CLOSE, 0, 0);
    } else {
        // If window not found, force exit
        exit(1);
    }
}

std::string sha256(const std::string &data)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32];
    DWORD hashLen = 32;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        blog(LOG_WARNING, "[obs-license] Failed to acquire crypto context: %lu", GetLastError());
        return "";
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        blog(LOG_WARNING, "[obs-license] Failed to create hash: %lu", GetLastError());
        CryptReleaseContext(hProv, 0);
        return "";
    }

    if (!CryptHashData(hHash, reinterpret_cast<const BYTE *>(data.c_str()), static_cast<DWORD>(data.size()), 0)) {
        blog(LOG_WARNING, "[obs-license] Failed to hash data: %lu", GetLastError());
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        blog(LOG_WARNING, "[obs-license] Failed to get hash param: %lu", GetLastError());
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    std::stringstream ss;
    for (int i = 0; i < 32; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];

    return ss.str();
}

void showMessageBox(const std::string& title, const std::string& message, UINT type)
{
    // Use MessageBoxA for ASCII strings
    MessageBoxA(NULL, message.c_str(), title.c_str(), type);
}

bool verify_license()
{
    // Try multiple possible paths
    std::vector<std::string> possiblePaths = {
        "C:\\ProgramData\\OBSSample\\license.dat",
        "license.dat",
        "C:\\Users\\vikas\\AppData\\Roaming\\obs-studio\\plugins\\obs-license\\license.dat",
        "C:\\Program Files\\obs-studio\\obs-plugins\\64bit\\license.dat"
    };

    std::string line1, line2;
    std::string foundPath;
    bool fileFound = false;

    for (const auto &path : possiblePaths) {
        std::ifstream file(path);
        if (file.is_open()) {
            foundPath = path;
            blog(LOG_INFO, "[obs-license] Found license file at: %s", path.c_str());
            std::getline(file, line1);
            std::getline(file, line2);
            file.close();
            fileFound = true;
            break;
        }
    }

    if (!fileFound) {
        blog(LOG_ERROR, "[obs-license] License file not found in any location");
        showMessageBox("OBS License - ERROR",
                       "License file not found!\n\n"
                    //    "Expected location: C:\\ProgramData\\OBSSample\\license.dat\n\n"
                       "Please install a valid license to use this plugin.",
                       MB_ICONERROR | MB_OK);
        return false;
    }

    // Clean up line2 (remove carriage return if present)
    if (!line2.empty() && (line2.back() == '\r' || line2.back() == '\n'))
        line2.pop_back();

    std::string expected = sha256(line1 + SECRET_KEY);

    // Log for debugging
    blog(LOG_INFO, "[obs-license] === License Debug Info ===");
    blog(LOG_INFO, "[obs-license] License data: %s", line1.c_str());
    blog(LOG_INFO, "[obs-license] Expected hash: %s", expected.c_str());
    blog(LOG_INFO, "[obs-license] Provided hash: %s", line2.c_str());

    bool isValid = (expected == line2);
    blog(LOG_INFO, "[obs-license] License valid: %s", isValid ? "YES" : "NO");

    // Parse user info from license data
    std::string userInfo = "Unknown";
    std::string expiryInfo = "Unknown";

    if (isValid) {
        size_t userPos = line1.find("USER=");
        size_t expPos = line1.find("EXP=");

        if (userPos != std::string::npos) {
            size_t endPos = line1.find('|', userPos);
            if (endPos == std::string::npos)
                endPos = line1.length();
            userInfo = line1.substr(userPos + 5, endPos - (userPos + 5));
        }

        if (expPos != std::string::npos) {
            expiryInfo = line1.substr(expPos + 4);
        }
    }

    // Show message box based on validation result
    if (isValid) {
        std::string message = "LICENSE VALID!\n\n";
        message += "License File: " + foundPath + "\n";
        message += "User: " + userInfo + "\n";
        message += "Expiry: " + expiryInfo + "\n\n";
        message += "Plugin will be enabled.";

        showMessageBox("OBS License - SUCCESS", message, MB_ICONINFORMATION | MB_OK);
    } else {
        std::string message = "LICENSE INVALID!\n\n";
        message += "License File: " + foundPath + "\n";
        // message += "Expected hash: " + expected.substr(0, 16) + "...\n";
        // message += "Provided hash: " + line2.substr(0, 16) + "...\n\n";
        message += "Plugin will be disabled.\n\n";
        message += "Please contact support for a valid license.";

        showMessageBox("OBS License - ERROR", message, MB_ICONERROR | MB_OK);
    }

    return isValid;
}

bool obs_module_load(void)
{
    blog(LOG_INFO, "[obs-license] ==========================");
    blog(LOG_INFO, "[obs-license] OBS License Plugin v1.0");
    blog(LOG_INFO, "[obs-license] Loading...");
    blog(LOG_INFO, "[obs-license] ==========================");

    bool licenseValid = verify_license();

    if (!licenseValid) {
        blog(LOG_ERROR, "[obs-license] ==========================");
        blog(LOG_ERROR, "[obs-license] LICENSE VALIDATION FAILED!");
        blog(LOG_ERROR, "[obs-license] Plugin will be disabled");
        blog(LOG_ERROR, "[obs-license] ==========================");

		force_exit_obs();

        return false; // Plugin won't load
    }

    blog(LOG_INFO, "[obs-license] ==========================");
    blog(LOG_INFO, "[obs-license] LICENSE VALID!");
    blog(LOG_INFO, "[obs-license] Plugin loaded successfully");
    blog(LOG_INFO, "[obs-license] ==========================");

    return true;
}

void obs_module_unload(void)
{
    blog(LOG_INFO, "[obs-license] Plugin unloaded");
    showMessageBox("OBS License", "Plugin unloaded successfully.", MB_ICONINFORMATION | MB_OK);
}

MODULE_EXPORT const char *obs_module_description(void)
{
    return "OBS License Validation Plugin";
}

MODULE_EXPORT const char *obs_module_name(void)
{
    return "License Validation";
}

MODULE_EXPORT const char *obs_module_author(void)
{
    return "Your Name";
}