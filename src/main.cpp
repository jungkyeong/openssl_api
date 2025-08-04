#include "main.h"
#include "Util.h"
#include "Define.h"
#include "ConfigRead.h"
#include "../lib/json/json.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string>
#include <cstring>
#include <dlfcn.h> // library load

Util util;
ConfigRead configread;

int main() {

    // current time get
    // std::string asd = util.time_get();

    // std::string pw = util.get_input("user password: ");
    // std::cout << pw << std::endl;
/*
    // Json lib
    void* LibHandle = NULL;
    LibHandle = dlopen(JSON_LIB, RTLD_NOW);
    if(!LibHandle){
        DBG_PRINT("Failed to load JSON library: %s\n", dlerror());
        return FAIL;
    }

    Json::Value resroot;
    resroot["CKA_CLASS"] = "CKO_SECRET_KEY";
    resroot["CKA_KEY_TYPE"] = "CKK_AES";
    resroot["CKA_LABEL"] = "key_label";
    resroot["CKA_TOKEN"] = "false";
    Json::StreamWriterBuilder abuilder;
    std::string create_json_file = Json::writeString(abuilder, resroot);

    std::cout << create_json_file << std::endl;

    dlclose(LibHandle);
*/
/*
    // config read
    void* file_data = nullptr;
    int file_len = util.read_from_file(CONFIG_ROOT, &file_data);
    if(file_len <=0){
        DBG_PRINT("File read fail \n");
    }
    char* config_str = static_cast<char*>(file_data);
    printf("파일 내용:\n%s\n", config_str);


    free(file_data);
*/
/*
    std::ifstream file(CONFIG_ROOT);
    std::string line;
    std::vector<ConfigEntry> configList;

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string key, equal_sign, value;

        if (iss >> key >> equal_sign >> value && equal_sign == "=") {
            // 큰따옴표 제거
            if (!value.empty() && value.front() == '"')
                value = value.substr(1, value.length() - 2);
            
            configList.push_back({key, value});
        }
    }

    // 확인용 출력
    for (const auto& entry : configList) {
        std::cout << entry.key << " -> " << entry.value << std::endl;
    }
    for (auto& entry : configList) { // clear
        std::fill(entry.value.begin(), entry.value.end(), '\0');
        if (entry.key == "password") {
        }
    }

    // 확인용 출력
    for (const auto& entry : configList) {
        std::cout << entry.key << " -> " << entry.value << std::endl;
    }
*/

    // config value out
    // std::string pw = configread.config_get_key(SEC_CONFIG_ROOT, "password");
    // std::cout << pw << std::endl;

    std::vector<ConfigList> configs = configread.config_get_all(CONFIG_ROOT);

    for (const auto& entry : configs) { // print
        std::cout << entry.key << " = " << entry.value << std::endl;
        if(entry.key == "relam"){
            printf("realm name: %s \n", entry.value.c_str());
        }
    }

    for (auto& entry : configs) { // clear
        std::fill(entry.value.begin(), entry.value.end(), '\0');
    }
    return 0;
}