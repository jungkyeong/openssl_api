/**
  ******************************************************************************
  * @file           : Configread
  * @brief          : Class Config read define use Utility function 
  ******************************************************************************
  * Made in GreenOasis  
  * https://github.com/jungkyeong
  * CopyRigth MIT License
  ******************************************************************************
  * Release History
  * branch name, working description, time
  * version_005: define add version  2025-07-31
  ******************************************************************************
  */

#include "ConfigRead.h"
#include "Util.h"
#include "Define.h"

/**
 * @brief get config file keys search value
 * @param filename input file root
 * @param keyname config file key
 * @return Success value , Fail ""
 */
std::string ConfigRead::config_get_key(std::string filename, std::string keyname){

    // file open Check
    std::ifstream file(filename);
    if (!file.is_open()) {
        DBG_PRINT("file open fail: %s \n", filename.c_str());
        return "";
    }

    std::string line;
    while (std::getline(file, line)) { // get read prev string '\n'
        std::istringstream iss(line); // enable string extraction
        std::string key, equal_sign, value;
        if (iss >> key >> equal_sign >> value && equal_sign == ":") {
            if (key == keyname) {
                // remove ""
                if (!value.empty() && value.front() == '"'){
                    value = value.substr(1, value.length() - 2); // "string"\n pick up string 
                }
                return value;
            }
        }
    }
    return "";
}

std::vector<ConfigList> ConfigRead::config_get_all(std::string filename) {

    std::vector<ConfigList> configVector;
    std::ifstream file(filename);
    
    // file open Check
    if (!file.is_open()) {
        DBG_PRINT("file open fail: %s \n", filename.c_str());
        return configVector;
    }

    std::string line;
    while (std::getline(file, line)) { // get read prev string '\n'
        std::istringstream iss(line); // enable string extraction
        std::string key, equal_sign, value;
        if (iss >> key >> equal_sign >> value && equal_sign == ":") {
            // remove ""
            if (!value.empty() && value.front() == '"' && value.back() == '"') {
                value = value.substr(1, value.length() - 2); // "string"\n pick up string
            }
            configVector.push_back({key, value});
        }
    }
    return configVector;
}