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

#ifndef __CONFIGREAD_HPP
#define __CONFIGREAD_HPP

#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <string>

// Debug print
#ifdef DEBUG
#define DBG_PRINT(fmt, ...) printf("[DEBUG] " fmt, ##__VA_ARGS__)
#else
#define DBG_PRINT(fmt, ...)
#endif

struct ConfigList {
    std::string key;
    std::string value;
};

class ConfigRead {
    private:
  
    public:
    
    /**
     * @brief get config file keys search value (ex. password = "1234")
     * @param filename input file root
     * @param keyname config file key
     * @return Success value , Fail ""
     */
    std::string config_get_key(std::string filename, std::string keyname);

    /**
     * @brief get config file keys search value
     * @param filename input file root
     * @return Struct ConfigEntry
     */
    std::vector<ConfigList> config_get_all(std::string filename);

};

#endif /* __CONFIGREAD_HPP */