#pragma once

#include <iostream>
#include "Util.h"

// test file data
const char* file_data = "asd";

//========== json message ==========//
std::string resp_msg;

//========== file root ==========//
#define JSON_LIB "./lib/json/libjsoncpp.so"
#define CONFIG_ROOT "./cfg/config.txt"
#define SEC_CONFIG_ROOT "./cfg/secret_config.txt"