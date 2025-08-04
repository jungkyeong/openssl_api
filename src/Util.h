/**
  ******************************************************************************
  * @file           : Util
  * @brief          : Class Util define use Utility function 
  ******************************************************************************
  * Made in GreenOasis  
  * https://github.com/jungkyeong
  * CopyRigth MIT License
  ******************************************************************************
  * Release History
  * branch name, working description, time
  * version_001: define add version  2024-09-22
  ******************************************************************************
  */

#ifndef __UTIL_HPP
#define __UTIL_HPP

#include <iostream>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>
#include <termios.h>
#include <unistd.h>
#include <cstring>

// Debug print
#ifdef DEBUG
#define DBG_PRINT(fmt, ...) printf("[DEBUG] " fmt, ##__VA_ARGS__)
#else
#define DBG_PRINT(fmt, ...)
#endif

class Util {
private:

public:

    /**
     * @brief file read data
     * @param filename input file root
     * @param data output data
     * @return Success data_len, Fail -1
     */
    int read_from_file(const char *filename, void **data);

    /**
     * @brief file write and save
     * @param filename input file name
     * @param data input data
     * @param data_len input data size
     * @return Success 0, Fail -1
     */
    int write_to_file(const char *filename, const void *data, size_t data_len);

    /**
     * @brief Get the current time
     * @return current time
    */
    std::string time_get();

    /**
     * @brief Get user input string
     * @param guide_cmd guide print string
     * @return input value
    */
    std::string get_input(std::string guide_cmd);

    /**
     * @brief string switch 32-> 64byte + \0  (ex.0x61 -> 61)
     * @param hex_buffer unsigned char hex buffer
     * @param buffer_len unsigned char hex buffer len
     * @return string
    */
    std::string hex_to_hexstr(unsigned char* hex_buffer, int buffer_len);

    /**
     * @brief string switch 32-> 64byte + \0  (ex.0x61 -> 'a')
     * @param hex_buffer unsigned char hex buffer
     * @param buffer_len unsigned char hex buffer len
     * @return string
    */
    std::string hex_to_str(unsigned char* hex_buffer, int buffer_len);

    /**
     * @brief string switch 2Byte('3','3') -> 1Byte ('33')
     * @param inputdata char input data
     * @param outputdata unsigned char hex output buffer
     * @return output data length
    */
    int hexstr_to_hex(char *inputdata, unsigned char *outputdata);

};

#endif /* __UTIL_HPP */