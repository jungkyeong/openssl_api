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

#include "Util.h"
#include "Define.h"

/**
 * @brief file read data
 * @param filename input file root
 * @param data output data
 * @return Success data_len, Fail -1 Nothing 0
 */
int Util::read_from_file(const char *filename, void **data){

    int data_len = 0;

    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        DBG_PRINT("file open fail : %s \n", filename);
        return FAIL;
    }

    // get file size
    fseek(file, 0, SEEK_END); // file pointer goto move end 
    data_len = ftell(file); // get file size from file pointer position 
    fseek(file, 0, SEEK_SET); // set file pointer clear set move init position 

    // read data
    *data = malloc(data_len+1);
    if (*data == NULL) {
        DBG_PRINT("memory malloc fail \n");
        free(*data);
        fclose(file);
        return FAIL;
    }

    int read_len = fread(*data, 1, data_len, file);
    if (read_len != data_len) {
        DBG_PRINT("file read fail \n");
        free(*data);
        fclose(file);
        return FAIL;
    }

    ((char*)*data)[data_len] = '\0'; 

    fclose(file);
    return data_len;
}

/**
* @brief file create
* @param filename input file root
* @param data input file data
* @param data_len input file length 
* @return Success 0, Fail -1
*/
int Util::write_to_file(const char *filename, const void *data, size_t data_len){
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        DBG_PRINT("Error opening file \n");
        return FAIL;
    }
    size_t written = fwrite(data, 1, data_len, file);
    if (written != data_len) {
        DBG_PRINT("Error writing to file \n");
        fclose(file);
        return FAIL;
    }
    fclose(file);
    return SUCCESS;
}

/**
 * @brief Get the current time
 * @return current time
*/
std::string Util::time_get() {
    int year, mon, day, hour, min, sec;
    time_t TIME = time(NULL);
    struct tm* local_time = localtime(&TIME);

    if (local_time != NULL) {
        year = local_time->tm_year + 1900;
        mon = local_time->tm_mon + 1;
        day = local_time->tm_mday;
        hour = local_time->tm_hour;
        min = local_time->tm_min;
        sec = local_time->tm_sec;
    } else {
        DBG_PRINT("time fail");
    }

    std::ostringstream TimeStamp;
    TimeStamp << year << "-" 
              << std::setw(2) << std::setfill('0') << mon << "-" 
              << std::setw(2) << std::setfill('0') << day << " " 
              << std::setw(2) << std::setfill('0') << hour << ":" 
              << std::setw(2) << std::setfill('0') << min << ":" 
              << std::setw(2) << std::setfill('0') << sec;

    return TimeStamp.str();
}

/**
 * @brief Get user input string
 * @param guide_cmd guide print string
 * @return input value
*/
std::string Util::get_input(std::string guide_cmd){

    std::string input_string;
    struct termios oldt, newt; //terminal option

    std::cout << guide_cmd;
    
    // terminal option
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;

    // ECHO disactive -> set option not show terminal input string
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    // input get
    std::getline(std::cin, input_string);

    //ECHO active -> set option show terminal input string
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;

    return input_string;
}

/**
 * @brief string switch 32-> 64byte + \0  (ex.0x61 -> 61)
 * @param hex_buffer unsigned char hex buffer
 * @param buffer_len unsigned char hex buffer len
 * @return string
*/
std::string Util::hex_to_hexstr(unsigned char* hex_buffer, int buffer_len){

    std::ostringstream oss;

    // hexa data change string, if empty add in '0'
    for (int i = 0; i < buffer_len; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hex_buffer[i];
    }
    return oss.str();
}

/**
 * @brief string switch 32-> 64byte + \0  (ex.0x61 -> 'a')
 * @param hex_buffer unsigned char hex buffer
 * @param buffer_len unsigned char hex buffer len
 * @return string
*/
std::string Util::hex_to_str(unsigned char* hex_buffer, int buffer_len){

    std::string result;

    for (int i = 0; i < buffer_len; i++) {
        result.push_back(static_cast<char>(hex_buffer[i]));
    }
    return result;
}

/**
 * @brief string switch 2Byte('3','3') -> 1Byte ('33')
 * @param inputdata char input data
 * @param outputdata unsigned char hex output buffer
 * @return output data length
*/
int Util::hexstr_to_hex(char *inputdata, unsigned char *outputdata){

    int i=0;

    // len get
    int inputdata_len = strlen(inputdata);

    // check odd number
    if(inputdata_len %2 !=0){
        DBG_PRINT("not inputdata pair \n");
        return FAIL;
    }

    unsigned char unsigned_inputdata[inputdata_len]={0,};

    for( i=0; i < inputdata_len; i++){
        if(inputdata[i] >= 0x30 && inputdata[i] <= 0x39){
            unsigned_inputdata[i]= inputdata[i] - 0x30;
        }
        else if(inputdata[i] >= 0x61 && inputdata[i] <= 0x66){
            unsigned_inputdata[i] = inputdata[i] - 0x61 + 0x0a;
        }
        else if(inputdata[i] >= 0x41 && inputdata[i] <= 0x46){
            unsigned_inputdata[i] = inputdata[i] - 0x41 + 0x0a;
        }
        else {
            DBG_PRINT("inputdata value Invalid \n");
            return FAIL;
        }
    }
    int outputdata_len = inputdata_len / 2;
    for(i=0; i< outputdata_len; i++){
        outputdata[i] = (unsigned_inputdata[i*2] << 4) | (unsigned_inputdata[i*2 +1]);
    }

    return outputdata_len;
}