
#pragma once

#include "Utils.h"
#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"

#include <cstdlib>
#include <array>
#include <deque>
#include <map>
#include <vector>
#include <iostream>
#include <thread>
#include <boost/asio.hpp>
//#include <boost/filesystem.hpp> - raised error

using boost::asio::ip::tcp;

typedef std::array<char, UUID_SIZE> uuid;//to represent clients user id
typedef std::array<char, PUB_KEY_SIZE> pubKey; //to represent clients public key
typedef std::array<char, SYMMETRIC_KEY_SIZE> symKey; //to represent clients aes key


class Client
{
private:

    void getTransferInfo();
    std::ifstream openInputFile(const std::string filename);
    void sendRegistrationRequet();
    std::vector<char> buildHeader(char* clientId, char version, uint16_t code, uint32_t size);
    //void connectToServer();
    //void configureTimeouts();//check if needed
    size_t sendBytes(char* data, size_t amount);
    size_t sendBytes(std::vector<char> vec, size_t amount);
    size_t sendBytes(std::string str, size_t amount);
    size_t recvBytes(size_t amount);
    void clearBuffer(char* buf, uint32_t size);
    void parseResponseHeader(ResponseHeader* rh, char* arr);
    void hexify(const unsigned char* buffer, unsigned int length);
    std::ofstream openOutputFile(const std::string filename);
    std::string hexToAscii(const char* arr, size_t len);
    void getClientID();
    void ascii2HexBytes(char* dest, const std::string src, size_t len);
    symKey sendPublicKeyRequet();
    bool sendFileRequest(symKey aesKey);
    std::vector<char> buildFilePayload(char* clientID, uint32_t size, std::string fName);
    uint32_t sendFile(std::string filepath, uint32_t cipherLen, AESWrapper* aes);
    uint32_t calcCRC(const std::string& my_string);
    void sendSuccessedCRC();
    std::vector<char> buildCRCPayload(char* clientID, std::string fName);
    void sendFailedCRCEndProgram();
    void sendWrongCRC();

    /*  tcp ip  */
    boost::asio::ip::address ip_;
    uint16_t port_;

    /*  user information and keys */
    std::string username_ = "";
    std::string filepath_ = "";
    std::string privateKey_ = "";
    std::string base64Pivatekey_ = "";
    pubKey publicKey_ = { 0 };
    uuid clientID_ = { 0 };


    /*  session objects     */
    boost::asio::io_context& io_context_;
    tcp::socket socket_;
    RSAPrivateWrapper* rsapriv_ = nullptr; // RSA private/public key pair engine and decryptor
    RSAPublicWrapper* rsapub_ = nullptr;   // RSA encryptor with public key

    /*  session variables   */
    char data[CHUNK_SIZE] = { 0 };



public:
    char version_ = 3;

    Client() = default;
    Client(boost::asio::io_context& io_context);
    void handleClient();
    void close();
    ~Client();

};



