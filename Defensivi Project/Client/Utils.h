#pragma once
#include <array>



#define TRANSFER_INFO ("transfer.info.txt")
#define ME_INFO     ("me.info.txt")

#define UUID_SIZE (16)
#define PUB_KEY_SIZE (RSAPublicWrapper::KEYSIZE)		 // RSA 1024 bit X509 format
#define SYMMETRIC_KEY_SIZE (AESWrapper::DEFAULT_KEYLENGTH)  // AES-CBC 128 bit
#define MAX_USERNAME (255)
#define TIMES_TO_SEND_FILE (3)

#define HEADER_SIZE (23) //client request header size
#define HEADER_SIZE_RESPONSE (7) //server respond header size
#define CHUNK_SIZE  (1024) 
#define BLOCK_SIZE (16) //AES block size
#define CONTENT_SIZE (4)
#define FILE_NAME_SIZE (255)
#define CRC_SIZE (4)

/* Operation constants defenition */
#define REGISTRATION_CODE (1100)
#define REGISTERATION_FAILED (2101)
#define REGISTERATION_SUCCESS (2100)

#define PUB_KEY_CODE (1101)
#define RES_AES_KEY (2102) //server recieved public key and sent in respond aes key encrypted by the public key


#define SEND_FILE_CODE (1103)
#define RECV_CRC (2103)

#define CRC_SUCCESS_CODE (1104)
#define SERVER_VERIFIED_CODE (2104)
#define CRC_WRONG_CODE (1105)
#define CRC_FAILED_CODE (1106)







struct ResponseHeader {
	uint8_t serverVersion = 0;
	uint16_t statusCode = 0;
	uint32_t payloadSize = 0;
};
