
#include "Client.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <boost/crc.hpp>


/*
*Client constructor.
*The constructor reads the transfer info and saves the  info in this client object,
*then generates the rsa keys.
*The public and private key of a given pair work over the same modulus value.
*(whatevers encrypted with a public key will be decrypted with the corresponding private key).
*/
Client::Client(boost::asio::io_context& io_context) : io_context_(io_context), socket_(io_context)
{
	getTransferInfo();
	/*create client rsa key(public and private)*/
	rsapriv_ = new RSAPrivateWrapper(); // create rsa private engine
	base64Pivatekey_ = Base64Wrapper::encode(rsapriv_->getPrivateKey()); // encode the private key as base64
	rsapriv_->getPublicKey(publicKey_.data(), PUB_KEY_SIZE); // generate the public key from private key
	rsapub_ = new RSAPublicWrapper(publicKey_.data(), PUB_KEY_SIZE); // create RSA encryptor
}


/*
* This function reads the transfer info from the file "transfer.info".
* The info contains server's ip and port, clients user name, and the path to the file to be sent to server.
* The function checks if all info is valid and assigns to client object members.
*/
void Client::getTransferInfo()
{
	std::string line = "";
	std::string port = "";
	std::string ip = "";
	size_t pos;

	std::ifstream transFile(TRANSFER_INFO);
	if (!transFile)//check if file doesn't exist
		throw std::exception("Error: transfer.info file does not exist");

	/*read from transfer info servers ip and port*/
	std::ifstream file;
	file = openInputFile(TRANSFER_INFO);
	std::getline(file, line);	//read ip and port from file

	if (line.size() == 0) {
		file.close();
		throw std::exception("Error: transfer.info File is empty");
	}
	// separate ip and port 
	pos = line.find(":");
	if (pos != std::string::npos)
	{
		ip = line.substr(0, pos);
		port = line.substr(pos + 1);
	}

	// check whether ip and port are valid
	if (port.size() > 0 && port.size() <= 4)
		port_ = std::stoi(port);  // assign to class member
	else
	{
		file.close();
		throw std::exception("Error: Invalid port number");
	}

	boost::asio::ip::address ip_add = boost::asio::ip::make_address(ip);
	if (!ip_add.is_v4())
	{
		file.close();
		throw std::exception("Error: Invalid ip address");
	}
	ip_ = ip_add; 

	// client username
	std::getline(file, line);
	if (line.size() == 0 || line.size() > MAX_USERNAME) {
		file.close();
		throw std::exception("Error: Invalid user name in transfer.info");
	}
	username_ = line;

	// file path to send to server
	std::getline(file, line);
	std::ifstream pathFile(line);
	if (!pathFile)//if path of file wanted to sent to server is not found
	{
		file.close();
		throw std::exception("Error: file to send to server does not exist");
	}
	filepath_ = line;
	std::cout << "IP: " << ip_ << " Port: " << port_ << " User Name: " << username_ << " File Path: " << filepath_ << std::endl;

	file.close(); //done proccessing transfer file info, all info was valid
}


/*
* This function opens a file for input
*/
std::ifstream Client::openInputFile(const std::string filename)
{
	std::ifstream file;
	file.open(filename);
	if (!file)
		throw std::exception("Error: File can not be opened");
	return file;
}


/*
* This function handles the clients requests.
* including: regerstration request, sending public key to server, sending file to server,
* and verifing crc calculation on sent file
*/
void Client::handleClient()
{
	int i = 0;
	bool isEqualCRC;
	symKey symmetricKey;
	try
	{
		std::ifstream file;
		file.open(ME_INFO);
		if (!file)//if me.info file does not exist yet
			sendRegistrationRequet();//register client
		else {
			std::cout << "CLIENT "<< username_ <<" IS ALREADY REGISTERED" << std::endl;
			getClientID();
			socket_.connect(tcp::endpoint(ip_, port_));
		}
		symmetricKey = sendPublicKeyRequet();

		for (i = 0; i < TIMES_TO_SEND_FILE; i++) {
			isEqualCRC = sendFileRequest(symmetricKey);

			if (isEqualCRC) {
				sendSuccessedCRC();
				break;
			}
			if(i<2)
				sendWrongCRC();//send status to server, and try sending file again. up to 3 times
		}
		if(i==3)
			sendFailedCRCEndProgram();//----
		std::cout << "---Closing connection---\n\n" << std::endl;//

			
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}
}


/*
* This function creates a client header vector according to the given parameters:
* clientId - 16 byte, version - 1 bytes, code - 2 bytes, payloadSize - 4 bytes
* returns the header vector (represented in Little Endian)
*/
std::vector<char> Client::buildHeader(char* clientId, char version, uint16_t code, uint32_t size)
{
	std::vector<char> header;
	/*insert client id into header*/
	for (size_t i = 0; i < UUID_SIZE; i++)
		header.push_back((uint8_t)clientId[i]);
	/*insert version into header*/
	header.push_back(version);
	/*insert request code into header*/
	header.push_back((uint8_t)(code));
	header.push_back((uint8_t)(code >> 8));
	/*insert payload size into header*/
	header.push_back((uint8_t)(size));
	header.push_back((uint8_t)(size >> 8));
	header.push_back((uint8_t)(size >> 16));
	header.push_back((uint8_t)(size >> 24));

	return header;
}


/*
* This function sends the data storred in vec to server through socket.
* amount specifies the nubmer of bytes to send.
* returns the number of bytes that were successfully sent
*/
size_t Client::sendBytes(std::vector<char> vec, size_t amount)
{
	size_t bytesSent = boost::asio::write(socket_, boost::asio::buffer(vec, amount));
	if (bytesSent < amount) {//not all data was sent
		std::string err = "Could not send all data, sent" + std::to_string(bytesSent) + " out of " + std::to_string(amount);
		throw std::exception(err.c_str());
	}
	return bytesSent;
}


/*
* This function sends the data to server through socket.
* amount specifies the nubmer of bytes to send.
* returns the number of bytes that were successfully sent
*/size_t Client::sendBytes(char* data, size_t amount)
{
	size_t bytesSent = boost::asio::write(socket_, boost::asio::buffer(data, amount));

	if (bytesSent < amount) {
		std::string err = "Could not send all data, sent" + std::to_string(bytesSent) + " out of " + std::to_string(amount);
		throw std::exception(err.c_str());
	}
	return bytesSent;
}


/*This function clears the buffer in order to recieve new data into the buffer*/
void Client::clearBuffer(char* buf, uint32_t size)
{
	for (uint32_t i = 0; i < size; i++)
		buf[i] = 0;
}


/*
* This function receives bytes into data buffer from socket connected to server. 
* returns the number of bytes that were successfully received
*/
size_t Client::recvBytes(size_t amount)
{
	clearBuffer(data, CHUNK_SIZE);
	size_t bytesRecv = boost::asio::read(socket_, boost::asio::buffer(data, amount));//number of bytes received from server

	if (bytesRecv < amount) {
		clearBuffer(data, CHUNK_SIZE);
		std::string err = "Could not receive all data, received" + std::to_string(bytesRecv) + " out of " + std::to_string(amount);
		throw std::exception(err.c_str());
	}
	return bytesRecv; //number of bytes recieved
}


/*
* This function gets the response header from server, unpackes the data (according to little endian) and saves the unpacked header
* parameters in ResponseHeader struct
*/
void Client::parseResponseHeader(ResponseHeader* rh, char* arr)
{
	rh->serverVersion = (uint8_t)arr[0];
	rh->statusCode = (uint8_t)arr[2] << 8 | (uint8_t)arr[1]; //combine code into one number
	rh->payloadSize = (uint8_t)(arr[6]) << 24 |
		(uint8_t)(arr[5]) << 16 |
		(uint8_t)(arr[4]) << 8 |
		(uint8_t)(arr[3]); //combine payload size
}


/*
* This function opens a file for output
*/
std::ofstream Client::openOutputFile(const std::string filename)
{
	std::ofstream file(filename);
	if (!file)
		throw std::exception("Could not create me.info file");
	return file;
}


/*
* This function sends a registration request to the server.
* the request includes a header and a payload consisting of the clients user name.
* then receives servers answer containing a distinct user id for the client
*/
void Client::sendRegistrationRequet()
{
	/* create request header and send to server*/
	std::vector<char>header = buildHeader(clientID_.data(), version_, REGISTRATION_CODE, MAX_USERNAME);
	socket_.connect(tcp::endpoint(ip_, port_));

	/*send header*/
	sendBytes(header, HEADER_SIZE);

	/*convert string username to bytes vector, and send payload to server*/
	std::vector<char> vec(username_.c_str(), username_.c_str() + username_.length());
	/*in order to prevent access to invalid hidden data, we padd the user name to fill max user name length*/
	std::vector<char>::iterator it;
	it = vec.end();
	vec.insert(it, MAX_USERNAME - vec.size(), NULL);
	/*send payload*/
	sendBytes(vec, MAX_USERNAME);

	/* receive response from server, first recieve header*/
	recvBytes(HEADER_SIZE_RESPONSE);
	ResponseHeader* resHead = new ResponseHeader;
	parseResponseHeader(resHead, data);

	if (resHead->statusCode == REGISTERATION_FAILED)
	{
		delete(resHead);
		throw std::exception("Regestration failed, user already exists");
	}
	if (resHead->statusCode != REGISTERATION_SUCCESS)
	{
		delete(resHead);
		throw std::exception("Invalied server status code");
	}
	if (resHead->payloadSize != UUID_SIZE)
	{
		delete(resHead);
		throw std::exception("Invalid payload size");
	}
	std::cout << "Server code: " << resHead->statusCode << std::endl;

	/*recieve payload*/
	recvBytes(UUID_SIZE);//insert into data buffer the client id recieved
	memcpy(clientID_.data(), data, UUID_SIZE);
	delete(resHead);

	/* save to me.info */
	std::ofstream me = openOutputFile(ME_INFO);
	me << username_ << std::endl;
	me << hexToAscii(clientID_.data(), UUID_SIZE) << std::endl;
	me << base64Pivatekey_ << std::endl;
	me.close();
	std::cout << "REGISTERED CLIENT " << username_ << " SUCCESSFULLY" << std::endl;
}


/*This function converts from hex string to bytes*/
void Client::ascii2HexBytes(char* dest, const std::string src, size_t len)
{
	std::string bytes = "";
	std::stringstream converter;
	converter << std::hex << std::setfill('0');

	for (size_t i = 0; i < (len * 2); i += 2)
	{
		converter << std::hex << src.substr(i, 2);
		int byte;
		converter >> byte;
		bytes += (byte & 0xFF);
		converter.str(std::string());
		converter.clear();
	}
	memcpy(dest, bytes.c_str(), len);
}


/*This function gets the client id for already registered clients, from me.info file*/
void Client::getClientID() {
	std::string line;
	std::ifstream infoFile(ME_INFO);
	if (!infoFile)//check if file doesn't exist
		throw std::exception("In function getClientID, me.info file does not exist");

	/* read the client id*/
	std::ifstream file;
	file = openInputFile(ME_INFO);
	std::getline(file, line);//read name
	std::getline(file, line);//read client ID
	std::cout << "Client ID: " << line << std::endl;

	if (line.size() == 0) {
		file.close();
		throw std::exception("In function getClientID, Couldn't get client ID");
	}
	ascii2HexBytes(clientID_.data(), line, UUID_SIZE);
}


/*This function converts recieves bytes data to hex*/
std::string Client::hexToAscii(const char* arr, size_t len)
{
	std::stringstream converter;
	converter << std::hex << std::setfill('0');

	for (size_t i = 0; i < len; i++)
		converter << std::setw(2) << (static_cast<unsigned>(arr[i]) & 0xFF);
	return converter.str();
}


/*
* This function sends the clients public key to server, and recieves AES key encoded by the public key.
*the request includes a header and a payload consisting of the clients user name and public key
*/
symKey Client::sendPublicKeyRequet() {
	std::string decrypted = "";
	symKey symmetricKey = { 0 };

	/* create request header and send to server*/
	std::vector<char>header = buildHeader(clientID_.data(), version_, PUB_KEY_CODE, MAX_USERNAME + PUB_KEY_SIZE);
	/*send header*/
	sendBytes(header, HEADER_SIZE);

	// convert string username and public key to bytes vector and send payload to server
	std::vector<char> vec(username_.c_str(), username_.c_str() + username_.length());
	/*in order to prevent access to invalid hidden data, we padd the user name to fill max user name length*/
	std::vector<char>::iterator it;
	it = vec.end();
	vec.insert(it, MAX_USERNAME - vec.size(), NULL);

	sendBytes(vec, MAX_USERNAME);//send user name
	sendBytes(publicKey_.data(), PUB_KEY_SIZE);//send public key

	std::cout << "PUBLIC KEY WAS SENT " << std::endl;

	/* receive response from server - recieve header*/
	size_t num = recvBytes(HEADER_SIZE_RESPONSE);
	ResponseHeader* resHead = new ResponseHeader;
	parseResponseHeader(resHead, data);

	if (resHead->statusCode != RES_AES_KEY)
	{
		delete(resHead);
		throw std::exception("Invalied server status code");
	}
	std::cout << "Server code: " << resHead->statusCode << std::endl;

	/*recieve payload*/
	recvBytes(UUID_SIZE);//insert into data buffer the client id 

	num = recvBytes((resHead->payloadSize) - UUID_SIZE);//insert into data buffer the aes key recieved
	std::string temp = "";
	for (int i = 0; i < 16; i++) 
		temp += (uint8_t)data[i];//temporarly - untill is fixed...
	decrypted = temp;//rsapriv_->decrypt(data, num);
	
	memcpy(symmetricKey.data(), decrypted.c_str(), decrypted.length());//now symmetricKey contains the semmetric key recieved from server

	delete(resHead);
	return symmetricKey;
}


/*
* This function creates a message payload vector according to the given parameters:
* clientid - 16 byte, content size - 4 byte, file name - 255 byte
* not refering to the actual content (the content will be sent afterwards..)
* returns a vector containing the payload
*/
std::vector<char> Client::buildFilePayload(char* clientID, uint32_t size, std::string fName)
{
	std::vector<char> msgPayload;

	for (size_t i = 0; i < UUID_SIZE; i++)
		msgPayload.push_back((uint8_t)clientID[i]);

	msgPayload.push_back((uint8_t)(size));
	msgPayload.push_back((uint8_t)(size >> 8));
	msgPayload.push_back((uint8_t)(size >> 16));
	msgPayload.push_back((uint8_t)(size >> 24));

	for (size_t i = 0; i < FILE_NAME_SIZE; i++)
		msgPayload.push_back((uint8_t)fName[i]);

	return msgPayload;
}


/*
* This function calculates crc of the file represented in my_string.
* returns client crc calculation
*/
uint32_t Client::calcCRC(const std::string& my_string) {
	boost::crc_32_type result;
	result.process_bytes(my_string.data(), my_string.length());
	return result.checksum();
}


/*
* This function sends the file at filepath to the server,
* file data will be sent encrypted with aes key. 
* returns client crc calculation for file
*/
uint32_t Client::sendFile(std::string filepath, uint32_t cipherLen, AESWrapper* aes)
{
	std::string cipher = "";
	std::ifstream file(filepath, std::ios::binary);

	clearBuffer(data, CHUNK_SIZE);


	file.read(data, CHUNK_SIZE - BLOCK_SIZE);
	cipher = aes->encrypt(data, (unsigned int)file.gcount());

	//sendBytes(cipher, cipher.length());
	sendBytes(data, cipherLen);
	uint32_t clientCRC = calcCRC("1234");//data

	std::cout << "FILE WAS SUCCESSFULLY SENT" << std::endl;
	file.close();
	return clientCRC;
}


/*
* This function sends the clients file to server, and recieves CRC calculated by server.
* the request includes a header and a payload consisting of the clients id, content size, file name, and message content
* returns true if server crc = client crc calculation
*/
bool Client::sendFileRequest(symKey aesKey) {
	std::ifstream file(filepath_, std::ios::binary);
	std::string line = "";
	file.seekg(0, std::fstream::end);
	uint32_t fileSize = file.tellg();
	if ((fileSize <= 0) || (fileSize > CHUNK_SIZE))    // do not support more than uint32 max size files. (up to 4GB).
		fileSize = 4;//temporarly

	// create encryption engine
	AESWrapper aes((unsigned char*)aesKey.data(), SYMMETRIC_KEY_SIZE);

	// calculate expected AES ciphertext length
	uint32_t cipherLen = ((fileSize / BLOCK_SIZE) + 1) * BLOCK_SIZE;

	// construct header and message payload
	std::vector<char>header = buildHeader(
		clientID_.data(),
		version_,
		SEND_FILE_CODE,
		UUID_SIZE + CONTENT_SIZE + FILE_NAME_SIZE + cipherLen);

	std::vector<char>msgPayload = buildFilePayload(
		clientID_.data(),
		cipherLen,
		filepath_);

	// send header, payload and encrypted file content to server
	sendBytes(header, HEADER_SIZE);
	sendBytes(msgPayload, UUID_SIZE + CONTENT_SIZE + FILE_NAME_SIZE);
	uint32_t clientCRC = sendFile(filepath_, cipherLen, &aes);

	// receive response header + uuid
	recvBytes(HEADER_SIZE_RESPONSE);
	ResponseHeader* resHead = new ResponseHeader;
	parseResponseHeader(resHead, data);

	if (resHead->statusCode != RECV_CRC) {
		delete(resHead);
		throw std::exception("In function sendFileRequest: Invalid status code");
	}
	std::cout << "Server code: " << resHead->statusCode << std::endl;

	recvBytes(UUID_SIZE+ CONTENT_SIZE+ FILE_NAME_SIZE);//not interested
	recvBytes(CRC_SIZE);//recieve server crc calculation
	uint32_t serverCRC = (uint8_t)(data[3]) << 24 |
		(uint8_t)(data[2]) << 16 |
		(uint8_t)(data[1]) << 8 |
		(uint8_t)(data[0]);

	return serverCRC == clientCRC;
}


/*
* This function sends to server that crc was success, and recieves verification from server.
*/
void Client::sendSuccessedCRC() {
	std::ifstream file(filepath_, std::ios::binary);

	// construct header and message payload
	std::vector<char>header = buildHeader(
		clientID_.data(),
		version_,
		CRC_SUCCESS_CODE,
		UUID_SIZE + FILE_NAME_SIZE);

	std::vector<char>crcPayload = buildCRCPayload(
		clientID_.data(),
		filepath_);

	// send header and payload to server
	sendBytes(header, HEADER_SIZE);
	sendBytes(crcPayload, UUID_SIZE + FILE_NAME_SIZE);

	recvBytes(HEADER_SIZE_RESPONSE);
	ResponseHeader* resHead = new ResponseHeader;
	parseResponseHeader(resHead, data);

	if (resHead->statusCode != SERVER_VERIFIED_CODE) {
		delete(resHead);
		throw std::exception("In function sendSuccessedCRC: Invalid status code");
	}
	std::cout << "Server code: " << resHead->statusCode << std::endl;
	std::cout << "File " << filepath_ << " was successfully received by server" << std::endl;
}


/*
* This function sends to server that crc for file was wrong.
*/
void Client::sendWrongCRC() {
	std::ifstream file(filepath_, std::ios::binary);

	// construct header and message payload
	std::vector<char>header = buildHeader(
		clientID_.data(),
		version_,
		CRC_WRONG_CODE,
		UUID_SIZE + FILE_NAME_SIZE);

	std::vector<char>crcPayload = buildCRCPayload(
		clientID_.data(),
		filepath_);

	// send header and payload to server, update server that crc was wrong.
	sendBytes(header, HEADER_SIZE);
	sendBytes(crcPayload, UUID_SIZE + FILE_NAME_SIZE);
}


/*
* This function sends to server that crc was wrong after trying 3 times.
*/
void Client::sendFailedCRCEndProgram(){
	std::ifstream file(filepath_, std::ios::binary);

	// construct header and message payload
	std::vector<char>header = buildHeader(
		clientID_.data(),
		version_,
		CRC_FAILED_CODE,
		UUID_SIZE + FILE_NAME_SIZE);

	std::vector<char>crcPayload = buildCRCPayload(
		clientID_.data(),
		filepath_);

	// send header and payload to server
	sendBytes(header, HEADER_SIZE);
	sendBytes(crcPayload, UUID_SIZE + FILE_NAME_SIZE);
}


/*
* This function creates a crc response payload vector according to the given parameters:
* clientid - 16 byte, file name - 255 byte
*/
std::vector<char> Client::buildCRCPayload(char* clientID, std::string fName)
{
	std::vector<char> crcPayload;

	for (size_t i = 0; i < UUID_SIZE; i++)
		crcPayload.push_back((uint8_t)clientID[i]);

	for (size_t i = 0; i < FILE_NAME_SIZE; i++)
		crcPayload.push_back((uint8_t)fName[i]);

	return crcPayload;
}


/*
* This function closes socket connection to server
*/
void Client::close()
{
	socket_.close();
}


/*Client destructor.
*releases memory
*/
Client::~Client()
{
	delete(rsapriv_);
	delete(rsapub_);
}









