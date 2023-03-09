

from collections import namedtuple
import os
import random
import selectors
import socket
import sqlite3
import string
import struct
import time
import uuid
from Crypto.Cipher import AES
from parameters import *
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from secrets import token_bytes
import zlib  # to calc crc


def recieve_header(conn, mask) -> bytes:
    """
    This function receives the header of client request
    returns header
    """
    header = conn.recv(REQUEST_HEADER_SIZE)  # get header data from socket
    if not header:
        raise Exception('Could not process request, missing header')
    if len(header) != REQUEST_HEADER_SIZE:
        raise Exception(
            f'Invalid header, requested header size: {REQUEST_HEADER_SIZE}')
    return header


def parse_header(header) -> tuple:
    """
    This function unpacks the header occurding to given sizes (in bytes): client_id-16 bytes, version-1 byte, code-2 bytes, payload_size-4 bytes.
    header: the request header recieved from client
    returns unpacked header tuple
    """
    return struct.unpack('<16sBHI', header)  # Interpret bytes as packed binary data


def recv_payload(conn, mask, size) -> bytes:
    """
    This function receives the client payload from socket.
    conn: connection socket with client
    mask: Event mask
    size: payload size (bytes)
    returns payload (bytes object)
    """
    data = conn.recv(size)  # receive payload data from socket
    if not data:
        raise Exception('Missing payload, request aborted')
    if len(data) != size:
        raise Exception(
            f"Payload too short, Number of received bytes ({len(data)}) != payload size specified ({size})")
    return data


def parse_payload(payload, **kwargs) -> tuple:
    """
    This function gets the payload bytes object, and unpacks it in a way
    that the resulted bytes would split into categories
    according to key word arguments provided.
    payload: payload recieved from client
    kwargs: type dict, key value elements (categories in payload) 
    returns a tuple that contains the payload, split according the kwargs argument.
    """
    if len(payload) > sum(kwargs.values()):  # key word args refers as a dictionary, sum calcs the total amount of bytes in payload
        raise Exception("Could not parse payload, invalid size")
    splitter = ''
    for num_bytes in kwargs.values():
        splitter += f'{num_bytes}s'  # create format for unpacking payload
    # unpack payload to wanted fields
    return struct.unpack(splitter, payload)


def registration_request(self, conn, mask, uh):
    """
    This function handles the registration request - unpacks the payload,
    adds client (if doesn't exist) to clients DB table and generates a distinct uuid for the client.
    """
    # if didn't manage to receive payload - caller will raise exception
    payload = recv_payload(conn, mask, uh.payload_size)
    Payload = namedtuple('Payload', ['username'])
    unpaked_payload = Payload._make(parse_payload(
        payload, username_size=MAX_USERNAME))
    self.cur.execute("SELECT ID FROM clients WHERE ID=:uuid", {
                     "uuid": uh.client_id})  # check if user exists already
    if not self.cur.fetchall():  # if user doesn't exist
        uid = uuid.uuid4().bytes_le  # create new uuid for user
        temp = unpaked_payload.username.find(b'\00')
        print(
            f'Registering new client: {(unpaked_payload.username.decode())[0:temp]}')
        self.cur.execute("INSERT INTO clients (ID, Name, PublicKey, LastSeen, AES) VALUES (?, ?, ?, ?, ?)",
                         (uid, unpaked_payload.username, NULL, time.ctime(), NULL))  # insert client with the known fields
        self.conn.commit()  # store changes in DB
        self.status = REGISTER_SUCCESS  # client regestered
        self.cur_cid = uid
    else:
        print(
            f'Client already exists, can not reregister')
        self.status = REGISTER_NOT_SUCCESS  # client already exists
        self.cur_cid = uh.client_id


def response_registration(self, conn, mask):
    """
    This function handles the server response to clients registration request
    """
    res_header = struct.pack('<BHI', self.version, self.status, UUID_SIZE)
    res_payload = struct.pack(f'<{UUID_SIZE}s', self.cur_cid)
    # send registration response
    send(conn, mask, res_header, RESPONSE_HEADER_SIZE)
    send(conn, mask, res_payload, UUID_SIZE)


def recieve_public_key(self, conn, mask, uh):
    """
    This fuction handles request of client sent public key - unpacks the payload from the client, 
    and adds the public key to the clients BD table.
    returns the generated AES key incrypted with public key.
    """
    payload = recv_payload(conn, mask, uh.payload_size)
    Payload = namedtuple('Payload', ['username', 'public_key'])
    up = Payload._make(parse_payload(
        payload, username_size=MAX_USERNAME, public_key_size=PUBLIC_KEY_SIZE))
    self.cur.execute("SELECT ID FROM clients WHERE ID=:uuid", {
                     "uuid": uh.client_id})
    if not self.cur.fetchall():
        raise Exception(f'Cannot recieve public key, user not registered')
    else:
        self.cur.execute("UPDATE clients SET PublicKey=:pk WHERE ID=:uuid", {
                         "pk": up.public_key, "uuid": uh.client_id})  # save clients public key in clients table
        self.conn.commit()  # save to DB
    self.status = PUBLIC_KEY_RESPOND_STATUS


def response_public_key(self, conn, mask, uh):  # debug funct with proper DB info
    """
    This function creates and sends server response to the client that sent public key request
    server response contains generates AES key encoded by clients public key
    """
    self.cur.execute("SELECT PublicKey FROM clients WHERE ID=:uuid", {
                     "uuid": uh.client_id})
    public_key = self.cur.fetchone()
    aes_key = create_AES()
    print(f'CREATED AES KEY: {aes_key}')
    self.cur.execute("UPDATE clients SET AES=:ak WHERE ID=:uuid", {
                     "ak": aes_key, "uuid": uh.client_id})  # save aes key to db
    self.conn.commit()
    # encode AES key with users public key using rsa encoding
    key = RSA.importKey(public_key[0])
    cipher = Cipher_PKCS1_v1_5.new(key)
    encoded_AES = cipher.encrypt(aes_key)
    res_header = struct.pack('<BHI', self.version,
                             self.status, UUID_SIZE + len(encoded_AES))
    res_payload = struct.pack(
        f'<{UUID_SIZE}s{len(encoded_AES)}s', self.cur_cid, encoded_AES)
    # send server response (containing encrypted AES key) to the client that sent public key
    send(conn, mask, res_header, RESPONSE_HEADER_SIZE)
    send(conn, mask, res_payload, UUID_SIZE + len(encoded_AES))
    print("RESPONDED ENCODED AES KEY")


def create_AES() -> bytes:
    """
    This function creates an aes key
    returns AES key
    """
    key = token_bytes(16)
    return key


def recieve_file(self, conn, mask, uh):
    """
    This function handles file sent request - unpacks the payload 
    the funct calls other functions to decrypt the file, save the decrypted file, and calc crc.
    returns unpaked payload and crc
    """
    recieved_file = recv_payload(conn, mask, uh.payload_size)
    Recieved_file = namedtuple(
        'recieved_file', ['client_id', 'content_size', 'file_name', 'message_content'])
    file_size = uh.payload_size - UUID_SIZE - CONTENT_SIZE - MAX_FILENAME
    up = Recieved_file._make(parse_payload(
        recieved_file, id_size=UUID_SIZE, c_size=CONTENT_SIZE, f_name=MAX_FILENAME, f_size=file_size))
    print("RECEIVED FILE")
    self.cur.execute("SELECT AES FROM clients WHERE ID=:uuid", {
                     "uuid": uh.client_id})
    aes_key = self.cur.fetchone()
    if aes_key == None:
        raise Exception(
            "In recieveFile: could not receive file, user not reqistered")
    # the decrypted content in bytes
    dec_content = decrypt_file(aes_key[0], up.message_content)
    print(f"DECRIPTED FILE, ", end="")

    save_file(self, dec_content, up)
    file_crc = calc_crc(dec_content)
    self.status = CRC_RESPOND_STATUS
    return up, file_crc


def decrypt_file(aes_key, content):
    '''
    returns decrypted content in bytes
    '''
    aes = AES.new(aes_key, AES.MODE_CBC, IV)
    dec_content = aes.decrypt(content)
    return dec_content


def save_file(self, dec_content, up):

    # to give disticnt name
    j = up.file_name.find(b'\x00')
    file_name = up.file_name[:j].decode()

    print(f'File Name: {file_name}')
    #print(f'Dec contant: {dec_content}')
    path_name = os.path.abspath(f'./recieved_files/{file_name}')
    with open(path_name, 'w') as f:
        # dec_content.decode()) -->fix after fixing client decode aes
        f.write("1234")
    self.cur.execute("INSERT INTO files (ID, FileName, PathName, Verified) VALUES (?, ?, ?, ?)",
                     (up.client_id, file_name, path_name, False))  # insert file to files DB
    self.conn.commit()  # store changes in DB


def calc_crc(dec_content):
    # calc crc and return it
    # instead of "1234" write dec_content.decode()---fix after fixing client aes
    server_crc = zlib.crc32("1234".encode())
    print(f"CALCULATED CRC: {server_crc}")
    return server_crc


def response_recieved_file(self, conn, mask, uh, upf, file_crc):
    """
    This function creates and sends server response to the client that sent file
    server response contains crc calculation of decrypted contant
    """
    res_head = struct.pack('<BHI', self.version,
                           self.status, CRC_RESPONSE_PAYLOAD)
    res_payload = struct.pack(
        f'<{UUID_SIZE}s{CONTENT_SIZE}s{MAX_FILENAME}s{CKSUM_SIZE}s', self.cur_cid, upf.content_size, upf.file_name, file_crc.to_bytes(CKSUM_SIZE, 'little'))
    send(conn, mask, res_head, RESPONSE_HEADER_SIZE)
    send(conn, mask, res_payload, CRC_RESPONSE_PAYLOAD)


def verify_file(self, conn, mask, uh):
    """
    This function updates files table in servers DB that the recieved file was verified, and updates status accordingly
    """
    payload = recv_payload(conn, mask, uh.payload_size)
    Payload = namedtuple(
        'recieved_file', ['client_id', 'file_name'])
    up = Payload._make(parse_payload(
        payload, id_size=UUID_SIZE, f_name=MAX_FILENAME))
    j = up.file_name.find(b'\x00')
    file_name = up.file_name[:j].decode()

    self.cur.execute("UPDATE files SET Verified=:ver WHERE FileName=:fName", {
                     "ver": True, "fName": file_name})
    self.conn.commit()
    self.status = SUCCESS_MSG


def response_success(self, conn, mask, uh):
    """
    This function responds to client that the file he sent was successfuly recieved
    """
    res_head = struct.pack('<BHI', self.version,
                           self.status, EMPTY_PAYLOAD)
    send(conn, mask, res_head, RESPONSE_HEADER_SIZE)


def read_bytes(conn, mask, uh):
    """
    This function reads the received bytes in order to clear socket
    """
    payload = recv_payload(conn, mask, uh.payload_size)


def delete_file(conn, mask, uh):
    """
    This function deletes file from server directory after file was not verified three times
    """
    payload = recv_payload(conn, mask, uh.payload_size)
    Payload = namedtuple(
        'recieved_file', ['client_id', 'file_name'])
    up = Payload._make(parse_payload(
        payload, id_size=UUID_SIZE, f_name=MAX_FILENAME))
    j = up.file_name.find(b'\x00')
    file_name = up.file_name[:j].decode()
    path_name = os.path.abspath(f'./recieved_files/{file_name}')
    if os.path.exists(path_name):
        os.remove(path_name)
    else:
        raise Exception(f"The file {file_name} does not exist")


def send(conn, mask, data, amount):
    """
    This function sends server response to client through socket.
    """
    num_sent = conn.send(data)  # send data to client through socket
    if num_sent != amount:
        raise Exception(
            f'Sending failed, the number of bytes sent {num_sent} != amout specified {amount}')
