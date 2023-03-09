from requests import *


class Server:

    def __init__(self, ip):
        self.ip = ip
        try:
            self.port = self.get_server_port()
        except Exception as err:  # if invalid port
            print(err)
            exit(1)
        self.version = SERVER_VERSION
        self.status = 0  # status of current request
        self.cur_cid = b''  # id of client that is currently handled

        self.conn, self.cur = self.open_sql_db()
        self.create_dir()  # create directory to save recieved files
        # selector to run multiple requests from multiple clients
        self.sel = selectors.DefaultSelector()

        # open server socket (TCP/IP non-blocking)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.ip, self.port))
        self.sock.listen(MAX_CONNECTIONS)
        self.sock.setblocking(False)
        # register read events on server socket
        self.sel.register(self.sock, selectors.EVENT_READ, self.accept)

    def run(self):
        """
        This function handles the incoming events on this server's socket
        """
        print(f"Server listening for connections on port {self.port}")
        while True:
            events = self.sel.select()  # selector, multiple requests
            for key, mask in events:
                callback = key.data
                # here the function accept is called on the current event socket (stored in key.fileobj)
                callback(key.fileobj, mask)

    def accept(self, sock, mask):
        """
        This function accepts the incoming client connections
        :param sock: this server's socket
        :param mask: Event mask
        """
        conn, addr = sock.accept()  # waits for client connection
        print(f'\nAccepted client, client address: {addr}')
        conn.setblocking(False)
        # selector goes on and runs the recv_request function
        self.sel.register(conn, selectors.EVENT_READ, self.recieve_request)

    def get_server_port(self):
        """
        This function gets server port from port.info file
        """
        if not os.path.isfile('port.info.txt'):
            print('Can not find port.info file, connection istablished on default port')
            info = DEFUALT_PORT
        else:
            f = open('port.info.txt', 'r')
            info = f.readline()  # read port number
            f.close()
            if not (info.isdecimal()) or not (0 < len(info) < 5):
                raise Exception(
                    'invalid port in port.info file, terminated program')
        return int(info)

    def open_sql_db(self):
        """
        This function opens an sqlite database. then creates a clients table and files table with the following entries: 
        clients table: ID-16 bytes, Name-255 bytes, Public Key-160 bytes, Last Seen-Date and Hour, AES-32 bytes
        files table: ID-4 bytes, FileName-255 bytes, PathName-255 bytes, verified-1 byte (boolean)
        """
        if not os.path.exists(SERVER_DB):
            open(SERVER_DB, 'ab')  # open DB in append binary mode

        conn = sqlite3.connect(SERVER_DB)  # connect to DB
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS clients (ID BLOB, Name BLOB, PublicKey BLOB, LastSeen TEXT, AES BLOB)''')  # BLOB because the data is binary
        cur.execute(
            '''CREATE TABLE IF NOT EXISTS files(ID BLOB, FileName BLOB, PathName BLOB, Verified BLOB)''')
        conn.commit()  # save changes to DB
        print('Created Data-Base Tables Successfully')
        return conn, cur

    def create_dir(self):
        """
        This function creates a new directory in server to store recieved files from client
        """
        current_directory = os.getcwd()
        # r represents raw string..  and will cause backslashes in the string to be interpreted as actual backslashes rather than special characters
        final_directory = os.path.join(current_directory, r'recieved_files')
        if not os.path.exists(final_directory):
            os.makedirs(final_directory)

    def recieve_request(self, conn, mask):
        """
        This function handles client request by receiving the header of the request, processing the request 
        and then closing the connection to client (whether request was fulfilled or not).
        """
        try:
            # recieve client request header, not containing payload content
            header = recieve_header(conn, mask)
            Header = namedtuple(
                'Header', ['client_id', 'version', 'code', 'payload_size'])
            # insert interpeted values into Header fields
            unpaked_header = Header._make(parse_header(header))
            print(unpaked_header)  # for debug info
            self.process_request(conn, mask, unpaked_header)

        except Exception as err:
            print(err)
            self.shutdown_client(conn, None)

    def process_request(self, conn, mask, uh):
        """
        This function receivs the clients request and deals with it accordingly
        uh: unpacked header, represented by a named tuple
        """
        print(f'Received request code: {uh.code}'.upper())

        if uh.code == REGISTER_REQUEST_CODE:
            registration_request(self, conn, mask, uh)
            print("registered client".upper())
            response_registration(self, conn, mask)

        elif uh.code == CLIENTS_SEND_PUBLIC_KEY:
            recieve_public_key(self, conn, mask, uh)
            print("recieved public key".upper())
            response_public_key(self, conn, mask, uh)

        elif uh.code == CLIENTS_SEND_ENCRYPTED_FILE:
            up, file_crc = recieve_file(self, conn, mask, uh)
            response_recieved_file(self, conn, mask, uh, up, file_crc)

        elif uh.code == CRC_SUCCESS:
            verify_file(self, conn, mask, uh)
            print(f"VERIFIED FILE ")
            response_success(self, conn, mask, uh)
            self.shutdown_client(conn, uh)  # close client connection socket

        elif uh.code == CRC_FAILED:
            # now client will send right away again request with code 1103
            read_bytes(conn, mask, uh)
            print('CRC FAILED, waiting for client to re-send file'.upper())

        elif uh.code == CRC_FAILED_END_PROGRAM:
            print('CRC FAILED, COULD NOT RECEIVE FILE')
            delete_file(conn, mask, uh)  # delete file, done
            self.shutdown_client(conn, uh)  # close client connection socket

        else:
            raise Exception('Received unknown code in header')

    def shutdown_client(self, conn, uh):
        """
        This function closes socket connection to client, and unregisters the connection
        from any future events.
        param conn: client's socket connection to be closed
        """
        try:
            self.cur.execute("SELECT Name FROM clients WHERE ID=:uuid", {
                "uuid": uh.client_id})
            client_name = self.cur.fetchone()
            client_name = client_name[0].decode()
            i = client_name.find("\00")
            client_name = client_name[:i]
        except Exception as err:
            client_name = "Unregistered client"
        print(f'---Closing connection for client: {client_name}---\n\n')
        self.sel.unregister(conn)
        conn.close()

    def close(self):
        """
        closes the selector, the socket, and the sql db
        """
        self.sel.close()
        self.sock.close()
        self.conn.close()
