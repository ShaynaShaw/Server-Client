from server import *


def main():
    """
        main function, create server thread and start running
    """
    server = Server('localhost')
    server.run()
    server.close()


if __name__ == '__main__':
    main()
