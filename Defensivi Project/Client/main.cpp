#include "Client.h"

int main(int argc, char* argv[])
{
    try
    {
        boost::asio::io_context io_context;//An object that provides basic input/output functionality in communication channels
        Client c(io_context);
        c.handleClient();
        c.close();
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }
    return 0;
}