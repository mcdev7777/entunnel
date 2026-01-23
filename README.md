# entunnel

**entunnel** is a lightweight, modern C++20 library designed to establish TCP tunnels through HTTP proxies on Windows. It specializes in handling corporate environments by automatically detecting system proxy settings and performing transparent authentication (NTLM/Negotiate/Kerberos) using the Windows Security Support Provider Interface (SSPI).

## Features

- **C++20 Modules**: Built entirely using modern C++20 modules (`.ixx`).
- **Automatic Proxy Detection**: Uses WinHTTP to discover system proxy configurations (PAC scripts or manual settings).
- **Transparent Authentication**: Seamlessly handles `407 Proxy Authentication Required` using SSPI. Supports NTLM and Kerberos without manual credential management (uses the current user's context).
- **RAII Resource Management**: Safe handling of sockets and Windows handles.
- **Dependency Free**: Relies solely on the C++ Standard Library and the Windows SDK.

## Requirements

- **Compiler**: A C++20 compliant compiler with Modules support.
  - Clang (tested only).
- **Build System**: CMake 3.26+ (required for C++ Modules support).

## Usage

Here is a simple example of how to use `entunnel` to connect to a remote host through the system proxy:

```cpp
#include <windows.h>
import entunnel;

int main()
{
    entunnel::C_Entunnel tunnel;

    // 1. Initialize and resolve the system proxy for the target address.
    //    Returns false if no proxy is configured or initialization fails.
    if (!tunnel.initialize(L"api.ipify.org:443")) {
        return -1;
    }

    // 2. Perform the HTTP CONNECT handshake and authentication.
    //    Returns a valid raw SOCKET only if the connection through the proxy was successfully established.
    //    Returns SOCKET_ERROR on failure (e.g., authentication failed or host unreachable).
    SOCKET
    SOCKET rawSocket = tunnel.createTunnel();
    
    if (rawSocket == SOCKET_ERROR) {
        // Handle connection or authentication failure
        return -1;
    }

    // ... Use rawSocket for standard send/recv operations ...

    // Clean up
    closesocket(rawSocket);
    return 0;
}
```

## Architecture

The project is structured into several modular components:

*   **`entunnel`**: The main facade class orchestrating the tunnel creation.
*   **`entunnel.inet`**: Handles TCP socket operations and scoped socket management.
*   **`entunnel.proxy`**: Interacts with WinHTTP to resolve proxy settings (PAC/WPAD support).
*   **`entunnel.sspi`**: Manages the authentication handshake (producing NTLM/Kerberos tokens).
*   **`entunnel.http_parser`**: A lightweight HTTP parser for processing proxy responses.

## License

This project is open-source. Feel free to use and modify it for your needs.
