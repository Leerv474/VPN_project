# VPN Project Architecture Summary

## 1. Overview

This VPN project uses C++ and the POSIX API. It builds a simple but solid foundation for a **UDP-based VPN** that uses a **TUN** interface for networking.

The goal is to:

- Accept encrypted UDP packets from VPN clients.
- Decrypt them, inject them into a **TUN device**.
- Read packets from the TUN device, encrypt, and send back via UDP to the right client.

---

## 2. Core Classes

| Class                        | Purpose                                                                                                                   |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `UdpSocket`                  | Low-level UDP operations: create socket, send, receive, bind, set non-blocking.                                           |
| `VpnServer`                  | Main server class: owns `UdpSocket`, manages sessions, handles TUN device, controls event loop.                           |
| `Session`                    | Represents one connected VPN client: holds their real IP:port, VPN-assigned IP, encryption key, last activity timestamp.  |
| (optional) `SessionManager`  | (Optional now, but recommended later) Manages all active sessions separately from `VpnServer`.                            |
| `TunDevice`                  | Manages the TUN interface: open/close device, read/write packets, configure IP and routes.                                |
| (future) `EncryptionManager` | Handles encrypting and decrypting packets based on session keys. (Could be simple XOR/encryption now, real crypto later.) |


---

## 3. How the Server Should Work

1. **Create UDP socket** (non-blocking).
2. **Create and configure TUN device**:

   - Open `/dev/net/tun`.
   - Set device flags (`IFF_TUN | IFF_NO_PI`).
   - Assign an IP address (e.g., `10.8.0.1/24`).
   - Set routing rules and NAT if necessary.

3. **Event loop** (with `select`, `poll`, or `epoll`):

   - Check for **incoming UDP packets**.
     - Find corresponding session or create a new one.
     - Decrypt packet.
     - Inject into TUN interface.
   - Check for **outgoing TUN packets**.
     - Determine which session it belongs to (based on destination IP).
     - Encrypt packet.
     - Send to the client via UDP.

4. **Session management**:
   - Store sessions by `(IP:port)` or authenticated ID.
   - Handle inactivity timeouts (remove dead clients).
   - Manage client authentication (later with keys).

---

## 4. How the Client Should Work

1. **Create UDP socket**.
2. **Create and configure TUN device**:
   - Open TUN device.
   - Assign virtual IP (e.g., `10.8.0.2/24`).
   - Set default route through TUN if needed (optional for testing).
3. **Event loop**:
   - Read packets from TUN.
     - Encrypt.
     - Send to server via UDP.
   - Read packets from UDP socket.
     - Decrypt.
     - Write into TUN interface.

---

## 5. Why This Structure?

- **UdpSocket** is clean and reusable — handles pure networking without mixing in VPN logic.
- **VpnServer** focuses on running the event loop and owning important resources.
- **Session** allows tracking which client owns which VPN IP and encryption key.
- **TunDevice** abstracts messy `ioctl()` and device file operations.
- **EncryptionManager** (future) will make switching between different crypto systems easy.
- **Separation of concerns** keeps code easy to maintain, debug, and expand (e.g., add TCP tunneling or better encryption later).

---

## 6. Minimal README Summary (you can paste)

### VPN Project Design Overview

#### Core Classes

- UdpSocket: handles raw UDP operations (send/recv/bind).
- VpnServer: manages socket, TUN device, client sessions, main event loop.
- Session: tracks connected clients (IP, port, VPN IP, encryption keys).
- TunDevice: manages TUN interface setup, packet I/O.
- (future) EncryptionManager: manages encryption and decryption of packets.

#### Server Workflow

1. Open and configure UDP socket.
2. Open and configure TUN device.
3. Wait for events:
   - Incoming UDP: decrypt → inject to TUN.
   - Outgoing TUN: encrypt → send via UDP.
4. Manage client sessions and expiration.

#### Client Workflow

1. Open UDP socket.
2. Open TUN device.
3. Forward:
   - TUN to UDP (encrypt and send).
   - UDP to TUN (receive and decrypt).

#### Why this structure?

- Clear separation between networking, session tracking, and system interface (TUN).
- Easy to maintain and add features (encryption, multi-client, keys).
- Realistic scalable VPN server layout.

---
