#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace MessagingProtocol {

// Protocol constants

static const uint16_t MAGIC_NUMBER = 0xCAFE; // Identifier for our protocol
static const uint8_t PROTOCOL_VERSION = 1;

// Message types - explicit values for wire format stability
enum MessageType : uint8_t {
    CHAT_MESSAGE = 1,   // Text messages between users
    USER_INFO = 2,      // User profile and metadata
    FILE_CHUNK = 3      // Binary file transfer segments
};

// A simple string structure to hold message data
// Length-prefixed string to avoid null-termination issues
// Note: Manual memory management could still make this error-prone
struct ProtocolString {
    uint16_t length;    // Limits strings to 65KB
    char* data;         // Raw pointer requires careful lifetime management

    ProtocolString();
    ~ProtocolString();
    ProtocolString(const ProtocolString& other);
    ProtocolString& operator=(const ProtocolString& other);

    void set_data(const std::string& str);
    std::string to_string() const;
};

// Fixed-size header for all messages - enables streaming parsers
struct MessageHeader {
    uint16_t magic;         // Protocol validation
    uint8_t version;        // Backwards compatibility
    MessageType type;       // Payload interpretation
    uint32_t payload_size;  // Bytes following header (excluding header itself)
    uint32_t message_id;    // For request/response correlation
};

// Basic chat message - demonstrates string handling
struct ChatMessage {
    ProtocolString username;
    ProtocolString message;
    uint64_t timestamp;     // Unix timestamp for ordering
    uint8_t priority;       // 0=low, 255=critical
};

// User profile with dynamic tag array - most complex structure
struct UserInfo {
    ProtocolString username;
    ProtocolString email;
    uint32_t user_id;
    uint16_t status;        // 0=offline, 1=online, 2=away, etc.
    ProtocolString* tags;   // Dynamic array - memory management critical
    uint16_t tag_count;     // Array size - bounds checking essential
};

// File transfer chunk - handles arbitrary binary data
struct FileChunk {
    ProtocolString filename;
    uint32_t chunk_id;      // 0-based chunk number
    uint32_t total_chunks;  // Total expected chunks
    uint16_t chunk_size;    // Bytes in this chunk (0-65535)
    uint8_t* data;          // Raw binary data - size validation critical
};

// Complete message with type-specific payload
struct Message {
    MessageHeader header;

    // Only one payload pointer is valid based on header.type
    // Manual memory management required for proper cleanup
    // Manual means a nice vulnerability potential!
    ChatMessage* chat;
    UserInfo* user_info;
    FileChunk* file_chunk;

    Message(MessageType type);
    ~Message();
    Message(const Message& other);      // Deep copy semantics expected
    Message& operator=(const Message& other);
};

// Serialization functions to convert data types into binary formats
// Binary serialization to/from wire format or when storing into disk
// Note: No endianness handling - assumes same architecture
class Serializer {
public:
    static std::vector<uint8_t> serialize(const Message& msg);
    static Message* deserialize(const uint8_t* data, size_t length);  // Returns nullptr on error

private:
    // Internal helpers - buffer bounds checking is caller's responsibility
    static size_t write_string(uint8_t* buffer, const ProtocolString& str);
    static size_t read_string(const uint8_t* buffer, size_t remaining, ProtocolString& str);
};

} // namespace MessagingProtocol
