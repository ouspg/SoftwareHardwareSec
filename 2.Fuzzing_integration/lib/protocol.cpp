#include "protocol.h"
#include <cstring>
#include <cstdlib>

namespace MessagingProtocol {

/**
 * ProtocolString implementation
 *
 * Manages variable-length strings with explicit length prefixes to avoid
 * null-termination dependencies. Uses manual memory management which makes
 * it prone to leaks, double-frees, and shallow copy issues, and more!
 */

// Default constructor - creates empty string with no allocation
ProtocolString::ProtocolString() : length(0), data(nullptr) {}

// Destructor - frees allocated memory if any exists
// Note: Simple check for null pointer before deletion
ProtocolString::~ProtocolString() {
    if (data) {
        delete[] data;
    }
}

// Copy constructor - performs deep copy of string data
// Allocates new memory and copies content to ensure independent ownership
ProtocolString::ProtocolString(const ProtocolString& other) : length(other.length) {
    if (other.data && other.length > 0) {
        data = new char[length];
        memcpy(data, other.data, length);
    } else {
        data = nullptr;
    }
}

// Assignment operator - should perform deep copy like copy constructor
// INTENTIONAL BUG: Does not free existing memory before reassignment,
// causing memory leaks on repeated assignments
ProtocolString& ProtocolString::operator=(const ProtocolString& other) {
    if (this != &other) {
        length = other.length;
        if (other.data && other.length > 0) {
            data = new char[length];
            memcpy(data, other.data, length);
        } else {
            data = nullptr;
        }
    }
    return *this;
}

// Sets string content from std::string, handling memory allocation
// Properly frees existing memory before allocating new buffer
// Copies only the string content, not the null terminator
void ProtocolString::set_data(const std::string& str) {
    length = str.length();
    if (data) {
        delete[] data;
    }
    if (length > 0) {
        data = new char[length];
        memcpy(data, str.c_str(), length);
    } else {
        data = nullptr;
    }
}

// Converts internal representation back to std::string
// Uses length-based constructor to handle non-null-terminated data
std::string ProtocolString::to_string() const {
    if (data && length > 0) {
        return std::string(data, length);
    }
    return "";
}

/**
 * Message implementation
 *
 * Manages the complete protocol message with header and type-specific payload.
 * Uses pointer-based payload storage to avoid C++ union constructor issues.
 * Only one payload pointer is valid per message based on the type field.
 */

// Message constructor - creates message of specified type with default values
// Initializes header with protocol constants and allocates appropriate payload
// All unused payload pointers remain null to prevent confusion
Message::Message(MessageType type) {
    header.magic = MAGIC_NUMBER;
    header.version = PROTOCOL_VERSION;
    header.type = type;
    header.payload_size = 0;
    header.message_id = 0;

    // Initialize all payload pointers to null
    chat = nullptr;
    user_info = nullptr;
    file_chunk = nullptr;

    // Allocate and initialize payload based on message type
    switch (type) {
        case CHAT_MESSAGE:
            chat = new ChatMessage();
            chat->timestamp = 0;
            chat->priority = 0;
            break;
        case USER_INFO:
            user_info = new UserInfo();
            user_info->user_id = 0;
            user_info->status = 0;
            user_info->tags = nullptr;
            user_info->tag_count = 0;
            break;
        case FILE_CHUNK:
            file_chunk = new FileChunk();
            file_chunk->chunk_id = 0;
            file_chunk->total_chunks = 0;
            file_chunk->chunk_size = 0;
            file_chunk->data = nullptr;
            break;
    }
}

// Message destructor - cleans up payload based on message type
// Must handle nested dynamic allocations (tags array, file data)
// Type-specific cleanup prevents memory leaks
Message::~Message() {
    switch (header.type) {
        case CHAT_MESSAGE:
            delete chat;
            break;
        case USER_INFO:
            if (user_info) {
                if (user_info->tags) {
                    delete[] user_info->tags;  // Free tag array first
                }
                delete user_info;
            }
            break;
        case FILE_CHUNK:
            if (file_chunk) {
                if (file_chunk->data) {
                    delete[] file_chunk->data;  // Free binary data first
                }
                delete file_chunk;
            }
            break;
    }
}

// Copy constructor - creates independent copy of message and all its data
// INTENTIONAL BUG: Performs shallow copy of UserInfo tags array, causing
// both objects to share the same memory, leading to double-free on destruction
Message::Message(const Message& other) : header(other.header) {
    chat = nullptr;
    user_info = nullptr;
    file_chunk = nullptr;

    switch (header.type) {
        case CHAT_MESSAGE:
            chat = new ChatMessage();
            *chat = *other.chat;  // Uses ProtocolString copy semantics
            chat->timestamp = other.chat->timestamp;
            chat->priority = other.chat->priority;
            break;
        case USER_INFO:
            user_info = new UserInfo();
            user_info->username = other.user_info->username;
            user_info->email = other.user_info->email;
            user_info->user_id = other.user_info->user_id;
            user_info->status = other.user_info->status;
            user_info->tag_count = other.user_info->tag_count;

            // Bug: Shallow copy of array - both objects share same tags pointer
            user_info->tags = other.user_info->tags;
            break;
        case FILE_CHUNK:
            file_chunk = new FileChunk();
            file_chunk->filename = other.file_chunk->filename;
            file_chunk->chunk_id = other.file_chunk->chunk_id;
            file_chunk->total_chunks = other.file_chunk->total_chunks;
            file_chunk->chunk_size = other.file_chunk->chunk_size;

            // Properly deep copy binary data
            if (other.file_chunk->data && other.file_chunk->chunk_size > 0) {
                file_chunk->data = new uint8_t[other.file_chunk->chunk_size];
                memcpy(file_chunk->data, other.file_chunk->data, other.file_chunk->chunk_size);
            } else {
                file_chunk->data = nullptr;
            }
            break;
    }
}

// Assignment operator - replaces current message content with copy of other
// INTENTIONAL BUGS: Many
Message& Message::operator=(const Message& other) {
    if (this != &other) {
        // Bug: Not cleaning up existing resources before assignment?
        header = other.header;

        switch (header.type) {
            case CHAT_MESSAGE:
                *chat = *other.chat;
                break;
            case USER_INFO:
                *user_info = *other.user_info;
                user_info->tags = other.user_info->tags;
                break;
            case FILE_CHUNK:
                *file_chunk = *other.file_chunk;
                if (other.file_chunk->data && other.file_chunk->chunk_size > 0) {
                    file_chunk->data = new uint8_t[other.file_chunk->chunk_size];
                    memcpy(file_chunk->data, other.file_chunk->data, other.file_chunk->chunk_size);
                } else {
                    file_chunk->data = nullptr;
                }
                break;
        }
    }
    return *this;
}

/**
 * Serializer Implementation
 *
 * Converts Message objects to/from binary wire format for network transmission or
 * storing data into disc.
 * Uses little-endian byte order and assumes same architecture on both ends.
 * No compression or encryption - focused on demonstrating memory safety issues.
 */

// Serialize message to binary format suitable for network transmission
// Returns vector containing complete message including header and payload
// POTENTIAL ISSUE: No endianness handling - assumes same architecture
std::vector<uint8_t> Serializer::serialize(const Message& msg) {
    std::vector<uint8_t> buffer;

    // Write fixed-size header first
    buffer.resize(sizeof(MessageHeader));
    memcpy(buffer.data(), &msg.header, sizeof(MessageHeader));

    size_t offset = sizeof(MessageHeader);

    switch (msg.header.type) {
        case CHAT_MESSAGE: {
            const auto& chat = *msg.chat;

            // Write timestamp and priority
            buffer.resize(offset + sizeof(uint64_t) + sizeof(uint8_t));
            memcpy(buffer.data() + offset, &chat.timestamp, sizeof(uint64_t));
            offset += sizeof(uint64_t);
            memcpy(buffer.data() + offset, &chat.priority, sizeof(uint8_t));
            offset += sizeof(uint8_t);

            // Write strings - resize buffer first
            size_t username_size = sizeof(uint16_t) + chat.username.length;
            size_t message_size = sizeof(uint16_t) + chat.message.length;
            buffer.resize(offset + username_size + message_size);

            offset += write_string(buffer.data() + offset, chat.username);
            offset += write_string(buffer.data() + offset, chat.message);
            break;
        }
        case USER_INFO: {
            const auto& user = *msg.user_info;

            // Write basic fields
            buffer.resize(offset + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t));
            memcpy(buffer.data() + offset, &user.user_id, sizeof(uint32_t));
            offset += sizeof(uint32_t);
            memcpy(buffer.data() + offset, &user.status, sizeof(uint16_t));
            offset += sizeof(uint16_t);
            memcpy(buffer.data() + offset, &user.tag_count, sizeof(uint16_t));
            offset += sizeof(uint16_t);

            // Calculate total size needed for strings
            size_t string_size = sizeof(uint16_t) + user.username.length + sizeof(uint16_t) + user.email.length;
            for (uint16_t i = 0; i < user.tag_count; i++) {
                string_size += sizeof(uint16_t) + user.tags[i].length;
            }
            buffer.resize(offset + string_size);

            // Write strings
            offset += write_string(buffer.data() + offset, user.username);
            offset += write_string(buffer.data() + offset, user.email);

            // Write tags array
            for (uint16_t i = 0; i < user.tag_count; i++) {
                offset += write_string(buffer.data() + offset, user.tags[i]);
            }
            break;
        }
        case FILE_CHUNK: {
            const auto& chunk = *msg.file_chunk;

            // Calculate total size needed
            size_t filename_size = sizeof(uint16_t) + chunk.filename.length;
            size_t total_size = sizeof(uint32_t) * 2 + sizeof(uint16_t) + filename_size + chunk.chunk_size;
            buffer.resize(offset + total_size);

            // Write chunk info
            memcpy(buffer.data() + offset, &chunk.chunk_id, sizeof(uint32_t));
            offset += sizeof(uint32_t);
            memcpy(buffer.data() + offset, &chunk.total_chunks, sizeof(uint32_t));
            offset += sizeof(uint32_t);
            memcpy(buffer.data() + offset, &chunk.chunk_size, sizeof(uint16_t));
            offset += sizeof(uint16_t);

            // Write filename
            offset += write_string(buffer.data() + offset, chunk.filename);

            // Write chunk data
            if (chunk.data && chunk.chunk_size > 0) {
                memcpy(buffer.data() + offset, chunk.data, chunk.chunk_size);
                offset += chunk.chunk_size;
            }
            break;
        }
    }

    // Update payload size in header
    MessageHeader* hdr = reinterpret_cast<MessageHeader*>(buffer.data());
    hdr->payload_size = offset - sizeof(MessageHeader);

    return buffer;
}

// Deserialize binary data back into Message object
// INTENTIONAL BUGS: How is the input validation?
// Returns new Message* (caller must delete) or nullptr on error
Message* Serializer::deserialize(const uint8_t* data, size_t length) {
    if (length < sizeof(MessageHeader)) {
        return nullptr;  // Not enough data for header
    }

    const MessageHeader* hdr = reinterpret_cast<const MessageHeader*>(data);

    Message* msg = new Message(hdr->type);
    msg->header = *hdr;

    size_t offset = sizeof(MessageHeader);

    switch (hdr->type) {
        case CHAT_MESSAGE: {
            if (offset + sizeof(uint64_t) + sizeof(uint8_t) > length) {
                delete msg;
                return nullptr;
            }

            memcpy(&msg->chat->timestamp, data + offset, sizeof(uint64_t));
            offset += sizeof(uint64_t);
            memcpy(&msg->chat->priority, data + offset, sizeof(uint8_t));
            offset += sizeof(uint8_t);

            // Bug: No bounds checking in read_string?
            offset += read_string(data + offset, length - offset, msg->chat->username);
            offset += read_string(data + offset, length - offset, msg->chat->message);
            break;
        }
        case USER_INFO: {
            if (offset + sizeof(uint32_t) + sizeof(uint16_t) * 2 > length) {
                delete msg;
                return nullptr;
            }

            memcpy(&msg->user_info->user_id, data + offset, sizeof(uint32_t));
            offset += sizeof(uint32_t);
            memcpy(&msg->user_info->status, data + offset, sizeof(uint16_t));
            offset += sizeof(uint16_t);
            memcpy(&msg->user_info->tag_count, data + offset, sizeof(uint16_t));
            offset += sizeof(uint16_t);

            offset += read_string(data + offset, length - offset, msg->user_info->username);
            offset += read_string(data + offset, length - offset, msg->user_info->email);

            // Bug: No validation of tag_count - could be huge?
            if (msg->user_info->tag_count > 0) {
                msg->user_info->tags = new ProtocolString[msg->user_info->tag_count];
                for (uint16_t i = 0; i < msg->user_info->tag_count; i++) {
                    offset += read_string(data + offset, length - offset, msg->user_info->tags[i]);
                }
            }
            break;
        }
        case FILE_CHUNK: {
            if (offset + sizeof(uint32_t) * 2 + sizeof(uint16_t) > length) {
                delete msg;
                return nullptr;
            }

            memcpy(&msg->file_chunk->chunk_id, data + offset, sizeof(uint32_t));
            offset += sizeof(uint32_t);
            memcpy(&msg->file_chunk->total_chunks, data + offset, sizeof(uint32_t));
            offset += sizeof(uint32_t);
            memcpy(&msg->file_chunk->chunk_size, data + offset, sizeof(uint16_t));
            offset += sizeof(uint16_t);

            offset += read_string(data + offset, length - offset, msg->file_chunk->filename);

            if (msg->file_chunk->chunk_size > 0) {
                // Bug: No bounds checking for chunk data?
                msg->file_chunk->data = new uint8_t[msg->file_chunk->chunk_size];
                memcpy(msg->file_chunk->data, data + offset, msg->file_chunk->chunk_size);
            }
            break;
        }
        default:
            delete msg;
            return nullptr;
    }

    return msg;
}

// Write ProtocolString to buffer in wire format (length + data)
// INTENTIONAL BUG: Space?
// Returns number of bytes written
size_t Serializer::write_string(uint8_t* buffer, const ProtocolString& str) {
    // Bug: Buffer could be null, no size checking?
    memcpy(buffer, &str.length, sizeof(uint16_t));
    if (str.length > 0 && str.data) {
        memcpy(buffer + sizeof(uint16_t), str.data, str.length);
    }
    return sizeof(uint16_t) + str.length;
}

// Read ProtocolString from buffer - parses length prefix then data
// INTENTIONAL BUG: What bounds?
// Returns number of bytes consumed, or 0 on error
size_t Serializer::read_string(const uint8_t* buffer, size_t remaining, ProtocolString& str) {
    if (remaining < sizeof(uint16_t)) {
        return 0;  // Not enough data for length field
    }

    memcpy(&str.length, buffer, sizeof(uint16_t));

    if (str.length > 0) {
        str.data = new char[str.length];
        memcpy(str.data, buffer + sizeof(uint16_t), str.length);
    } else {
        str.data = nullptr;
    }

    return sizeof(uint16_t) + str.length;
}

} // namespace MessagingProtocol
