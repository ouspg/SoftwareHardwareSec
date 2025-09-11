#include "../lib/protocol.h"
#include <iostream>
#include <vector>

using namespace MessagingProtocol;

void demo_chat_message() {
    std::cout << "\n=== Chat message demo ===\n" << std::endl;

    Message msg(CHAT_MESSAGE);
    msg.header.message_id = 1001;
    msg.chat->username.set_data("Alice");
    msg.chat->message.set_data("Hello everyone! How is the protocol working?");
    msg.chat->timestamp = 1699123456;
    msg.chat->priority = 3;

    std::cout << "Original message:" << std::endl;
    std::cout << "  User: " << msg.chat->username.to_string() << std::endl;
    std::cout << "  Message: " << msg.chat->message.to_string() << std::endl;
    std::cout << "  Timestamp: " << msg.chat->timestamp << std::endl;
    std::cout << "  Priority: " << (int)msg.chat->priority << std::endl;

    // Serialize
    auto buffer = Serializer::serialize(msg);
    std::cout << "Serialized size: " << buffer.size() << " bytes" << std::endl;

    // Deserialize
    Message* decoded = Serializer::deserialize(buffer.data(), buffer.size());
    if (decoded) {
        std::cout << "Decoded message:" << std::endl;
        std::cout << "  User: " << decoded->chat->username.to_string() << std::endl;
        std::cout << "  Message: " << decoded->chat->message.to_string() << std::endl;
        std::cout << "  Timestamp: " << decoded->chat->timestamp << std::endl;
        delete decoded;
    }
}

void demo_user_info() {
    std::cout << "\n=== User info demo ===\n" << std::endl;

    Message msg(USER_INFO);
    msg.header.message_id = 2001;
    msg.user_info->username.set_data("bob_admin");
    msg.user_info->email.set_data("bob@company.com");
    msg.user_info->user_id = 12345;
    msg.user_info->status = 1; // online

    // Add some tags
    msg.user_info->tag_count = 3;
    msg.user_info->tags = new ProtocolString[3];
    msg.user_info->tags[0].set_data("admin");
    msg.user_info->tags[1].set_data("premium");
    msg.user_info->tags[2].set_data("verified");

    std::cout << "User info:" << std::endl;
    std::cout << "  Username: " << msg.user_info->username.to_string() << std::endl;
    std::cout << "  Email: " << msg.user_info->email.to_string() << std::endl;
    std::cout << "  User ID: " << msg.user_info->user_id << std::endl;
    std::cout << "  Tags: ";
    for (int i = 0; i < msg.user_info->tag_count; i++) {
        std::cout << msg.user_info->tags[i].to_string();
        if (i < msg.user_info->tag_count - 1) std::cout << ", ";
    }
    std::cout << std::endl;

    // Serialize and deserialize
    auto buffer = Serializer::serialize(msg);
    std::cout << "Serialized size: " << buffer.size() << " bytes" << std::endl;

    Message* decoded = Serializer::deserialize(buffer.data(), buffer.size());
    if (decoded) {
        std::cout << "Decoded successfully with " << decoded->user_info->tag_count << " tags" << std::endl;
        delete decoded;
    }
}

void demo_file_chunk() {
    std::cout << "\n=== File Chunk demo ===\n" << std::endl;

    Message msg(FILE_CHUNK);
    msg.header.message_id = 3001;
    msg.file_chunk->filename.set_data("document.pdf");
    msg.file_chunk->chunk_id = 0;
    msg.file_chunk->total_chunks = 5;
    msg.file_chunk->chunk_size = 1024;

    // Create some dummy file data
    msg.file_chunk->data = new uint8_t[1024];
    for (int i = 0; i < 1024; i++) {
        msg.file_chunk->data[i] = i % 256;
    }

    std::cout << "File chunk info:" << std::endl;
    std::cout << "  Filename: " << msg.file_chunk->filename.to_string() << std::endl;
    std::cout << "  Chunk: " << msg.file_chunk->chunk_id + 1 << "/" << msg.file_chunk->total_chunks << std::endl;
    std::cout << "  Size: " << msg.file_chunk->chunk_size << " bytes" << std::endl;

    auto buffer = Serializer::serialize(msg);
    std::cout << "Serialized size: " << buffer.size() << " bytes" << std::endl;

    Message* decoded = Serializer::deserialize(buffer.data(), buffer.size());
    if (decoded) {
        std::cout << "Decoded file chunk successfully" << std::endl;
        // Verify first few bytes
        bool data_ok = true;
        for (int i = 0; i < 10; i++) {
            if (decoded->file_chunk->data[i] != (i % 256)) {
                data_ok = false;
                break;
            }
        }
        std::cout << "Data integrity: " << (data_ok ? "OK" : "FAILED") << std::endl;
        delete decoded;
    }
}

void demo_copy_operations() {
    std::cout << "\n=== Copy Operations demo (may trigger bugs) ===" << std::endl;

    // This will trigger memory bugs in copy operations
    Message original(USER_INFO);
    original.user_info->username.set_data("testuser");
    original.user_info->tag_count = 2;
    original.user_info->tags = new ProtocolString[2];
    original.user_info->tags[0].set_data("tag1");
    original.user_info->tags[1].set_data("tag2");

    std::cout << "Creating copy of message with tags..." << std::endl;

    // This will trigger the shallow copy bug
    Message copy1(original);
    std::cout << "Copy 1 created" << std::endl;

    std::cout << "Copies created successfully (bugs may manifest on destruction)" << std::endl;
}

int main() {
    std::cout << "Demo program" << std::endl;
    std::cout << "===================" << std::endl;
    std::cout << "This demo showcases the protocol functionality." << std::endl;
    std::cout << "Some operations may trigger memory bugs that can be" << std::endl;
    std::cout << "detected with AddressSanitizer, Valgrind, or fuzzing." << std::endl;

    try {
        demo_chat_message();
        demo_user_info();
        demo_file_chunk();
        demo_copy_operations();

        std::cout << "\n=== Demo completed ===" << std::endl;
        std::cout << "If running with sanitizers, check for reported issues." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Demo crashed with exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Demo crashed with unknown exception" << std::endl;
        return 1;
    }

    return 0;
}
