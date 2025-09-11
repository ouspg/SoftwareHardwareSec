/**
 * Basic unit tests for our protocol
 *
 * PURPOSE: These tests verify basic functionality but are intentionally LIMITED.
 * They test the "happy path" scenarios where everything works correctly.
 *
 * This demonstrates why unit tests alone are insufficient
 * for memory safety. These tests will all pass even though the code contains
 * serious memory bugs that can cause crashes, data corruption, and security
 * vulnerabilities.
 *
 * WHAT THESE TESTS MAY MISS:
 * - Memory leaks in assignment operators
 * - Double-free bugs in copy constructors
 * - Buffer overflows in deserialization
 * - Integer overflows
 * - Malformed input handling that result to even other scenarios
 *
 * TO FIND THE REAL BUGS: Use AddressSanitizer, Valgrind, or fuzzing tools.
 */

#include "../lib/protocol.h"
#include <cassert>
#include <iostream>
#include <cstring>

using namespace MessagingProtocol;

// Tests basic chat message serialization round-trip
// This only tests the happy path - valid input, normal sizes
void test_chat_message_basic() {
    std::cout << "Testing basic chat message..." << std::endl;

    Message msg(CHAT_MESSAGE);
    msg.chat->username.set_data("alice");
    msg.chat->message.set_data("Hello World!");
    msg.chat->timestamp = 1234567890;
    msg.chat->priority = 5;

    // Test serialization - convert Message object to binary format
    auto buffer = Serializer::serialize(msg);
    assert(buffer.size() > sizeof(MessageHeader));  // Sanity check: has header + payload

    // Test deserialization - convert binary back to Message object
    // NOTE: This only tests with valid, well-formed data from our own serializer
    Message* deserialized = Serializer::deserialize(buffer.data(), buffer.size());
    assert(deserialized != nullptr);
    assert(deserialized->header.type == CHAT_MESSAGE);
    assert(deserialized->chat->timestamp == 1234567890);
    assert(deserialized->chat->priority == 5);
    assert(deserialized->chat->username.to_string() == "alice");
    assert(deserialized->chat->message.to_string() == "Hello World!");

    delete deserialized;
    std::cout << "✓ Chat message test passed" << std::endl;
}

// Tests UserInfo message type
void test_user_info_basic() {
    std::cout << "Testing basic user info..." << std::endl;

    Message msg(USER_INFO);
    msg.user_info->username.set_data("bob");
    msg.user_info->email.set_data("bob@example.com");
    msg.user_info->user_id = 42;
    msg.user_info->status = 1;

    // Simple case - no tags
    msg.user_info->tag_count = 0;
    msg.user_info->tags = nullptr;

    auto buffer = Serializer::serialize(msg);
    Message* deserialized = Serializer::deserialize(buffer.data(), buffer.size());

    assert(deserialized != nullptr);
    assert(deserialized->header.type == USER_INFO);
    assert(deserialized->user_info->user_id == 42);
    assert(deserialized->user_info->username.to_string() == "bob");
    assert(deserialized->user_info->email.to_string() == "bob@example.com");

    delete deserialized;
    std::cout << "✓ User info test passed" << std::endl;
}

// Tests binary data handling with small, well-formed chunk
void test_file_chunk_basic() {
    std::cout << "Testing basic file chunk..." << std::endl;

    Message msg(FILE_CHUNK);
    msg.file_chunk->filename.set_data("test.txt");
    msg.file_chunk->chunk_id = 0;
    msg.file_chunk->total_chunks = 1;
    msg.file_chunk->chunk_size = 5;

    // Small data chunk - using tiny size avoids triggering bounds checking bugs
    msg.file_chunk->data = new uint8_t[5];
    memcpy(msg.file_chunk->data, "hello", 5);  // Known safe: size matches allocation

    // Serialize and deserialize - this creates a NEW Message object
    auto buffer = Serializer::serialize(msg);
    Message* deserialized = Serializer::deserialize(buffer.data(), buffer.size());

    assert(deserialized != nullptr);
    assert(deserialized->header.type == FILE_CHUNK);
    assert(deserialized->file_chunk->chunk_id == 0);
    assert(deserialized->file_chunk->filename.to_string() == "test.txt");
    assert(deserialized->file_chunk->chunk_size == 5);
    assert(memcmp(deserialized->file_chunk->data, "hello", 5) == 0);

    delete deserialized;
    std::cout << "✓ File chunk test passed" << std::endl;
}

// Tests ProtocolString operations - but won't catch memory management bugs
// These operations look correct but have hidden memory safety issues
void test_string_operations() {
    std::cout << "Testing string operations..." << std::endl;

    ProtocolString str1;
    str1.set_data("test string");
    assert(str1.to_string() == "test string");
    assert(str1.length == 11);

    // Test copy constructor - LOOKS correct but has memory safety bug
    ProtocolString str2(str1);
    assert(str2.to_string() == "test string");

    // Test assignment operator - LOOKS correct but leaks memory
    // Memory leak happens here but won't be detected by this test
    ProtocolString str3;
    str3 = str1;
    assert(str3.to_string() == "test string");

    std::cout << "✓ String operations test passed" << std::endl;
}

// Tests edge case of empty strings - this is actually important!
// Empty/null strings often trigger boundary condition bugs
void test_empty_strings() {
    std::cout << "Testing empty strings..." << std::endl;

    Message msg(CHAT_MESSAGE);
    msg.chat->username.set_data("");
    msg.chat->message.set_data("");

    auto buffer = Serializer::serialize(msg);
    Message* deserialized = Serializer::deserialize(buffer.data(), buffer.size());

    assert(deserialized != nullptr);
    assert(deserialized->chat->username.to_string() == "");
    assert(deserialized->chat->message.to_string() == "");

    delete deserialized;
    std::cout << "✓ Empty strings test passed" << std::endl;
}

// Tests UserInfo with tags array
void test_user_with_tags_simple() {
    std::cout << "Testing user with tags (simple)..." << std::endl;

    Message msg(USER_INFO);
    msg.user_info->username.set_data("charlie");
    msg.user_info->email.set_data("charlie@test.com");
    msg.user_info->user_id = 123;
    msg.user_info->tag_count = 2;

    msg.user_info->tags = new ProtocolString[2];
    msg.user_info->tags[0].set_data("admin");
    msg.user_info->tags[1].set_data("vip");

    auto buffer = Serializer::serialize(msg);
    Message* deserialized = Serializer::deserialize(buffer.data(), buffer.size());

    assert(deserialized != nullptr);
    assert(deserialized->user_info->tag_count == 2);
    assert(deserialized->user_info->tags[0].to_string() == "admin");
    assert(deserialized->user_info->tags[1].to_string() == "vip");

    delete deserialized;  // This deletion is safe - deserialized object owns its memory
    std::cout << "✓ User with tags test passed" << std::endl;
}

int main() {
    std::cout << "Running protocol tests..." << std::endl;

    try {
        test_chat_message_basic();
        test_user_info_basic();
        test_file_chunk_basic();
        test_string_operations();
        test_empty_strings();
        test_user_with_tags_simple();

        std::cout << "\n✓ All basic tests passed!" << std::endl;
        std::cout << "Note: These tests only cover happy path scenarios." << std::endl;
        std::cout << "Memory bugs and edge cases require fuzzing and sanitizers to detect." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
