
#include "acutest.h"

void test_protobuf_handshake();
void test_protobuf_negotiation();
void test_send_receive();

TEST_LIST = {
        { "Test protobuf handshake", test_protobuf_handshake },
        { "Test protobuf negotiation", test_protobuf_negotiation },
        { "Test send/receive data", test_send_receive },
        { NULL, NULL }
};