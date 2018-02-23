//
// Created by Roman Kutashenko on 2/23/18.
//

#define TEST_NO_MAIN
#include "acutest.h"

#include <stdbool.h>

#include <pb_encode.h>
#include <pb_decode.h>
#include <handshake.pb.h>
#include <negotiation.pb.h>

void
test_protobuf_handshake() {
    // This is the buffer where we will store our message.
    uint8_t buffer[128];
    size_t message_length;
    bool status;

    bool _continuous_rekey = true;
    size_t _max_message_size = 1520;
    const char *_certificate_type = "Noise_XX_448_ChaChaPoly_BLAKE2s";

    // Encode message
    {
        handshake_initial_payload message = handshake_initial_payload_init_zero;

        // Create a stream that will write to our buffer.
        pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));


        message.max_message_size = _max_message_size;
        message.continuous_rekey = _continuous_rekey;


        if (strlen(_certificate_type) + 1 > sizeof(message.certificate_type)) {
            TEST_CHECK_(false, "Too long certificate type %d.", strlen(_certificate_type) + 1);
            return;
        }

        strcpy(message.certificate_type, _certificate_type);

        // Now we are ready to encode the message!
        status = pb_encode(&stream, handshake_initial_payload_fields, &message);
        message_length = stream.bytes_written;

        // Then just check for any errors ...
        if (!status) {
            TEST_CHECK_(false, "Encoding failed: %s\n", PB_GET_ERROR(&stream));
            return;
        }
    }

    // Decode message
    {
        handshake_initial_payload message = handshake_initial_payload_init_zero;

        // Create a stream that reads from the buffer.
        pb_istream_t stream = pb_istream_from_buffer(buffer, message_length);

        // Now we are ready to decode the message.
        status = pb_decode(&stream, handshake_initial_payload_fields, &message);

        // Check for errors ...
        if (!status) {
            TEST_CHECK_(false, "Decoding failed: %s\n", PB_GET_ERROR(&stream));
            return;
        }

        TEST_CHECK(message.max_message_size == _max_message_size);
        TEST_CHECK(message.continuous_rekey == _continuous_rekey);
        TEST_CHECK(0 == strncmp(message.certificate_type, _certificate_type, sizeof(buffer)));
    }
}

void
test_protobuf_negotiation() {
    // This is the buffer where we will store our message.
    uint8_t buffer[1024];
    size_t message_length;
    bool status;

    bool _continuous_rekey = true;
    size_t _max_message_size = 1520;
    const char *_protocol_type = "Noise_XX_448_ChaChaPoly_BLAKE2s";
    const size_t _protocol_type_cnt = 3;

    // Encode message
    {
        negotiation_initial_data message = negotiation_initial_data_init_zero;

        // Create a stream that will write to our buffer.
        pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));

        if (strlen(_protocol_type) + 1 > sizeof(message.initial_protocol)) {
            TEST_CHECK_(false, "Too long initial protocol type %d.", strlen(_protocol_type) + 1);
            return;
        }

        strcpy(message.initial_protocol, _protocol_type);

        message.switch_protocols_count = _protocol_type_cnt;
        message.retry_protocols_count = _protocol_type_cnt;
        int i;
        for (i = 0; i < _protocol_type_cnt; ++i) {
            strcpy(message.switch_protocols[i], _protocol_type);
            strcpy(message.retry_protocols[i], _protocol_type);
        }

        // Now we are ready to encode the message !
        status = pb_encode(&stream, negotiation_initial_data_fields, &message);
        message_length = stream.bytes_written;

        // Then just check for any errors ...
        if (!status) {
            TEST_CHECK_(false, "Encoding failed: %s\n", PB_GET_ERROR(&stream));
            return;
        }
    }

    // Decode message
    {
        negotiation_initial_data message = negotiation_initial_data_init_zero;

        // Create a stream that reads from the buffer.
        pb_istream_t stream = pb_istream_from_buffer(buffer, message_length);

        // Now we are ready to decode the message.
        status = pb_decode(&stream, negotiation_initial_data_fields, &message);

        // Check for errors ...
        if (!status) {
            TEST_CHECK_(false, "Decoding failed: %s\n", PB_GET_ERROR(&stream));
            return;
        }

        TEST_CHECK(0 == strncmp(message.initial_protocol, _protocol_type, sizeof(buffer)));
        TEST_CHECK(message.switch_protocols_count == _protocol_type_cnt);
        TEST_CHECK(message.retry_protocols_count == _protocol_type_cnt);
        int i;
        for (i = 0; i < _protocol_type_cnt; ++i) {
            TEST_CHECK(0 == strncmp(message.switch_protocols[i], _protocol_type, sizeof(buffer)));
            TEST_CHECK(0 == strncmp(message.retry_protocols[i], _protocol_type, sizeof(buffer)));
        }
    }
}