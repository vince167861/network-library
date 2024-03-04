#pragma once
#include "stream_endpoint.h"
#include "http/message.h"

namespace network::http {

	enum class message_body_parse_error {
		invalid_chunk_line_folding, invalid_chunk_size, invalid_content_length, cannot_determine_length
	};

	std::expected<std::string, message_body_parse_error>
	read_message_content(stream_endpoint&, const fields&, message_type);
}
