#pragma once
#include "http/message.h"
#include <cstdint>
#include <list>
#include <string>
#include <vector>

namespace leaf::network::http2 {

	extern const std::vector<std::pair<std::string_view, std::string_view>>
	static_header_pairs;

	union header_field_flag {
		struct {
			std::uint8_t indexed_field_index: 7;
			bool indexed_field: 1;
		};
		struct {
			std::uint8_t literal_index: 6;
			bool literal_value_field: 1;
			bool: 1;
		};
		struct {
			std::uint8_t table_max_size: 5;
			bool table_size_update: 1;
			bool not_table_size_update: 2;
		};
		struct {
			std::uint8_t literal_w_index: 4;
			bool never_indexed: 1;
			bool: 3;
		};
	};


	using header_list_t = std::list<std::pair<std::string, std::string>>;

	class header_packer {

		header_list_t dynamic_header_pairs;

		void shrink_();

		void emplace_front_(std::string name, std::string value);

		std::size_t dynamic_table_size_ = 4096;

	public:
		byte_string encode(const http::http_fields&);

		http::http_fields decode(byte_string_view source);
	};
}
