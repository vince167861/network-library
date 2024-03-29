#include "http2/header_packer.h"
#include "http2/huffman.h"
#include <ranges>

const std::vector<std::pair<std::string_view, std::string_view>>
static_header_pairs {
		{"", ""},
		{":authority", ""},
		{":method", "GET"},
		{":method", "POST"},
		{":path", "/"},
		{":path", "/index.html"},
		{":scheme", "http"},
		{":scheme", "https"},
		{":status", "200"},
		{":status", "204"},
		{":status", "206"},
		{":status", "304"},
		{":status", "400"},
		{":status", "404"},
		{":status", "500"},
		{"accept-charset", ""},
		{"accept-encoding", "gzip, deflate"},
		{"accept-language", ""},
		{"accept-ranges", ""},
		{"accept", ""},
		{"access-control-allow-origin", ""},
		{"age", ""},
		{"allow", ""},
		{"authorization", ""},
		{"cache-control", ""},
		{"content-disposition", ""},
		{"content-encoding", ""},
		{"content-language", ""},
		{"content-length", ""},
		{"content-location", ""},
		{"content-range", ""},
		{"content-type", ""},
		{"cookie", ""},
		{"date", ""},
		{"etag", ""},
		{"expect", ""},
		{"expires", ""},
		{"from", ""},
		{"host", ""},
		{"if-match", ""},
		{"if-modified-since", ""},
		{"if-none-match", ""},
		{"if-range", ""},
		{"if-unmodified-since", ""},
		{"last-modified", ""},
		{"link", ""},
		{"location", ""},
		{"max-forwards", ""},
		{"proxy-authenticate", ""},
		{"proxy-authorization", ""},
		{"range", ""},
		{"referer", ""},
		{"refresh", ""},
		{"retry-after", ""},
		{"server", ""},
		{"set-cookie", ""},
		{"strict-transport-security", ""},
		{"transfer-encoding", ""},
		{"user-agent", ""},
		{"vary", ""},
		{"via", ""},
		{"www-authenticate", ""},
	};

namespace network::http2 {

	void write_integer(byte_string& dst, const std::uint8_t prefix_size, std::uintmax_t value) {
		const auto max_value = (1u << prefix_size) - 1;
		if (value < max_value) {
			dst.back() = dst.back() & ~max_value | value;
			return;
		}
		dst.back() &= max_value;
		for (value -= max_value; value >= 128; value >>= 7)
			dst.push_back(value & 127 | 128);
		dst.push_back(value);
	}

	void read_integer(auto& it, const std::uint8_t prefix_size, std::uintmax_t& value) {
		const auto max_value = (1u << prefix_size) - 1;
		value = *it++ & max_value;
		if (value < max_value)
			return;
		std::size_t i = 0;
		while (true) {
			const auto octet = *it++;
			value += octet & 127 << i;
			if (!(octet & 128))
				break;
			i += 7;
		}
	}

	void header_packer::shrink_() {
		if (dynamic_header_pairs.size() > dynamic_table_size_)
			dynamic_header_pairs.resize(dynamic_table_size_);
	}

	void header_packer::emplace_front_(std::string name, std::string value) {
		dynamic_header_pairs.emplace_front(std::move(name), std::move(value));
		shrink_();
	}

	template<class T1, class T2, class U1, class U2>
	constexpr bool operator==(const std::pair<T1, T2>& lhs, const std::pair<U1, U2>& rhs) {
		return lhs.first == rhs.first && lhs.second == rhs.second;
	}

	byte_string header_packer::encode(const http::fields& headers) {
		byte_string ret;
		for (auto& pair: headers) {
			auto& [name, value] = pair;
			const auto [ind, indexed] = [&] -> std::pair<std::uintmax_t, bool> {
				if (const auto it = std::ranges::find_if(static_header_pairs, [&](auto& lhs){ return lhs == pair; }); it != static_header_pairs.end())
					return {static_cast<std::uintmax_t>(std::distance(static_header_pairs.begin(), it)), true};
				if (const auto it = std::ranges::find_if(dynamic_header_pairs, [&](auto& lhs){ return lhs == pair; }); it != dynamic_header_pairs.end())
					return {static_cast<std::uintmax_t>(std::distance(dynamic_header_pairs.begin(), it) + 62), true};
				const auto static_keys = static_header_pairs | std::views::keys;
				if (const auto it = std::ranges::find(static_keys, name); it != static_keys.end())
					return {static_cast<std::uintmax_t>(std::distance(static_keys.begin(), it)), false};
				const auto dynamic_keys = dynamic_header_pairs | std::views::keys;
				if (const auto it = std::ranges::find(dynamic_keys, name); it != dynamic_keys.end())
					return {static_cast<std::uintmax_t>(std::distance(dynamic_keys.begin(), it) + 62), false};
				return {0, false};
			}();
			if (indexed) {
				ret.push_back(128);
				write_integer(ret, 7, ind);
				continue;
			}
			ret.push_back(64);
			write_integer(ret, 6, ind);
			if (ind == 0) {
				ret.push_back(0);
				write_integer(ret, 7, name.size());
				ret += reinterpret_cast<const byte_string&>(name);
			}
			ret.push_back(0);
			write_integer(ret, 7, value.size());
			ret += reinterpret_cast<const byte_string&>(value);
			emplace_front_(name, value);
		}
		return ret;
	}

	http::fields header_packer::decode(const byte_string_view source) {
		http::fields members;
		uint64_t value;
		for (auto it = source.begin(), end = source.end(); it != end;) {
			if (const auto header = reinterpret_cast<const header_field_flag&>(*it); header.indexed_field) {
				read_integer(it, 7, value);
				std::pair<std::string, std::string> pair;
				if (value < 62) {
					auto& [name, field] = static_header_pairs[value];
					members.append(name, field);
				} else {
					const auto ind = value - 62;
					if (ind > dynamic_header_pairs.size())
						throw std::out_of_range("dynamic header table");
					auto& [name, field] = *std::next(dynamic_header_pairs.begin(), ind);
					members.append(name, field);
				}
			} else if (!header.not_table_size_update && header.table_size_update) {
				read_integer(it, 5, value);
				dynamic_table_size_ = value;
				shrink_();
			} else {
				if (header.literal_value_field)
					read_integer(it, 6, value);
				else
					// TODO: never-indexed(0001) and without-indexed(0000) is processed identically
					read_integer(it, 4, value);
				std::string name;
				if (value == 0) {
					const bool huffman = *it & 0x80;
					read_integer(it, 7, value);
					const auto begin = it;
					std::advance(it, value);
					if (huffman)
						name = internal::from_huffman({begin, it});
					else
						name = {begin, it};
				} else if (value < 62)
					name = std::next(static_header_pairs.begin(), value)->first;
				else
					name = std::next(dynamic_header_pairs.begin(), value - 62)->first;
				const bool huffman = *it & 0x80;
				read_integer(it, 7, value);
				const auto begin = it;
				std::advance(it, value);
				const auto field = [&] -> std::string {
					if (huffman)
						return internal::from_huffman({begin, it});
					return {begin, it};
				}();
				emplace_front_(name, field);
				members.append(std::move(name), std::move(field));
			}
		}
		return members;
	}
}
