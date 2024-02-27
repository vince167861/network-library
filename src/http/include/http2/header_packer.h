#pragma once

#include "../http/message.h"

#include <cstdint>
#include <list>
#include <string>
#include <vector>

namespace leaf::network::http2 {


	enum class static_header_t: uint8_t {
		invalid,
		/* :authority */ authority,
		/* :method = GET */ get,
		/* :method = POST */ post,
		/* :path = / */ root,
		/* :path = /index.html */ index_html,
		/* :scheme = http */ http,
		/* :scheme = https */ https,
		/* :status = 200 */ status_200,
		/* :status = 204 */ status_204,
		/* :status = 206 */ status_206,
		/* :status = 304 */ status_304,
		/* :status = 400 */ status_400,
		/* :status = 404 */ status_404,
		/* :status = 500 */ status_500,
		/* accept-charset */ accept_charset,
		/* accept-encoding = gzip, deflate */ accept_encoding,
		/* accept-language */ accept_lang,
		/* accept-ranges */ accept_ranges,
		/* accept */ accept,
		/* access-control-allow-origin */ access_control_allow_origin,
		/* age */ age,
		/* allow */ allow,
		/* authorization */ authorization,
		/* cache-control */ cache_control,
		/* content-disposition */ content_disposition,
		/* content-encoding */ content_encoding,
		/* content-language */ content_lang,
		/* content-length */ content_length,
		/* content-location */ content_location,
		/* content-range */ content_range,
		/* content-type */ content_type,
		/* cookie */ cookie,
		/* date */ date,
		/* etag */ etag,
		/* expect */ expect,
		/* expires */ expires,
		/* from */ from,
		/* host */ host,
		/* if-match */ if_match,
		/* if-modified-since */ if_modified_since,
		/* if-none-match */ if_none_match,
		/* if-range */ if_range,
		/* if-unmodified-since */ if_unmodified_since,
		/* last-modified */ last_modified,
		/* link */ link,
		/* location */ location,
		/* max-forwards */ max_forwards,
		/* proxy-authenticate */ proxy_authenticate,
		/* proxy-authorization */ proxy_authorization,
		/* range */ range,
		/* referer */ referer,
		/* refresh */ refresh,
		/* retry-after */ retry_after,
		/* server */ server,
		/* set-cookie */ set_cookie,
		/* strict-transport-security */ strict_transport_security,
		/* transfer-encoding */ transfer_encoding,
		/* user-agent */ user_agent,
		/* vary */ vary,
		/* via */ via,
		/* www-authenticate */ www_authenticate
	};

	extern const std::vector<std::pair<std::string_view, std::string>>
	static_header_pairs;


	using header_list_t = std::list<std::pair<std::string, std::string>>;

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


	class header_packer {

		header_list_t dynamic_header_pairs;

		void shrink_();

		void emplace_front_(std::string name, std::string value);

		std::size_t dynamic_table_size_ = 4096;

	public:
		byte_string encode(const http::http_fields&);

		http::http_fields decode(const byte_string_view source);
	};
}
