#include "tls-record/record.h"

#include "tls-handshake/handshake.h"
#include "tls-context/context.h"
#include "tls-record/alert.h"

#include "utils.h"
#include <utility>
#include <algorithm>
#include <iostream>

namespace leaf::network::tls {

	std::list<std::string> record::build(context& context) {
		std::list<std::string> packets;
		auto content = build_content_();
		for (auto ptr = content.begin(); ptr != content.end(); ) {
			std::string packet;
			//	type
			content_type_t t = encrypted ? content_type_t::application_data : type;
			reverse_write(packet, t);
			//	legacy_record_version
			reverse_write(packet, legacy_record_version);
			uint16_t length = std::min<std::ptrdiff_t>(std::distance(ptr, content.end()), 1 << 14);
			std::string_view fragment{ptr, ptr + length};
			if (!encrypted) {
				//	length
				reverse_write(packet, length);
				//	fragment
				packet += fragment;
			} else {
				std::string payload(fragment);
				reverse_write(payload, type);
				uint16_t encrypted_length = payload.size() + 16;
				//	length
				reverse_write(packet, encrypted_length);
				//	fragment
				auto&& encrypted_record = context.encrypt(packet, payload);
				packet += encrypted_record;
			}
			packets.push_back(std::move(packet));
			ptr += length;
		}
		return packets;
	}

	record::record(content_type_t type, bool encrypted)
			: encrypted(encrypted), type(type) {
	}

	void record::parse(context& context, const std::function<void(record&)>& callback) {
		auto&& header = context.client_.read(sizeof type + sizeof legacy_record_version + sizeof(uint16_t));
		auto ptr = header.cbegin();
		content_type_t type;
		protocol_version_t version;
		uint16_t length;
		reverse_read(ptr, type);
		reverse_read(ptr, version);
		reverse_read(ptr, length);

		const auto fragment = context.client_.read(length);
		const std::string_view fragment_view = fragment;

		switch (type) {
			case content_type_t::handshake:
				for (auto f_ptr = fragment_view.begin(); f_ptr != fragment_view.end(); ) {
					auto msg_ptr = handshake::parse(context, f_ptr, false);
					if (msg_ptr)
						callback(*msg_ptr);
				}
				break;
			case content_type_t::alert: {
				alert alert(fragment_view, false);
				callback(alert);
				break;
			}
			case content_type_t::application_data: {
				auto&& plain_text = context.decrypt(header, fragment_view);
				std::string_view plain_view = plain_text;
				auto&& end = std::find_if(plain_view.rbegin(), plain_view.rend(), [](auto c){ return c != 0; }).base() - 1;
				switch (static_cast<content_type_t>(*end)) {
					case content_type_t::handshake:
						for (auto p_ptr = plain_view.begin(); p_ptr != end; ) {
							auto msg_ptr = handshake::parse(context, p_ptr, true);
							if (msg_ptr)
								callback(*msg_ptr);
						}
						break;
					case content_type_t::alert: {
						alert alert({plain_view.begin(), end}, true);
						callback(alert);
						break;
					}
					case content_type_t::application_data: {
						application_data record({plain_view.begin(), end});
						callback(record);
						break;
					}
					default:
						throw std::exception();
				}
				break;
			}
			case content_type_t::change_cipher_spec:
				if (fragment != "\1")
					throw alert::unexpected_message();
				break;
		}
	}

	std::ostream& operator<<(std::ostream& s, const record& obj) {
		obj.print(s);
		return s;
	}

	application_data::application_data(std::string_view data)
			: record(content_type_t::application_data, true), data(data) {
	}

	std::string application_data::build_content_() {
		return data;
	}

	void application_data::print(std::ostream& s) const {
		s << "Application data\n";
	}
}
