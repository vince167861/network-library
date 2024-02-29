#include "http2/type.h"
#include "internal/macro.h"

std::format_context::iterator
std::formatter<leaf::network::http2::error_t>::format(const leaf::network::http2::error_t& error, format_context& context) const {
	using leaf::network::http2::error_t;
	auto it = context.out();
	switch (error) {
		build_enum_item2(it, error_t, no_error);
		build_enum_item2(it, error_t, protocol_error);
		build_enum_item2(it, error_t, internal_error);
		build_enum_item2(it, error_t, flow_control_error);
		build_enum_item2(it, error_t, settings_timeout);
		build_enum_item2(it, error_t, compression_error);
		default:
			it = std::ranges::copy("unknown", it).out;
	}
	return std::format_to(it, " ({:x})", static_cast<std::underlying_type_t<error_t>>(error));
}

std::format_context::iterator
std::formatter<leaf::network::http2::settings_t>::format(const leaf::network::http2::settings_t& type, format_context& context) const {
	using leaf::network::http2::settings_t;
	auto it = context.out();
	switch (type) {
		build_enum_item2(it, settings_t, header_table_size);
		build_enum_item2(it, settings_t, enable_push);
		build_enum_item2(it, settings_t, max_concurrent_stream);
		build_enum_item2(it, settings_t, initial_window_size);
		build_enum_item2(it, settings_t, max_frame_size);
		build_enum_item2(it, settings_t, max_header_list_size);
		default:
			it = std::ranges::copy("unknown", it).out;
	}
	return std::format_to(it, " ({:x})", static_cast<std::underlying_type_t<settings_t>>(type));
}
