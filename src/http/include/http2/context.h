#pragma once

#include "http2/type.h"
#include "http2/header_packer.h"

#include <coroutine>
#include <list>
#include <map>


namespace leaf::network::http2 {

	class stream_handler;


	class context {
		std::map<std::uint32_t, stream_handler> handlers_;

		std::list<std::coroutine_handle<>> tasks_;

		uint32_t next_remote_stream_id_();

		uint32_t next_local_stream_id_();

	public:
		const enum class endpoint_type_t: uint8_t {
			server, client
		} endpoint_type;

		endpoint_state_t local_config, remote_config;

		header_packer local_packer, remote_packer;

		void update_remote_config(const setting_values_t&);

		[[nodiscard]] setting_values_t pack_settings() const;

		stream_handler& local_open_stream();

		stream_handler& remote_reserve_stream(uint32_t);

		stream_handler& get_stream(uint32_t);

		void remote_closing(uint32_t last_stream_id);

		explicit context(endpoint_type_t);

		void add_task(std::coroutine_handle<> handle);

		bool process_tasks();

		bool has_pending_streams() const;
	};
}
