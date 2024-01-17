#pragma once

#include "http2/type.h"
#include "http2/header_packer.h"

#include <coroutine>
#include <list>
#include <map>
#include <memory>


namespace leaf::network::http2 {

	class stream_handler;


	class context {
		std::map<stream_id_t, std::unique_ptr<stream_handler>> handlers_;

		std::list<std::coroutine_handle<>> tasks_;

	public:
		const enum class endpoint_type_t: std::uint8_t {
			server, client
		} endpoint_type;

		endpoint_state_t local_config, remote_config;

		header_packer local_packer, remote_packer;

		void update_remote_config(const setting_values_t&);

		[[nodiscard]] setting_values_t pack_settings() const;

		stream_id_t next_remote_stream_id();

		stream_id_t next_local_stream_id();

		void register_handler(std::unique_ptr<stream_handler> handler);

		stream_handler& get_stream(stream_id_t);

		void remote_closing(uint32_t last_stream_id);

		explicit context(endpoint_type_t);

		void add_task(std::coroutine_handle<> handle);

		bool process_tasks();

		bool has_pending_streams() const;
	};
}
