#pragma once
#include "random_source.h"
#include "tls/util/type.h"
#include <memory>

namespace network::tls {

	struct key_exchange_manager {

		const named_group_t group;

		virtual byte_string public_key() const = 0;

		virtual byte_string shared_key() const = 0;

		virtual bool ready() const = 0;

		virtual void generate(random_source&) = 0;

		virtual void exchange(byte_string_view remote_public_key) = 0;

		key_exchange_manager(named_group_t group)
				: group(group) {
		}

		virtual ~key_exchange_manager() = default;
	};


	struct unimplemented_group final: key_exchange_manager {

		byte_string public_key() const override {
			throw std::exception();
		}

		byte_string shared_key() const override {
			throw std::exception();
		}

		bool ready() const override {
			return false;
		}

		void generate(random_source&) override {
			throw std::exception();
		}

		void exchange(byte_string_view) override {
			throw std::exception();
		}

		unimplemented_group(named_group_t group)
				: key_exchange_manager(group) {
		}
	};

	std::unique_ptr<key_exchange_manager> get_key_manager(named_group_t, random_source&);
}
