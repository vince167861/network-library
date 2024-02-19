#pragma once
#include "tls-utils/type.h"
#include "tls-utils/rng.h"
#include <memory>

namespace leaf::network::tls {

	struct key_exchange_manager {

		const named_group_t group;

		virtual byte_string public_key() const = 0;

		virtual byte_string shared_key() const = 0;

		virtual bool ready() const = 0;

		virtual void generate(random_number_generator&) = 0;

		virtual void exchange(byte_string_view remote_public_key) = 0;

		key_exchange_manager(named_group_t);

		virtual ~key_exchange_manager() = default;
	};


	struct unimplemented_group: key_exchange_manager {

		byte_string public_key() const override {
			throw std::exception();
		}

		byte_string shared_key() const override {
			throw std::exception();
		}

		bool ready() const override {
			return false;
		}

		void generate(random_number_generator&) override {
			throw std::exception();
		}

		void exchange(byte_string_view) override {
			throw std::exception();
		}

		unimplemented_group(named_group_t ng)
				: key_exchange_manager(ng) {
		}
	};

	std::unique_ptr<key_exchange_manager> get_key_manager(named_group_t, random_number_generator&);
}
