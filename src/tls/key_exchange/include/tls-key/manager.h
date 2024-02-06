#pragma once

#include "tls-utils/type.h"
#include "tls-utils/rng.h"

#include <memory>

namespace leaf::network::tls {

	class key_exchange_manager {
	public:
		const named_group_t group;

		virtual std::string public_key() = 0;

		virtual std::string shared_key() const = 0;

		virtual bool key_ready() const = 0;

		virtual void generate_private_key(random_number_generator&) = 0;

		virtual void exchange_key(std::string_view remote_public_key) = 0;

		key_exchange_manager(named_group_t);

		virtual ~key_exchange_manager() = default;
	};


	class unimplemented_group: public key_exchange_manager {
	public:
		std::string public_key() override {
			throw std::exception();
		}

		void exchange_key(std::string_view remote_public_key) override {
			throw std::exception();
		}

		bool key_ready() const override {
			return false;
		}

		std::string shared_key() const override {
			throw std::exception();
		}

		unimplemented_group(named_group_t ng)
				: key_exchange_manager(ng) {}

		void generate_private_key(random_number_generator& generator) override {
			throw std::exception{};
		}
	};

	std::unique_ptr<key_exchange_manager> get_key_manager(named_group_t, random_number_generator&);
}
