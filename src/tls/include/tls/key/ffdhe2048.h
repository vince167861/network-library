#pragma once
#include "manager.h"
#include "big_number.h"

namespace network::tls {

	class ffdhe2048_manager final : public key_exchange_manager {

		bool has_key;

		big_unsigned secret_key_, public_key_, shared_key_;

	public:
		explicit ffdhe2048_manager();

		explicit ffdhe2048_manager(big_unsigned secret_key);

		byte_string public_key() const override;

		byte_string shared_key() const override;

		bool ready() const override;

		void generate(random_source&) override;

		void exchange(byte_string_view remote_public_key) override;
	};

	const big_unsigned ffdhe2048_p("ffffffffffffffffADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF");
}
