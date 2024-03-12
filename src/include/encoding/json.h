#pragma once
#include <variant>
#include <list>
#include <map>
#include <string>

namespace leaf::json {

	struct object;
	struct array;
	struct boolean;


	using element = std::variant<object, array, std::string, double, std::nullptr_t, bool>;


	struct object {

		using members_t = std::map<std::string, element>;

		members_t members;
	};


	struct array {

		using items_t = std::list<element>;

		items_t items;
	};

	element parse(std::string_view);

	std::string stringfy(const element&);
}
