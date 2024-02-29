#pragma once

using std::literals::operator ""sv;

#define build_enum_item(s, ns, name) case ns::name: s << #name; break;
#define build_enum_item_extra(s, ns, name, extra) case ns::name: s << #name extra; break;
#define build_enum_item2(s, ns, name) case ns::name: s = std::ranges::copy(#name##sv, s).out; break;
#define build_enum_item_extra2(s, ns, name, extra) case ns::name: s = std::ranges::copy(#name extra##sv, s).out; break;
