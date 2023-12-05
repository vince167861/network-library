#pragma once

#define build_enum_item(s, ns, name) case ns::name: s << #name; break;
#define build_enum_item_extra(s, ns, name, extra) case ns::name: s << #name extra; break;
