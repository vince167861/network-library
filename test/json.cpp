#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "encoding/json.h"

using namespace leaf::json;
using namespace testing;

TEST(parse, boolean_valid) {
	EXPECT_THAT(parse("true"), VariantWith<bool>(IsTrue()));
	EXPECT_THAT(parse("false"), VariantWith<bool>(IsFalse()));
}

TEST(parse, boolean_invalid) {
	ASSERT_THROW(parse("t rue"), std::runtime_error);
}

TEST(parse, string_valid) {
	EXPECT_THAT(parse(R"("true")"), VariantWith<std::string>("true"));
	EXPECT_THAT(parse(R"("\u1234\u5678")"), VariantWith<std::string>("\u1234\u5678"));
}

TEST(parse, string_invalid) {
	EXPECT_THROW(parse(R"("true)"), std::runtime_error);
	EXPECT_THROW(parse(R"(tr""ue)"), std::runtime_error);
}

TEST(parse, number_valid) {
	EXPECT_THAT(parse("123"), VariantWith<double>(DoubleEq(123)));
	EXPECT_THAT(parse("123e2"), VariantWith<double>(DoubleEq(123e2)));
	EXPECT_THAT(parse("-123.0e2"), VariantWith<double>(DoubleEq(-123.0e2)));
	EXPECT_THAT(parse("-1.32"), VariantWith<double>(DoubleEq(-1.32)));
	EXPECT_THAT(parse("-1.32e-2"), VariantWith<double>(DoubleEq(-1.32e-2)));
}

TEST(parse, number_invalid) {
	EXPECT_THROW(parse("123.e2"), std::runtime_error);
	EXPECT_THROW(parse("-01.32"), std::runtime_error);
}

TEST(parse, null) {
	EXPECT_THAT(parse("null"), VariantWith<std::nullptr_t>(IsNull()));
	EXPECT_THROW(parse("nul"), std::runtime_error);
}

TEST(parse, object_valid) {
	EXPECT_THAT(
			parse(R"({"name1": "value1"})"),
			VariantWith<object>(Field(&object::members, UnorderedElementsAre(
					Pair("name1", VariantWith<std::string>("value1"))))));
	EXPECT_THAT(
			parse(R"({"name1": "value1", " name2": 123})"),
			VariantWith<object>(Field(&object::members, UnorderedElementsAre(
					Pair("name1", VariantWith<std::string>("value1")),
					Pair(" name2", VariantWith<double>(DoubleEq(123)))))));
	EXPECT_THAT(
			parse(R"({"name1": "value1", )" "\t" R"(" name2": 123,  "n ame3"  :null  })"),
			VariantWith<object>(Field(&object::members, UnorderedElementsAre(
					Pair("name1", VariantWith<std::string>("value1")),
					Pair(" name2", VariantWith<double>(DoubleEq(123))),
					Pair("n ame3", VariantWith<std::nullptr_t>(nullptr))))));
	EXPECT_THAT(
			parse(R"({"name1": "value1", " name2": 123,  "n ame3"  :null  , "": "i am nu\tll"})"),
			VariantWith<object>(Field(&object::members, UnorderedElementsAre(
					Pair("name1", VariantWith<std::string>("value1")),
					Pair(" name2", VariantWith<double>(DoubleEq(123))),
					Pair("n ame3", VariantWith<std::nullptr_t>(nullptr)),
					Pair("", VariantWith<std::string>("i am nu\tll"))))));
}

TEST(stringfy, boolean) {
	EXPECT_EQ(stringfy(true), "true");
	EXPECT_EQ(stringfy(false), "false");
}

TEST(stringfy, string) {
	EXPECT_EQ(stringfy("123"), R"("123")");
	EXPECT_EQ(stringfy(R"(123"123)"), R"("123\"123")");
	EXPECT_EQ(stringfy("\n\r\f\b\t"), R"("\n\r\f\b\t")");
	EXPECT_EQ(stringfy("\u1234\u5667\uaddd\uffff"), R"("\u1234\u5667\uaddd\uffff")");
}

TEST(stringfy, number) {
	EXPECT_EQ(stringfy(123.), "123");
	EXPECT_EQ(stringfy(123e2), "12300");
}

TEST(stringfy, null) {
	EXPECT_EQ(stringfy(nullptr), "null");
}

TEST(stringfy, object) {
	EXPECT_EQ(stringfy(object{{{"name1", "value1"}, {"name2", 123.}}}), R"({"name1": "value1", "name2": 123})");
	EXPECT_EQ(stringfy(object{{{"name3", nullptr}, {"name4", false}}}), R"({"name3": null, "name4": false})");
}

int main() {
	testing::InitGoogleTest();
	return RUN_ALL_TESTS();
}
