#pragma once

#include <inttypes.h>
#include <tinyxml2.h>

#include <optional>
#include <vector>

struct Rule {
    Rule(const tinyxml2::XMLElement& element);

    enum class Type {
        BLOCK,
        ALLOW,
    };

    enum class Protocol {
        TCP,
        UDP,
    };

    enum class Action {
        DONT_KNOW,
        ALLOW,
        BLOCK,
    };

    Action operator()(const void* package) const;

   private:
    Action get_action() const {
        return type_ == Type::ALLOW ? Action::ALLOW : Action::BLOCK;
    }

    Type type_ = Type::ALLOW;
    std::optional<Protocol> protocol_{};
    std::optional<uint16_t> src_port_{};
    std::optional<uint16_t> dst_port_{};
    std::optional<uint32_t> src_ip_{};
    std::optional<uint32_t> dst_ip_{};
};

struct Ruleset {
    Ruleset() = default;

    static Ruleset import(const char* file_name);

    bool allows(const void* package) const;

   private:
    std::vector<Rule> rules_{};

    bool default_response_ = true;
};
