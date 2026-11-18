#include "../client/include/client_secret_source_policy.h"

#include <cstdlib>
#include <iostream>

namespace {
    void Require(bool condition, const char* message) {
        if (!condition) {
            std::cerr << "FAILED: " << message << std::endl;
            std::abort();
        }
    }
}

int main() {
    using Oblivion::ClientSecretEnvironmentState;

    const auto populated = Oblivion::ClassifyClientSecretEnvironment(
        true, false, false);
    Require(populated == ClientSecretEnvironmentState::ValuePresent,
            "a non-empty environment value must take precedence");
    Require(!Oblivion::ShouldLoadClientSecretFile(populated),
            "a populated environment value must not load the file");

    const auto missing = Oblivion::ClassifyClientSecretEnvironment(
        false, true, false);
    Require(missing == ClientSecretEnvironmentState::NotSet,
            "an absent environment variable must be distinguished");
    Require(Oblivion::ShouldLoadClientSecretFile(missing),
            "the file is the fallback only when the variable is absent");

    const auto empty = Oblivion::ClassifyClientSecretEnvironment(
        false, false, true);
    Require(empty == ClientSecretEnvironmentState::ExplicitlyEmpty,
            "a present but empty environment variable must be distinguished");
    Require(!Oblivion::ShouldLoadClientSecretFile(empty),
            "an explicitly empty value must fail closed without file fallback");

    const auto failed = Oblivion::ClassifyClientSecretEnvironment(
        false, false, false);
    Require(failed == ClientSecretEnvironmentState::QueryFailed,
            "an environment query error must be distinguished");
    Require(!Oblivion::ShouldLoadClientSecretFile(failed),
            "an environment query error must fail closed without file fallback");

    std::cout << "Client secret source policy tests passed" << std::endl;
    return 0;
}
