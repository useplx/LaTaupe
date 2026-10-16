#include "classifier.hpp"

#include <cstddef>

namespace LaTaupe {
    namespace {
        constexpr std::size_t feature_count = 18;
    } // namespace

    Classifier::Classifier() {
        name = "lataupe";
        modules.insert<Model>("model");
    }

    Mln::Buffer Classifier::forward(Mln::Runtime::Session &session, Mln::Buffer input) {
        if (input.size() != feature_count * sizeof(float))
            return Mln::Buffer(sizeof(float));
        return session.invoke("model.forward", std::move(input));
    }
} // namespace LaTaupe
