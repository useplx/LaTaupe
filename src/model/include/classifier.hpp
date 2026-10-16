#pragma once

#include <mln/sdk/orchestration.hpp>

#include "model.hpp"

namespace LaTaupe {
    class Classifier final : public Mln::Sdk::Orchestration {
        public:
            Classifier();
            Mln::Buffer forward(Mln::Runtime::Session &session, Mln::Buffer input) override;
    };
} // namespace LaTaupe
