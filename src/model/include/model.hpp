#pragma once

#include <mln/sdk/module.hpp>
#include <mln/sdk/tensor.hpp>

namespace LaTaupe {
    class Model final : public Mln::Sdk::Module {
        public:
            Model();
            std::vector<Mln::Sdk::Tensor>
            graph(std::span<const Mln::Sdk::Tensor> inputs) override;
            std::vector<std::vector<Mln::Sdk::Tensor>> specializations() const override;
    };
} // namespace LaTaupe
