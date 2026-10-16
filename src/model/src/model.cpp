#include "model.hpp"
#include "model_data.hpp"

#include <mln/sdk/functional.hpp>

#include <array>
#include <functional>

namespace LaTaupe {
    Model::Model() { name = "model"; }

    std::vector<Mln::Sdk::Tensor>
    Model::graph(std::span<const Mln::Sdk::Tensor> inputs) {
        using namespace Mln::Sdk;
        std::array<Tensor, 18> features;
        for (std::size_t index = 0; index < features.size(); ++index) {
            features[index] = operations.insert<Functional::Reshape>(
                operations.insert<Functional::Slice>(
                    inputs.front(), std::vector<int64_t>{static_cast<int64_t>(index)},
                    std::vector<int64_t>{static_cast<int64_t>(index + 1)},
                    std::vector<int64_t>{1}),
                std::vector<int64_t>{});
        }

        auto scalar = [this](float value) {
            return operations.insert<Functional::Const>(
                Weight{"", {}, static_cast<double>(value)}, false, Mln::DType::Float32);
        };
        std::function<Tensor(int)> tree = [&](int index) -> Tensor {
            const Data::TreeNode &node = Data::nodes[index];
            if (node.feature < 0)
                return scalar(node.leaf);
            Tensor condition = operations.insert<Functional::Less>(
                features[static_cast<std::size_t>(node.feature)], scalar(node.threshold));
            return operations.insert<Functional::Select>(
                std::move(condition), tree(node.yes), tree(node.no));
        };

        Tensor margin = scalar(Data::base_score);
        for (const int root : Data::roots)
            margin = operations.insert<Functional::Add>(std::move(margin), tree(root));
        return {operations.insert<Functional::Logistic>(std::move(margin))};
    }

    std::vector<std::vector<Mln::Sdk::Tensor>> Model::specializations() const {
        return {{Mln::Sdk::Tensor({18}, Mln::DType::Float32)}};
    }
} // namespace LaTaupe
