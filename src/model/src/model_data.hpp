#pragma once

namespace LaTaupe::Data {
    struct TreeNode {
            int feature;
            float threshold;
            int yes;
            int no;
            float leaf;
    };

#include "model.inc"
} // namespace LaTaupe::Data
