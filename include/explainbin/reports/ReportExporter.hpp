#pragma once

#include "explainbin/core/Types.hpp"

#include <string>

namespace explainbin {

class IReportExporter {
public:
    virtual ~IReportExporter() = default;
    [[nodiscard]] virtual std::string render(const AnalysisResult& result) const = 0;
};

class JSONExporter final : public IReportExporter {
public:
    [[nodiscard]] std::string render(const AnalysisResult& result) const override;
};

class HTMLExporter final : public IReportExporter {
public:
    [[nodiscard]] std::string render(const AnalysisResult& result) const override;
};

class TextExporter final : public IReportExporter {
public:
    [[nodiscard]] std::string render(const AnalysisResult& result) const override;
};

} // namespace explainbin
