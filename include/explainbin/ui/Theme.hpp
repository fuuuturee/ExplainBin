#pragma once

#include "explainbin/core/Types.hpp"

#include <QColor>
#include <QString>

class QApplication;

namespace explainbin::ui {

// Applies the shared Fusion-based palette and stylesheet.
void applyTheme(QApplication& application, bool dark);

QColor severityColor(Severity severity);
QString severityLabel(Severity severity);
QString severityBadgeStyle(Severity severity);

QString displayHex(std::uint64_t value);
QString displayBytes(std::uint64_t bytes);
QString fromUtf8(const std::string& value);

} // namespace explainbin::ui
