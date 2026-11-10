#pragma once

#include "explainbin/core/Types.hpp"

#include <QLabel>

namespace explainbin::ui {

class SeverityBadge : public QLabel {
    Q_OBJECT
public:
    explicit SeverityBadge(QWidget* parent = nullptr);
    void setSeverity(Severity severity);
};

} // namespace explainbin::ui
