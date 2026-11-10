#include "explainbin/ui/widgets/SeverityBadge.hpp"

#include "explainbin/ui/Theme.hpp"

namespace explainbin::ui {

SeverityBadge::SeverityBadge(QWidget* parent) : QLabel(parent) {
    setAlignment(Qt::AlignCenter);
    setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Fixed);
    setSeverity(Severity::Informational);
}

void SeverityBadge::setSeverity(Severity severity) {
    setText(severityLabel(severity).toUpper());
    setStyleSheet(severityBadgeStyle(severity));
}

} // namespace explainbin::ui
