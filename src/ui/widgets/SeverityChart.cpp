#include "explainbin/ui/widgets/SeverityChart.hpp"

#include "explainbin/ui/Theme.hpp"

#include <QFontMetrics>
#include <QPainter>
#include <QPaintEvent>

#include <algorithm>
#include <array>

namespace explainbin::ui {
namespace {

struct Row {
    const char* label;
    int count;
    Severity severity;
};

} // namespace

SeverityChart::SeverityChart(QWidget* parent) : QWidget(parent) {
    setMinimumHeight(168);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
}

void SeverityChart::setCounts(const SeverityCounts& counts) {
    m_counts = counts;
    m_hasData = true;
    update();
}

void SeverityChart::clear() {
    m_counts = {};
    m_hasData = false;
    update();
}

QSize SeverityChart::sizeHint() const {
    return {360, 178};
}

void SeverityChart::paintEvent(QPaintEvent* event) {
    Q_UNUSED(event);
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);

    const std::array<Row, 5> rows{{
        {QT_TRANSLATE_NOOP("SeverityChart", "Critical"), m_counts.critical, Severity::Critical},
        {QT_TRANSLATE_NOOP("SeverityChart", "High"), m_counts.high, Severity::High},
        {QT_TRANSLATE_NOOP("SeverityChart", "Medium"), m_counts.medium, Severity::Medium},
        {QT_TRANSLATE_NOOP("SeverityChart", "Low"), m_counts.low, Severity::Low},
        {QT_TRANSLATE_NOOP("SeverityChart", "Info"), m_counts.informational, Severity::Informational},
    }};

    const int labelWidth = 58;
    const int valueWidth = 28;
    const int rowHeight = 29;
    const int top = 6;
    const int barLeft = labelWidth;
    const int barWidth = std::max(20, width() - labelWidth - valueWidth - 8);

    int maximum = 1;
    for (const auto& row : rows) {
        maximum = std::max(maximum, row.count);
    }

    QFont labelFont = font();
    labelFont.setPointSizeF(8.5);
    painter.setFont(labelFont);
    const QFontMetrics metrics(labelFont);

    for (std::size_t index = 0; index < rows.size(); ++index) {
        const auto& row = rows[index];
        const int y = top + static_cast<int>(index) * rowHeight;

        painter.setPen(QColor(0x84, 0x96, 0xa9));
        painter.drawText(QRect(0, y, labelWidth - 8, 20),
                         Qt::AlignVCenter | Qt::AlignLeft,
                         QString::fromLatin1(row.label));

        const QRectF track(barLeft, y + 5, barWidth, 10);
        painter.setPen(Qt::NoPen);
        painter.setBrush(QColor(0x0a, 0x10, 0x17));
        painter.drawRoundedRect(track, 5, 5);

        if (m_hasData && row.count > 0) {
            const double fraction = static_cast<double>(row.count) / static_cast<double>(maximum);
            QRectF fill = track;
            fill.setWidth(std::max(6.0, track.width() * fraction));
            QColor color = severityColor(row.severity);
            painter.setBrush(color);
            painter.drawRoundedRect(fill, 5, 5);
        }

        painter.setPen(QColor(0xdc, 0xe6, 0xf2));
        painter.drawText(QRect(width() - valueWidth, y, valueWidth, 20),
                         Qt::AlignVCenter | Qt::AlignRight,
                         QString::number(row.count));
        (void)metrics;
    }
}

} // namespace explainbin::ui
