#include "explainbin/ui/widgets/SeverityChart.hpp"

#include "explainbin/ui/Animations.hpp"
#include "explainbin/ui/Theme.hpp"

#include <QFontMetrics>
#include <QLinearGradient>
#include <QPainter>
#include <QPaintEvent>
#include <QPalette>
#include <QVariantAnimation>

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
    setMinimumHeight(172);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
}

void SeverityChart::setCounts(const SeverityCounts& counts) {
    m_counts = counts;
    m_hasData = true;
    startAnimation();
}

void SeverityChart::clear() {
    m_counts = {};
    m_hasData = false;
    m_progress = 0.0;
    if (m_animation) {
        m_animation->stop();
    }
    update();
}

void SeverityChart::startAnimation() {
    if (!anim::enabled()) {
        m_progress = 1.0;
        update();
        return;
    }
    if (m_animation) {
        m_animation->stop();
        m_animation->deleteLater();
    }
    m_progress = 0.0;
    auto* animation = new QVariantAnimation(this);
    animation->setDuration(620);
    animation->setStartValue(0.0);
    animation->setEndValue(1.0);
    animation->setEasingCurve(QEasingCurve::OutCubic);
    connect(animation, &QVariantAnimation::valueChanged, this, [this](const QVariant& value) {
        m_progress = value.toReal();
        update();
    });
    m_animation = animation;
    animation->start();
    update();
}

QSize SeverityChart::sizeHint() const {
    return {380, 190};
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

    const QPalette colors = palette();
    const QColor muted = colors.color(QPalette::PlaceholderText);
    const QColor text = colors.color(QPalette::Text);
    QColor track = colors.color(QPalette::Mid);
    track.setAlpha(80);

    const int labelWidth = 58;
    const int valueWidth = 30;
    const int rowHeight = 30;
    const int top = 4;
    const int barLeft = labelWidth;
    const int barWidth = std::max(20, width() - labelWidth - valueWidth - 10);

    int maximum = 1;
    for (const auto& row : rows) {
        maximum = std::max(maximum, row.count);
    }

    QFont labelFont = font();
    labelFont.setPointSizeF(8.5);
    painter.setFont(labelFont);

    for (std::size_t index = 0; index < rows.size(); ++index) {
        const auto& row = rows[index];
        const int y = top + static_cast<int>(index) * rowHeight;

        painter.setPen(muted);
        painter.drawText(QRect(0, y, labelWidth - 8, 22),
                         Qt::AlignVCenter | Qt::AlignLeft,
                         QString::fromLatin1(row.label));

        const QRectF trackRect(barLeft, y + 6, barWidth, 9);
        painter.setPen(Qt::NoPen);
        painter.setBrush(track);
        painter.drawRoundedRect(trackRect, 4.5, 4.5);

        if (m_hasData && row.count > 0 && m_progress > 0.0) {
            const double fraction = static_cast<double>(row.count) / static_cast<double>(maximum);
            const double animated = fraction * m_progress;
            QRectF fill = trackRect;
            fill.setWidth(std::max(9.0, trackRect.width() * animated));
            QColor color = severityColor(row.severity);
            QLinearGradient gradient(fill.topLeft(), fill.bottomLeft());
            gradient.setColorAt(0.0, color.lighter(115));
            gradient.setColorAt(1.0, color);
            painter.setBrush(gradient);
            painter.drawRoundedRect(fill, 4.5, 4.5);
        }

        QFont valueFont = labelFont;
        valueFont.setBold(true);
        painter.setFont(valueFont);
        painter.setPen(text);
        painter.drawText(QRect(width() - valueWidth, y, valueWidth, 22),
                         Qt::AlignVCenter | Qt::AlignRight,
                         QString::number(qRound(row.count * m_progress)));
        painter.setFont(labelFont);
    }
}

} // namespace explainbin::ui
