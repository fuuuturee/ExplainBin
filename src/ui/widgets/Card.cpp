#include "explainbin/ui/widgets/Card.hpp"

#include <QColor>
#include <QLabel>
#include <QVBoxLayout>

namespace explainbin::ui {

Card::Card(const QString& title, QWidget* parent) : QFrame(parent) {
    setObjectName(QStringLiteral("card"));
    setFrameShape(QFrame::NoFrame);

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 14, 16, 14);
    layout->setSpacing(5);

    m_title = new QLabel(title.toUpper(), this);
    m_title->setObjectName(QStringLiteral("cardTitle"));
    m_value = new QLabel(QStringLiteral("-"), this);
    m_value->setObjectName(QStringLiteral("cardValue"));
    m_value->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_subtitle = new QLabel(this);
    m_subtitle->setObjectName(QStringLiteral("cardSubtitle"));
    m_subtitle->setWordWrap(true);

    layout->addWidget(m_title);
    layout->addWidget(m_value);
    layout->addWidget(m_subtitle);
}

void Card::setValue(const QString& value) {
    m_value->setText(value);
}

void Card::setSubtitle(const QString& subtitle) {
    m_subtitle->setText(subtitle);
}

void Card::setAccentColor(const QColor& color) {
    m_accent = color.name();
    updateAccent();
}

void Card::updateAccent() {
    if (m_accent.isEmpty()) {
        setStyleSheet(QString());
        return;
    }
    // Only the left border is overridden so the global theme keeps control of
    // the background, text and remaining border properties.
    setStyleSheet(QStringLiteral("QFrame#card { border-left: 3px solid %1; }").arg(m_accent));
}

} // namespace explainbin::ui
