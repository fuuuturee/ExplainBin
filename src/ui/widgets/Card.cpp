#include "explainbin/ui/widgets/Card.hpp"

#include "explainbin/ui/Animations.hpp"

#include <QLabel>
#include <QVBoxLayout>
#include <QVariantAnimation>

#include <algorithm>

namespace explainbin::ui {
namespace {

bool parseCount(const QString& text, int* value) {
    bool ok = false;
    const int parsed = text.toInt(&ok);
    if (!ok || text.isEmpty() || text != QString::number(parsed)) {
        return false;
    }
    *value = parsed;
    return true;
}

} // namespace

Card::Card(const QString& title, QWidget* parent) : QFrame(parent) {
    setObjectName(QStringLiteral("card"));
    setFrameShape(QFrame::NoFrame);
    setMinimumHeight(98);

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(17, 15, 17, 15);
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
    int target = 0;
    if (!parseCount(value, &target)) {
        if (m_valueAnimation) {
            m_valueAnimation->stop();
        }
        m_value->setText(value);
        return;
    }

    int current = 0;
    if (!anim::enabled() || !parseCount(m_value->text(), &current)) {
        current = 0;
    }
    if (current == target) {
        m_value->setText(value);
        return;
    }
    animateValue(target);
}

void Card::animateValue(int target) {
    if (m_valueAnimation) {
        m_valueAnimation->stop();
        m_valueAnimation->deleteLater();
    }

    int origin = 0;
    parseCount(m_value->text(), &origin);

    auto* animation = new QVariantAnimation(this);
    animation->setDuration(520);
    animation->setStartValue(origin);
    animation->setEndValue(target);
    animation->setEasingCurve(QEasingCurve::OutCubic);
    connect(animation, &QVariantAnimation::valueChanged, this, [this](const QVariant& value) {
        m_value->setText(QString::number(value.toInt()));
    });
    connect(animation, &QVariantAnimation::finished, this, [this, target] {
        m_value->setText(QString::number(target));
    });
    m_valueAnimation = animation;
    animation->start();
}

void Card::setSubtitle(const QString& subtitle) {
    m_subtitle->setText(subtitle);
}

void Card::setAccentColor(const QColor& color) {
    if (m_accent == color) {
        return;
    }
    if (!anim::enabled() || !m_accent.isValid()) {
        m_accent = color;
        updateAccent();
        return;
    }
    if (m_accentAnimation) {
        m_accentAnimation->stop();
        m_accentAnimation->deleteLater();
    }
    auto* animation = new QVariantAnimation(this);
    animation->setDuration(320);
    animation->setStartValue(m_accent);
    animation->setEndValue(color);
    animation->setEasingCurve(QEasingCurve::OutCubic);
    connect(animation, &QVariantAnimation::valueChanged, this, [this](const QVariant& value) {
        m_accent = value.value<QColor>();
        updateAccent();
    });
    m_accentAnimation = animation;
    animation->start();
}

void Card::updateAccent() {
    if (!m_accent.isValid()) {
        setStyleSheet(QString());
        return;
    }
    // Only the left border is overridden so the global theme keeps control of
    // the background, text and remaining border properties.
    setStyleSheet(QStringLiteral("QFrame#card { border-left: 3px solid %1; }").arg(m_accent.name()));
}

} // namespace explainbin::ui
