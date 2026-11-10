#pragma once

#include <QColor>
#include <QFrame>
#include <QString>

class QLabel;
class QVariantAnimation;

namespace explainbin::ui {

class Card : public QFrame {
    Q_OBJECT
public:
    explicit Card(const QString& title, QWidget* parent = nullptr);

    void setValue(const QString& value);
    void setSubtitle(const QString& subtitle);
    void setAccentColor(const QColor& color);

private:
    void updateAccent();
    void animateValue(int target);

    QLabel* m_title = nullptr;
    QLabel* m_value = nullptr;
    QLabel* m_subtitle = nullptr;
    QColor m_accent;
    QVariantAnimation* m_valueAnimation = nullptr;
    QVariantAnimation* m_accentAnimation = nullptr;
};

} // namespace explainbin::ui
