#pragma once

#include "explainbin/core/Types.hpp"

#include <QWidget>

class QVariantAnimation;

namespace explainbin::ui {

// Draws a compact horizontal bar chart of finding severities. It deliberately
// shows counts only: no score, percentage or verdict.
class SeverityChart : public QWidget {
    Q_OBJECT
public:
    explicit SeverityChart(QWidget* parent = nullptr);

    void setCounts(const SeverityCounts& counts);
    void clear();

    [[nodiscard]] QSize sizeHint() const override;

protected:
    void paintEvent(QPaintEvent* event) override;

private:
    void startAnimation();

    SeverityCounts m_counts;
    bool m_hasData = false;
    qreal m_progress = 0.0;
    QVariantAnimation* m_animation = nullptr;
};

} // namespace explainbin::ui
