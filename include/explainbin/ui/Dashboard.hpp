#pragma once

#include "explainbin/core/Types.hpp"

#include <QWidget>

class QLabel;
class QListWidget;

namespace explainbin::ui {

class Card;
class SeverityChart;

class Dashboard : public QWidget {
    Q_OBJECT
public:
    explicit Dashboard(QWidget* parent = nullptr);

    void setResult(const AnalysisResult& result);
    void clear();

private:
    Card* m_fileCard = nullptr;
    Card* m_formatCard = nullptr;
    Card* m_sectionsCard = nullptr;
    Card* m_findingsCard = nullptr;
    Card* m_signatureCard = nullptr;
    SeverityChart* m_chart = nullptr;
    QListWidget* m_topFindings = nullptr;
    QLabel* m_sha256 = nullptr;
    QWidget* m_empty = nullptr;
    QWidget* m_content = nullptr;
};

} // namespace explainbin::ui
