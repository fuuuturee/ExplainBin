#pragma once

#include "explainbin/core/Types.hpp"

#include <QWidget>

class QLabel;
class QPlainTextEdit;
class QPushButton;

namespace explainbin::ui {

class ReportView : public QWidget {
    Q_OBJECT
public:
    explicit ReportView(QWidget* parent = nullptr);

    void setResult(const AnalysisResult& result);
    void clear();

private:
    void exportJson();
    void exportHtml();
    void exportText();
    void exportReport(const QString& title, const QString& filter,
                      const QString& suffix, const QString& content);
    void updatePreview();

    const AnalysisResult* m_result = nullptr;
    QLabel* m_status = nullptr;
    QPlainTextEdit* m_preview = nullptr;
    QPushButton* m_jsonButton = nullptr;
    QPushButton* m_htmlButton = nullptr;
    QPushButton* m_textButton = nullptr;
};

} // namespace explainbin::ui
