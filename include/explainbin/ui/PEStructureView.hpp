#pragma once

#include "explainbin/core/Types.hpp"

#include <QWidget>

class QPlainTextEdit;
class QTableWidget;

namespace explainbin::ui {

class PEStructureView : public QWidget {
    Q_OBJECT
public:
    explicit PEStructureView(QWidget* parent = nullptr);

    void setResult(const AnalysisResult& result);
    void clear();

private:
    void fillHeaders(const PeInfo& pe);
    void fillSections(const PeInfo& pe);
    void fillDirectories(const PeInfo& pe);
    void fillExtras(const AnalysisResult& result);

    QTableWidget* m_headers = nullptr;
    QTableWidget* m_sections = nullptr;
    QTableWidget* m_directories = nullptr;
    QPlainTextEdit* m_extras = nullptr;
};

} // namespace explainbin::ui
