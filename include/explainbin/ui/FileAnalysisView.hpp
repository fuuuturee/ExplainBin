#pragma once

#include "explainbin/core/Types.hpp"

#include <QWidget>

class QLabel;
class QListWidget;
class QTableWidget;

namespace explainbin::ui {

class FileAnalysisView : public QWidget {
    Q_OBJECT
public:
    explicit FileAnalysisView(QWidget* parent = nullptr);

    void setResult(const AnalysisResult& result);
    void clear();

private:
    QLabel* m_summary = nullptr;
    QLabel* m_empty = nullptr;
    QWidget* m_content = nullptr;
    QTableWidget* m_metadata = nullptr;
    QTableWidget* m_hashes = nullptr;
    QListWidget* m_diagnostics = nullptr;
};

} // namespace explainbin::ui
