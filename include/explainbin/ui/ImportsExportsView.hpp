#pragma once

#include "explainbin/core/Types.hpp"

#include <QWidget>

class QLabel;
class QLineEdit;
class QTableWidget;
class QTreeWidget;

namespace explainbin::ui {

class ImportsExportsView : public QWidget {
    Q_OBJECT
public:
    explicit ImportsExportsView(QWidget* parent = nullptr);

    void setResult(const AnalysisResult& result);
    void clear();

private:
    void populateImports(const PeInfo& pe);
    void populateExports(const PeInfo& pe);
    void applyFilter(const QString& text);

    QLabel* m_summary = nullptr;
    QLineEdit* m_filter = nullptr;
    QTreeWidget* m_imports = nullptr;
    QTableWidget* m_exports = nullptr;
};

} // namespace explainbin::ui
