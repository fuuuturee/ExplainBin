#pragma once

#include "explainbin/core/Types.hpp"

#include <QWidget>

class QLabel;
class QListWidget;
class QTableWidget;

namespace explainbin::ui {

class SignatureView : public QWidget {
    Q_OBJECT
public:
    explicit SignatureView(QWidget* parent = nullptr);

    void setResult(const AnalysisResult& result);
    void clear();

private:
    QLabel* m_status = nullptr;
    QLabel* m_headline = nullptr;
    QLabel* m_note = nullptr;
    QTableWidget* m_details = nullptr;
    QListWidget* m_chain = nullptr;
};

} // namespace explainbin::ui
