#pragma once

#include "explainbin/core/Types.hpp"

#include <QString>
#include <QWidget>

#include <vector>

class QComboBox;
class QLabel;
class QLineEdit;
class QScrollArea;
class QVBoxLayout;

namespace explainbin::ui {

class FindingsView : public QWidget {
    Q_OBJECT
public:
    explicit FindingsView(QWidget* parent = nullptr);

    void setResult(const AnalysisResult& result);
    void clear();

private:
    struct CardEntry {
        QWidget* widget = nullptr;
        QString searchText;
        int severityRank = 0;
    };

    QWidget* createFindingCard(const Finding& finding);
    void rebuild();
    void clearCards();

    QComboBox* m_severityFilter = nullptr;
    QLineEdit* m_search = nullptr;
    QLabel* m_summary = nullptr;
    QScrollArea* m_scroll = nullptr;
    QWidget* m_container = nullptr;
    QVBoxLayout* m_cardsLayout = nullptr;
    QLabel* m_empty = nullptr;
    std::vector<CardEntry> m_cards;
    bool m_animateNext = false;
};

} // namespace explainbin::ui
