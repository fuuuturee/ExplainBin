#include "explainbin/ui/FindingsView.hpp"

#include "explainbin/ui/Theme.hpp"
#include "explainbin/ui/widgets/SeverityBadge.hpp"

#include <QComboBox>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QScrollArea>
#include <QVBoxLayout>

namespace explainbin::ui {
namespace {

QString bullets(const std::vector<std::string>& items) {
    QStringList lines;
    for (const auto& item : items) {
        lines << QStringLiteral("\u2022 ") + fromUtf8(item);
    }
    return lines.join(QStringLiteral("\n"));
}

QLabel* bodyLabel(const QString& text, QWidget* parent, bool muted = false) {
    auto* label = new QLabel(text, parent);
    label->setWordWrap(true);
    label->setTextFormat(Qt::PlainText);
    label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    if (muted) {
        label->setObjectName(QStringLiteral("muted"));
    }
    return label;
}

void addSection(QVBoxLayout* layout, const QString& title,
                const std::vector<std::string>& items, QWidget* parent) {
    if (items.empty()) {
        return;
    }
    auto* heading = new QLabel(title, parent);
    heading->setStyleSheet(QStringLiteral("font-weight: 650; color: #8fb3cc;"));
    layout->addWidget(heading);
    layout->addWidget(bodyLabel(bullets(items), parent));
}

} // namespace

FindingsView::FindingsView(QWidget* parent) : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(26, 22, 26, 22);
    root->setSpacing(12);

    auto* title = new QLabel(QStringLiteral("Security Findings"), this);
    title->setObjectName(QStringLiteral("sectionTitle"));
    auto* hint = new QLabel(
        QStringLiteral("Every finding explains what was observed, why it may matter, what else "
                       "could explain it and what to check next. Severities are hints for "
                       "triage, not a malware score."),
        this);
    hint->setObjectName(QStringLiteral("pageHint"));
    hint->setWordWrap(true);
    root->addWidget(title);
    root->addWidget(hint);

    auto* filterRow = new QWidget(this);
    auto* filterLayout = new QHBoxLayout(filterRow);
    filterLayout->setContentsMargins(0, 0, 0, 0);
    filterLayout->setSpacing(10);

    m_severityFilter = new QComboBox(filterRow);
    m_severityFilter->addItem(QStringLiteral("All severities"), -1);
    m_severityFilter->addItem(QStringLiteral("Critical"),
                              static_cast<int>(Severity::Critical));
    m_severityFilter->addItem(QStringLiteral("High"), static_cast<int>(Severity::High));
    m_severityFilter->addItem(QStringLiteral("Medium"), static_cast<int>(Severity::Medium));
    m_severityFilter->addItem(QStringLiteral("Low"), static_cast<int>(Severity::Low));
    m_severityFilter->addItem(QStringLiteral("Informational"),
                              static_cast<int>(Severity::Informational));
    m_severityFilter->setMinimumWidth(160);

    m_search = new QLineEdit(filterRow);
    m_search->setPlaceholderText(QStringLiteral("Search findings, evidence or explanations\u2026"));
    m_search->setClearButtonEnabled(true);

    m_summary = new QLabel(filterRow);
    m_summary->setObjectName(QStringLiteral("muted"));

    filterLayout->addWidget(m_severityFilter);
    filterLayout->addWidget(m_search, 1);
    filterLayout->addWidget(m_summary);
    root->addWidget(filterRow);

    m_empty = new QLabel(QStringLiteral("No analysis result yet."), this);
    m_empty->setObjectName(QStringLiteral("muted"));
    m_empty->setAlignment(Qt::AlignCenter);
    m_empty->setWordWrap(true);
    m_empty->setMinimumHeight(220);
    root->addWidget(m_empty);

    m_scroll = new QScrollArea(this);
    m_scroll->setWidgetResizable(true);
    m_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_container = new QWidget(m_scroll);
    m_cardsLayout = new QVBoxLayout(m_container);
    m_cardsLayout->setContentsMargins(0, 0, 6, 0);
    m_cardsLayout->setSpacing(12);
    m_cardsLayout->setAlignment(Qt::AlignTop);
    m_scroll->setWidget(m_container);
    root->addWidget(m_scroll, 1);

    m_scroll->setVisible(false);

    connect(m_severityFilter, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
            &FindingsView::rebuild);
    connect(m_search, &QLineEdit::textChanged, this, &FindingsView::rebuild);
}

void FindingsView::setResult(const AnalysisResult& result) {
    clearCards();
    for (const auto& finding : result.findings) {
        auto* card = createFindingCard(finding);
        m_cardsLayout->addWidget(card);
        CardEntry entry;
        entry.widget = card;
        entry.severityRank = static_cast<int>(finding.severity);
        QString searchText = fromUtf8(finding.id) + QLatin1Char(' ') +
                             fromUtf8(finding.title) + QLatin1Char(' ') +
                             fromUtf8(finding.category) + QLatin1Char(' ') +
                             fromUtf8(finding.description) + QLatin1Char(' ') +
                             fromUtf8(finding.whyItMatters);
        for (const auto& evidence : finding.evidence) {
            searchText += QLatin1Char(' ') + fromUtf8(evidence);
        }
        for (const auto& explanation : finding.legitimateExplanations) {
            searchText += QLatin1Char(' ') + fromUtf8(explanation);
        }
        for (const auto& next : finding.nextSteps) {
            searchText += QLatin1Char(' ') + fromUtf8(next);
        }
        entry.searchText = searchText.toLower();
        m_cards.push_back(entry);
    }
    rebuild();
}

QWidget* FindingsView::createFindingCard(const Finding& finding) {
    auto* card = new QFrame(this);
    card->setObjectName(QStringLiteral("findingCard"));

    auto* layout = new QVBoxLayout(card);
    layout->setContentsMargins(16, 14, 16, 14);
    layout->setSpacing(9);

    auto* header = new QWidget(card);
    auto* headerLayout = new QHBoxLayout(header);
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(10);

    auto* badge = new SeverityBadge(header);
    badge->setSeverity(finding.severity);

    auto* title = new QLabel(fromUtf8(finding.title), header);
    title->setWordWrap(true);
    title->setStyleSheet(QStringLiteral("font-size: 11.5pt; font-weight: 650;"));
    title->setTextInteractionFlags(Qt::TextSelectableByMouse);

    auto* id = new QLabel(fromUtf8(finding.id), header);
    id->setObjectName(QStringLiteral("muted"));

    headerLayout->addWidget(badge, 0, Qt::AlignTop);
    headerLayout->addWidget(title, 1);
    headerLayout->addWidget(id, 0, Qt::AlignTop);
    layout->addWidget(header);

    auto* meta = new QLabel(
        QStringLiteral("%1  \u00b7  confidence: %2")
            .arg(fromUtf8(finding.category),
                 fromUtf8(std::string(toString(finding.confidence)))),
        card);
    meta->setObjectName(QStringLiteral("muted"));
    meta->setWordWrap(true);
    layout->addWidget(meta);

    if (!finding.description.empty()) {
        layout->addWidget(bodyLabel(fromUtf8(finding.description), card));
    }

    if (!finding.whyItMatters.empty()) {
        auto* heading = new QLabel(QStringLiteral("Why it matters"), card);
        heading->setStyleSheet(QStringLiteral("font-weight: 650; color: #8fb3cc;"));
        layout->addWidget(heading);
        layout->addWidget(bodyLabel(fromUtf8(finding.whyItMatters), card));
    }

    addSection(layout, QStringLiteral("Technical evidence"), finding.evidence, card);
    addSection(layout, QStringLiteral("Could be legitimate because"), finding.legitimateExplanations,
               card);
    addSection(layout, QStringLiteral("Suggested next steps"), finding.nextSteps, card);

    return card;
}

void FindingsView::rebuild() {
    const int filterRank = m_severityFilter->currentData().toInt();
    const QString needle = m_search->text().trimmed().toLower();

    int visible = 0;
    for (const auto& entry : m_cards) {
        const bool severityMatch = filterRank < 0 || entry.severityRank == filterRank;
        const bool textMatch = needle.isEmpty() || entry.searchText.contains(needle);
        const bool show = severityMatch && textMatch;
        entry.widget->setVisible(show);
        if (show) {
            ++visible;
        }
    }

    m_summary->setText(QStringLiteral("Showing %1 of %2").arg(visible).arg(m_cards.size()));

    if (m_cards.empty()) {
        m_empty->setText(
            QStringLiteral("No findings were produced. This does not prove that the file is "
                           "safe \u2014 it only means the enabled rules observed nothing notable."));
        m_empty->setVisible(true);
        m_scroll->setVisible(false);
    } else if (visible == 0) {
        m_empty->setText(QStringLiteral("No findings match the current filter."));
        m_empty->setVisible(true);
        m_scroll->setVisible(false);
    } else {
        m_empty->setVisible(false);
        m_scroll->setVisible(true);
    }
}

void FindingsView::clearCards() {
    m_cards.clear();
    while (auto* item = m_cardsLayout->takeAt(0)) {
        if (auto* widget = item->widget()) {
            delete widget;
        }
        delete item;
    }
}

void FindingsView::clear() {
    clearCards();
    m_summary->clear();
    m_empty->setText(QStringLiteral("No analysis result yet."));
    m_empty->setVisible(true);
    m_scroll->setVisible(false);
}

} // namespace explainbin::ui
