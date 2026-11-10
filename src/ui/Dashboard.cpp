#include "explainbin/ui/Dashboard.hpp"

#include "explainbin/ui/Theme.hpp"
#include "explainbin/ui/widgets/Card.hpp"
#include "explainbin/ui/widgets/SeverityChart.hpp"

#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QVBoxLayout>

namespace explainbin::ui {
namespace {

QLabel* headingTitle(const QString& title, QWidget* parent) {
    return new QLabel(title, parent);
}

QWidget* heading(const QString& title, const QString& hint, QWidget* parent) {
    auto* container = new QWidget(parent);
    auto* layout = new QVBoxLayout(container);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(3);
    auto* titleLabel = headingTitle(title, container);
    titleLabel->setObjectName(QStringLiteral("sectionTitle"));
    auto* hintLabel = new QLabel(hint, container);
    hintLabel->setObjectName(QStringLiteral("pageHint"));
    hintLabel->setWordWrap(true);
    layout->addWidget(titleLabel);
    layout->addWidget(hintLabel);
    return container;
}

QFrame* panel(QWidget* parent) {
    auto* frame = new QFrame(parent);
    frame->setObjectName(QStringLiteral("panel"));
    return frame;
}

} // namespace

Dashboard::Dashboard(QWidget* parent) : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(26, 22, 26, 22);
    root->setSpacing(18);

    root->addWidget(heading(QStringLiteral("Overview"),
                            QStringLiteral("A local summary of the selected file. Findings are observations, "
                                           "not a malware verdict."),
                            this));

    m_empty = new QLabel(QStringLiteral(
                             "Open a Windows executable, DLL or driver to begin.\n\n"
                             "ExplainBin reads the file once, parses it with bounds checks and explains "
                             "what it observed. The file is never executed, loaded or uploaded."),
                         this);
    m_empty->setAlignment(Qt::AlignCenter);
    m_empty->setObjectName(QStringLiteral("muted"));
    m_empty->setWordWrap(true);
    m_empty->setMinimumHeight(320);
    root->addWidget(m_empty);

    m_content = new QWidget(this);
    auto* contentLayout = new QVBoxLayout(m_content);
    contentLayout->setContentsMargins(0, 0, 0, 0);
    contentLayout->setSpacing(16);

    auto* cards = new QWidget(m_content);
    auto* cardLayout = new QGridLayout(cards);
    cardLayout->setContentsMargins(0, 0, 0, 0);
    cardLayout->setHorizontalSpacing(12);
    cardLayout->setVerticalSpacing(12);

    m_fileCard = new Card(QStringLiteral("File"), cards);
    m_formatCard = new Card(QStringLiteral("Format"), cards);
    m_sectionsCard = new Card(QStringLiteral("Sections"), cards);
    m_findingsCard = new Card(QStringLiteral("Findings"), cards);
    m_signatureCard = new Card(QStringLiteral("Signature"), cards);

    cardLayout->addWidget(m_fileCard, 0, 0);
    cardLayout->addWidget(m_formatCard, 0, 1);
    cardLayout->addWidget(m_sectionsCard, 0, 2);
    cardLayout->addWidget(m_findingsCard, 0, 3);
    cardLayout->addWidget(m_signatureCard, 0, 4);
    for (int column = 0; column < 5; ++column) {
        cardLayout->setColumnStretch(column, 1);
    }
    contentLayout->addWidget(cards);

    auto* columns = new QWidget(m_content);
    auto* columnsLayout = new QHBoxLayout(columns);
    columnsLayout->setContentsMargins(0, 0, 0, 0);
    columnsLayout->setSpacing(12);

    auto* chartPanel = panel(columns);
    auto* chartLayout = new QVBoxLayout(chartPanel);
    chartLayout->setContentsMargins(18, 16, 18, 16);
    chartLayout->setSpacing(8);
    auto* chartTitle = new QLabel(QStringLiteral("Severity distribution"), chartPanel);
    chartTitle->setStyleSheet(QStringLiteral("font-weight: 650; font-size: 11pt;"));
    auto* chartHint = new QLabel(
        QStringLiteral("Counts describe observations. ExplainBin does not combine them into a score."),
        chartPanel);
    chartHint->setObjectName(QStringLiteral("muted"));
    chartHint->setWordWrap(true);
    m_chart = new SeverityChart(chartPanel);
    chartLayout->addWidget(chartTitle);
    chartLayout->addWidget(chartHint);
    chartLayout->addWidget(m_chart);
    chartLayout->addStretch(1);
    columnsLayout->addWidget(chartPanel, 3);

    auto* topPanel = panel(columns);
    auto* topLayout = new QVBoxLayout(topPanel);
    topLayout->setContentsMargins(18, 16, 18, 16);
    topLayout->setSpacing(8);
    auto* topTitle = new QLabel(QStringLiteral("Top observations"), topPanel);
    topTitle->setStyleSheet(QStringLiteral("font-weight: 650; font-size: 11pt;"));
    m_topFindings = new QListWidget(topPanel);
    m_topFindings->setObjectName(QStringLiteral("plainList"));
    m_topFindings->setAlternatingRowColors(true);
    m_topFindings->setSelectionMode(QAbstractItemView::NoSelection);
    m_topFindings->setFocusPolicy(Qt::NoFocus);
    m_topFindings->setWordWrap(true);
    m_sha256 = new QLabel(topPanel);
    m_sha256->setObjectName(QStringLiteral("muted"));
    m_sha256->setWordWrap(true);
    m_sha256->setTextInteractionFlags(Qt::TextSelectableByMouse);
    topLayout->addWidget(topTitle);
    topLayout->addWidget(m_topFindings, 1);
    topLayout->addWidget(m_sha256);
    columnsLayout->addWidget(topPanel, 4);

    contentLayout->addWidget(columns, 1);
    root->addWidget(m_content, 1);

    m_content->setVisible(false);
    m_empty->setVisible(true);
}

void Dashboard::setResult(const AnalysisResult& result) {
    m_empty->setVisible(false);
    m_content->setVisible(true);

    const auto& file = result.file;
    const auto& pe = result.pe;
    const auto counts = countSeverities(result.findings);

    m_fileCard->setValue(fromUtf8(file.fileName));
    m_fileCard->setSubtitle(displayBytes(file.size) + QStringLiteral(" \u00b7 ") +
                            fromUtf8(file.extension));
    m_fileCard->setAccentColor(QColor(0x4c, 0xc2, 0xff));

    if (pe.parsed) {
        m_formatCard->setValue(fromUtf8(pe.format));
        m_formatCard->setSubtitle(fromUtf8(pe.subsystemName) + QStringLiteral(" \u00b7 ") +
                                  (pe.isDll ? QStringLiteral("DLL") : QStringLiteral("Executable")));
    } else {
        m_formatCard->setValue(QStringLiteral("Unparsed"));
        m_formatCard->setSubtitle(QStringLiteral("Header chain invalid or unsupported"));
    }

    m_sectionsCard->setValue(QString::number(pe.sections.size()));
    m_sectionsCard->setSubtitle(QString::number(pe.numberOfSections) +
                                QStringLiteral(" declared \u00b7 ") +
                                QString::number(pe.imports.size()) +
                                QStringLiteral(" import libraries"));

    m_findingsCard->setValue(QString::number(counts.total()));
    m_findingsCard->setSubtitle(QStringLiteral("%1 high \u00b7 %2 critical")
                                    .arg(counts.high)
                                    .arg(counts.critical));
    if (counts.critical > 0) {
        m_findingsCard->setAccentColor(severityColor(Severity::Critical));
    } else if (counts.high > 0) {
        m_findingsCard->setAccentColor(severityColor(Severity::High));
    } else if (counts.medium > 0) {
        m_findingsCard->setAccentColor(severityColor(Severity::Medium));
    } else {
        m_findingsCard->setAccentColor(QColor(0x5f, 0xd1, 0x8b));
    }

    m_signatureCard->setValue(fromUtf8(std::string(toString(result.signature.status))));
    if (result.signature.status == SignatureStatus::Valid && result.signature.catalogSigned) {
        m_signatureCard->setSubtitle(QStringLiteral("Verified via Windows catalog"));
    } else {
        m_signatureCard->setSubtitle(
            result.signature.checked
                ? (result.signature.revocationChecked
                       ? QStringLiteral("Revocation checked")
                       : QStringLiteral("Revocation not checked online"))
                : QStringLiteral("Verification not performed"));
    }
    if (result.signature.status == SignatureStatus::Valid) {
        m_signatureCard->setAccentColor(QColor(0x5f, 0xd1, 0x8b));
    } else if (result.signature.status == SignatureStatus::Invalid) {
        m_signatureCard->setAccentColor(severityColor(Severity::Critical));
    }

    m_chart->setCounts(counts);

    m_topFindings->clear();
    int shown = 0;
    for (const auto& finding : result.findings) {
        if (shown++ >= 8) {
            break;
        }
        const auto severity = severityLabel(finding.severity).toUpper();
        m_topFindings->addItem(QStringLiteral("[%1]  %2  (%3)")
                                   .arg(severity, fromUtf8(finding.title),
                                        fromUtf8(finding.id)));
    }
    if (result.findings.empty()) {
        m_topFindings->addItem(QStringLiteral(
            "No findings matched the enabled rules. This does not prove the file is safe."));
    }

    m_sha256->setText(QStringLiteral("SHA-256  ") + fromUtf8(file.hashes.sha256) +
                      QStringLiteral("\nAnalyzed ") + fromUtf8(result.analyzedAtUtc) +
                      QStringLiteral(" \u00b7 ") + QString::number(result.durationMs) +
                      QStringLiteral(" ms"));
}

void Dashboard::clear() {
    m_content->setVisible(false);
    m_empty->setVisible(true);
    m_topFindings->clear();
    m_chart->clear();
    m_sha256->clear();
}

} // namespace explainbin::ui
