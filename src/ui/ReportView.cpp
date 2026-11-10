#include "explainbin/ui/ReportView.hpp"

#include "explainbin/reports/ReportExporter.hpp"
#include "explainbin/reports/ReportUtil.hpp"
#include "explainbin/ui/Theme.hpp"

#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>

namespace explainbin::ui {
namespace {

QString suggestedPath(const AnalysisResult& result, const QString& suffix) {
    const QFileInfo info(fromUtf8(result.file.path));
    const QString base = info.completeBaseName().isEmpty()
                             ? QStringLiteral("explainbin-report")
                             : info.completeBaseName();
    return info.absolutePath() + QLatin1Char('/') + base + suffix;
}

} // namespace

ReportView::ReportView(QWidget* parent) : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(26, 22, 26, 22);
    root->setSpacing(12);

    auto* title = new QLabel(QStringLiteral("Reports"), this);
    title->setObjectName(QStringLiteral("sectionTitle"));
    auto* hint = new QLabel(
        QStringLiteral("Self-contained report files are written locally. Reports include the "
                       "file hashes, structural facts, signature state and every finding with "
                       "its evidence and plain-language explanation."),
        this);
    hint->setObjectName(QStringLiteral("pageHint"));
    hint->setWordWrap(true);
    root->addWidget(title);
    root->addWidget(hint);

    auto* buttonRow = new QWidget(this);
    auto* buttonLayout = new QHBoxLayout(buttonRow);
    buttonLayout->setContentsMargins(0, 0, 0, 0);
    buttonLayout->setSpacing(10);

    m_jsonButton = new QPushButton(QStringLiteral("Export JSON\u2026"), buttonRow);
    m_htmlButton = new QPushButton(QStringLiteral("Export HTML\u2026"), buttonRow);
    m_textButton = new QPushButton(QStringLiteral("Export text\u2026"), buttonRow);
    m_jsonButton->setObjectName(QStringLiteral("primary"));

    m_status = new QLabel(buttonRow);
    m_status->setObjectName(QStringLiteral("muted"));

    buttonLayout->addWidget(m_jsonButton);
    buttonLayout->addWidget(m_htmlButton);
    buttonLayout->addWidget(m_textButton);
    buttonLayout->addWidget(m_status, 1);
    root->addWidget(buttonRow);

    auto* previewLabel = new QLabel(QStringLiteral("Text report preview"), this);
    previewLabel->setStyleSheet(QStringLiteral("font-weight: 650; font-size: 11pt;"));
    root->addWidget(previewLabel);

    m_preview = new QPlainTextEdit(this);
    m_preview->setReadOnly(true);
    m_preview->setLineWrapMode(QPlainTextEdit::NoWrap);
    m_preview->setPlaceholderText(QStringLiteral("Analyze a file to preview its text report."));
    root->addWidget(m_preview, 1);

    connect(m_jsonButton, &QPushButton::clicked, this, &ReportView::exportJson);
    connect(m_htmlButton, &QPushButton::clicked, this, &ReportView::exportHtml);
    connect(m_textButton, &QPushButton::clicked, this, &ReportView::exportText);

    clear();
}

void ReportView::setResult(const AnalysisResult& result) {
    m_result = &result;
    const bool ready = result.success || !result.file.fileName.empty();
    m_jsonButton->setEnabled(ready);
    m_htmlButton->setEnabled(ready);
    m_textButton->setEnabled(ready);
    m_status->setText(ready ? QString() : QStringLiteral("No analyzable file."));
    updatePreview();
}

void ReportView::clear() {
    m_result = nullptr;
    m_jsonButton->setEnabled(false);
    m_htmlButton->setEnabled(false);
    m_textButton->setEnabled(false);
    m_status->clear();
    m_preview->clear();
}

void ReportView::updatePreview() {
    if (m_result == nullptr) {
        m_preview->clear();
        return;
    }
    TextExporter exporter;
    m_preview->setPlainText(fromUtf8(exporter.render(*m_result)));
}

void ReportView::exportJson() {
    if (m_result == nullptr) {
        return;
    }
    JSONExporter exporter;
    exportReport(QStringLiteral("Export JSON report"),
                 QStringLiteral("JSON report (*.json);;All files (*)"),
                 QStringLiteral(".json"), fromUtf8(exporter.render(*m_result)));
}

void ReportView::exportHtml() {
    if (m_result == nullptr) {
        return;
    }
    HTMLExporter exporter;
    exportReport(QStringLiteral("Export HTML report"),
                 QStringLiteral("HTML report (*.html *.htm);;All files (*)"),
                 QStringLiteral(".html"), fromUtf8(exporter.render(*m_result)));
}

void ReportView::exportText() {
    if (m_result == nullptr) {
        return;
    }
    TextExporter exporter;
    exportReport(QStringLiteral("Export text report"),
                 QStringLiteral("Text report (*.txt);;All files (*)"),
                 QStringLiteral(".txt"), fromUtf8(exporter.render(*m_result)));
}

void ReportView::exportReport(const QString& title, const QString& filter,
                              const QString& suffix, const QString& content) {
    if (m_result == nullptr) {
        return;
    }

    const QString target = QFileDialog::getSaveFileName(
        this, title, suggestedPath(*m_result, suffix), filter);
    if (target.isEmpty()) {
        return;
    }

    const QByteArray utf8 = content.toUtf8();
    std::string error;
    if (!writeReportFile(std::filesystem::path(target.toStdWString()),
                         std::string_view(utf8.constData(),
                                          static_cast<std::size_t>(utf8.size())),
                         error)) {
        QMessageBox::critical(this, QStringLiteral("Report export failed"),
                              fromUtf8(error));
        return;
    }

    m_status->setText(QStringLiteral("Report written to ") + target);
}

} // namespace explainbin::ui
