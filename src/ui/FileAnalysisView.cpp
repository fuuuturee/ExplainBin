#include "explainbin/ui/FileAnalysisView.hpp"

#include "explainbin/ui/Theme.hpp"

#include <QHeaderView>
#include <QLabel>
#include <QListWidget>
#include <QTableWidget>
#include <QVBoxLayout>

namespace explainbin::ui {
namespace {

QTableWidget* createKeyValueTable(QWidget* parent) {
    auto* table = new QTableWidget(0, 2, parent);
    table->setHorizontalHeaderLabels({QStringLiteral("Field"), QStringLiteral("Value")});
    table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    table->verticalHeader()->setVisible(false);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setAlternatingRowColors(true);
    table->setShowGrid(false);
    return table;
}

void addRow(QTableWidget* table, const QString& key, const QString& value) {
    const int row = table->rowCount();
    table->insertRow(row);
    table->setItem(row, 0, new QTableWidgetItem(key));
    auto* item = new QTableWidgetItem(value);
    table->setItem(row, 1, item);
}

} // namespace

FileAnalysisView::FileAnalysisView(QWidget* parent) : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(26, 22, 26, 22);
    root->setSpacing(14);

    auto* title = new QLabel(QStringLiteral("File Analysis"), this);
    title->setObjectName(QStringLiteral("sectionTitle"));
    auto* hint = new QLabel(
        QStringLiteral("End-to-end result of the local pipeline: read, hash, parse, verify and explain."),
        this);
    hint->setObjectName(QStringLiteral("pageHint"));
    hint->setWordWrap(true);
    root->addWidget(title);
    root->addWidget(hint);

    m_summary = new QLabel(this);
    m_summary->setObjectName(QStringLiteral("muted"));
    m_summary->setWordWrap(true);
    m_summary->setTextInteractionFlags(Qt::TextSelectableByMouse);
    root->addWidget(m_summary);

    m_empty = new QLabel(QStringLiteral("No analysis result yet."), this);
    m_empty->setObjectName(QStringLiteral("muted"));
    m_empty->setAlignment(Qt::AlignCenter);
    m_empty->setMinimumHeight(260);
    root->addWidget(m_empty);

    m_content = new QWidget(this);
    auto* contentLayout = new QVBoxLayout(m_content);
    contentLayout->setContentsMargins(0, 0, 0, 0);
    contentLayout->setSpacing(12);

    auto* metadataLabel = new QLabel(QStringLiteral("Metadata"), m_content);
    metadataLabel->setStyleSheet(QStringLiteral("font-weight: 650; font-size: 11pt;"));
    m_metadata = createKeyValueTable(m_content);
    m_metadata->setMinimumHeight(260);
    contentLayout->addWidget(metadataLabel);
    contentLayout->addWidget(m_metadata, 1);

    auto* hashesLabel = new QLabel(QStringLiteral("Hashes (computed locally with Windows CNG)"),
                                   m_content);
    hashesLabel->setStyleSheet(QStringLiteral("font-weight: 650; font-size: 11pt;"));
    m_hashes = createKeyValueTable(m_content);
    m_hashes->setMaximumHeight(150);
    contentLayout->addWidget(hashesLabel);
    contentLayout->addWidget(m_hashes);

    auto* diagnosticsLabel = new QLabel(QStringLiteral("Parser diagnostics"), m_content);
    diagnosticsLabel->setStyleSheet(QStringLiteral("font-weight: 650; font-size: 11pt;"));
    m_diagnostics = new QListWidget(m_content);
    m_diagnostics->setObjectName(QStringLiteral("plainList"));
    m_diagnostics->setAlternatingRowColors(true);
    m_diagnostics->setWordWrap(true);
    m_diagnostics->setMaximumHeight(160);
    contentLayout->addWidget(diagnosticsLabel);
    contentLayout->addWidget(m_diagnostics);

    root->addWidget(m_content, 1);

    m_content->setVisible(false);
    m_summary->setVisible(false);
}

void FileAnalysisView::setResult(const AnalysisResult& result) {
    m_empty->setVisible(false);
    m_content->setVisible(true);
    m_summary->setVisible(true);

    const auto counts = countSeverities(result.findings);
    if (!result.success) {
        m_summary->setText(QStringLiteral("Analysis failed: ") + fromUtf8(result.errorMessage));
    } else {
        m_summary->setText(
            QStringLiteral("%1 \u00b7 %2 findings (%3 critical, %4 high, %5 medium, %6 low, "
                           "%7 informational) \u00b7 signature %8")
                .arg(result.parseSuccess ? QStringLiteral("PE parsed successfully")
                                         : QStringLiteral("PE parsing failed"),
                     QString::number(counts.total()))
                .arg(counts.critical)
                .arg(counts.high)
                .arg(counts.medium)
                .arg(counts.low)
                .arg(counts.informational)
                .arg(fromUtf8(std::string(toString(result.signature.status)))));
    }

    m_metadata->setRowCount(0);
    const auto& file = result.file;
    const auto& pe = result.pe;

    addRow(m_metadata, QStringLiteral("File name"), fromUtf8(file.fileName));
    addRow(m_metadata, QStringLiteral("Path"), fromUtf8(file.path));
    addRow(m_metadata, QStringLiteral("Size"),
           QStringLiteral("%1 (%2 bytes)").arg(displayBytes(file.size)).arg(file.size));
    addRow(m_metadata, QStringLiteral("Last write (UTC)"), fromUtf8(file.lastWriteTimeUtc));
    addRow(m_metadata, QStringLiteral("Created (UTC)"), fromUtf8(file.creationTimeUtc));
    addRow(m_metadata, QStringLiteral("Analyzed at (UTC)"), fromUtf8(result.analyzedAtUtc));
    addRow(m_metadata, QStringLiteral("Duration"),
           QStringLiteral("%1 ms").arg(result.durationMs));
    addRow(m_metadata, QStringLiteral("Analysis result"),
           result.success ? QStringLiteral("completed") : QStringLiteral("failed"));
    addRow(m_metadata, QStringLiteral("PE parsed"),
           result.parseSuccess ? QStringLiteral("yes") : QStringLiteral("no"));
    addRow(m_metadata, QStringLiteral("Partial parse"),
           pe.partial ? QStringLiteral("yes, some structures were skipped") : QStringLiteral("no"));

    if (pe.parsed) {
        addRow(m_metadata, QStringLiteral("Format"), fromUtf8(pe.format));
        addRow(m_metadata, QStringLiteral("Subsystem"), fromUtf8(pe.subsystemName));
        addRow(m_metadata, QStringLiteral("Linker version"), fromUtf8(pe.linkerVersion));
        addRow(m_metadata, QStringLiteral("Compile time (UTC)"),
               pe.timestampUtc.empty() ? QStringLiteral("(zero or unavailable)")
                                       : fromUtf8(pe.timestampUtc));
        addRow(m_metadata, QStringLiteral("Entry point"),
               displayHex(pe.entryPointRva));
        addRow(m_metadata, QStringLiteral("Image base"),
               displayHex(pe.imageBase));
        addRow(m_metadata, QStringLiteral("Section alignment"),
               displayHex(pe.sectionAlignment));
        addRow(m_metadata, QStringLiteral("File alignment"),
               displayHex(pe.fileAlignment));
        addRow(m_metadata, QStringLiteral("Size of image"),
               QStringLiteral("%1 (%2 bytes)").arg(displayHex(pe.sizeOfImage))
                   .arg(pe.sizeOfImage));
        addRow(m_metadata, QStringLiteral("Sections"),
               QStringLiteral("%1 parsed / %2 declared")
                   .arg(pe.sections.size())
                   .arg(pe.numberOfSections));
        addRow(m_metadata, QStringLiteral("Import libraries"),
               QString::number(pe.imports.size()));
        addRow(m_metadata, QStringLiteral("Named exports"), QString::number(pe.exports.size()));
        addRow(m_metadata, QStringLiteral("Resources"), QString::number(pe.resources.size()));
        addRow(m_metadata, QStringLiteral("Overlay"), displayBytes(pe.overlaySize));
        addRow(m_metadata, QStringLiteral("Checksum"),
               pe.checksumPresent
                   ? (pe.checksumValid ? QStringLiteral("present and valid")
                                       : QStringLiteral("present but does not match"))
                   : QStringLiteral("absent/zero"));
        addRow(m_metadata, QStringLiteral("TLS"),
               pe.tls.present
                   ? QStringLiteral("present, %1 callback(s)").arg(pe.tls.callbacks.size())
                   : QStringLiteral("absent"));
        addRow(m_metadata, QStringLiteral(".NET / CLR"),
               pe.hasClrDirectory ? QStringLiteral("present") : QStringLiteral("absent"));
        addRow(m_metadata, QStringLiteral("Rich header"),
               pe.hasRichHeader ? QStringLiteral("present") : QStringLiteral("absent"));
        addRow(m_metadata, QStringLiteral("File entropy"),
               result.fileEntropyComputed
                   ? QStringLiteral("%1 bits/byte").arg(result.fileEntropy, 0, 'f', 3)
                   : QStringLiteral("not computed"));
    }

    m_hashes->setRowCount(0);
    addRow(m_hashes, QStringLiteral("SHA-256"), fromUtf8(file.hashes.sha256));
    addRow(m_hashes, QStringLiteral("SHA-1"), fromUtf8(file.hashes.sha1));
    addRow(m_hashes, QStringLiteral("MD5"),
           file.hashes.md5.empty() ? QStringLiteral("(not computed)") : fromUtf8(file.hashes.md5));

    m_diagnostics->clear();
    if (result.diagnostics.empty()) {
        m_diagnostics->addItem(QStringLiteral("No parser diagnostics."));
    }
    for (const auto& diagnostic : result.diagnostics) {
        m_diagnostics->addItem(QStringLiteral("%1%2: %3")
                                   .arg(diagnostic.fatal ? QStringLiteral("[fatal] ")
                                                         : QString(),
                                        fromUtf8(diagnostic.code),
                                        fromUtf8(diagnostic.message)));
    }
}

void FileAnalysisView::clear() {
    m_content->setVisible(false);
    m_summary->setVisible(false);
    m_empty->setVisible(true);
    m_metadata->setRowCount(0);
    m_hashes->setRowCount(0);
    m_diagnostics->clear();
}

} // namespace explainbin::ui
