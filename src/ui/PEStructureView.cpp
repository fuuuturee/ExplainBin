#include "explainbin/ui/PEStructureView.hpp"

#include "explainbin/ui/Theme.hpp"

#include <QHeaderView>
#include <QLabel>
#include <QPlainTextEdit>
#include <QTableWidget>
#include <QVBoxLayout>

#include <array>

namespace explainbin::ui {
namespace {

QTableWidget* createTable(const QStringList& headers, QWidget* parent) {
    auto* table = new QTableWidget(0, headers.size(), parent);
    table->setHorizontalHeaderLabels(headers);
    table->verticalHeader()->setVisible(false);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setAlternatingRowColors(true);
    table->setShowGrid(false);
    table->horizontalHeader()->setStretchLastSection(true);
    return table;
}

void addRow(QTableWidget* table, const QStringList& values) {
    const int row = table->rowCount();
    table->insertRow(row);
    for (int column = 0; column < values.size(); ++column) {
        auto* item = new QTableWidgetItem(values.at(column));
        table->setItem(row, column, item);
    }
}

QString yesNo(bool value) {
    return value ? QStringLiteral("yes") : QStringLiteral("no");
}

QString sectionFlags(const SectionInfo& section) {
    QStringList flags;
    if (section.readable) {
        flags << QStringLiteral("R");
    }
    if (section.writable) {
        flags << QStringLiteral("W");
    }
    if (section.executable) {
        flags << QStringLiteral("X");
    }
    if (section.code) {
        flags << QStringLiteral("code");
    }
    if (section.initializedData) {
        flags << QStringLiteral("init-data");
    }
    if (section.uninitializedData) {
        flags << QStringLiteral("uninit-data");
    }
    if (!section.rawRangeValid) {
        flags << QStringLiteral("invalid-raw-range");
    }
    return flags.join(QStringLiteral(" | "));
}

QString entropyText(double entropy) {
    if (entropy < 0.0) {
        return QStringLiteral("not computed");
    }
    return QStringLiteral("%1 bits/byte").arg(entropy, 0, 'f', 3);
}

} // namespace

PEStructureView::PEStructureView(QWidget* parent) : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(26, 22, 26, 22);
    root->setSpacing(12);

    auto* title = new QLabel(QStringLiteral("PE Structure"), this);
    title->setObjectName(QStringLiteral("sectionTitle"));
    auto* hint = new QLabel(
        QStringLiteral("Headers, sections and data directories as read from the file. "
                       "Every offset and size was validated against the real file buffer."),
        this);
    hint->setObjectName(QStringLiteral("pageHint"));
    hint->setWordWrap(true);
    root->addWidget(title);
    root->addWidget(hint);

    auto* headersLabel = new QLabel(QStringLiteral("Headers"), this);
    headersLabel->setStyleSheet(QStringLiteral("font-weight: 650; font-size: 11pt;"));
    m_headers = createTable({QStringLiteral("Field"), QStringLiteral("Value")}, this);
    m_headers->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_headers->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_headers->setMinimumHeight(210);
    root->addWidget(headersLabel);
    root->addWidget(m_headers, 2);

    auto* sectionsLabel = new QLabel(QStringLiteral("Sections"), this);
    sectionsLabel->setStyleSheet(QStringLiteral("font-weight: 650; font-size: 11pt;"));
    m_sections = createTable(
        {QStringLiteral("Name"), QStringLiteral("Virtual address"), QStringLiteral("Virtual size"),
         QStringLiteral("Raw offset"), QStringLiteral("Raw size"), QStringLiteral("Entropy"),
         QStringLiteral("Flags")},
        this);
    m_sections->setMinimumHeight(180);
    root->addWidget(sectionsLabel);
    root->addWidget(m_sections, 2);

    auto* directoriesLabel = new QLabel(QStringLiteral("Data directories"), this);
    directoriesLabel->setStyleSheet(QStringLiteral("font-weight: 650; font-size: 11pt;"));
    m_directories = createTable(
        {QStringLiteral("#"), QStringLiteral("Directory"), QStringLiteral("RVA"),
         QStringLiteral("Size"), QStringLiteral("State")},
        this);
    m_directories->setMinimumHeight(160);
    root->addWidget(directoriesLabel);
    root->addWidget(m_directories, 2);

    auto* extrasLabel = new QLabel(QStringLiteral("TLS, debug, resources and overlay"), this);
    extrasLabel->setStyleSheet(QStringLiteral("font-weight: 650; font-size: 11pt;"));
    m_extras = new QPlainTextEdit(this);
    m_extras->setReadOnly(true);
    m_extras->setMaximumHeight(170);
    m_extras->setLineWrapMode(QPlainTextEdit::NoWrap);
    m_extras->setPlaceholderText(QStringLiteral("No analysis result yet."));
    root->addWidget(extrasLabel);
    root->addWidget(m_extras, 1);
}

void PEStructureView::setResult(const AnalysisResult& result) {
    m_headers->setRowCount(0);
    m_sections->setRowCount(0);
    m_directories->setRowCount(0);
    m_extras->clear();

    if (!result.pe.parsed) {
        m_extras->setPlainText(
            QStringLiteral("The PE structure could not be parsed. Enable the parser diagnostics "
                           "on the File Analysis page for details.\n\n") +
            fromUtf8(result.errorMessage));
        return;
    }

    fillHeaders(result.pe);
    fillSections(result.pe);
    fillDirectories(result.pe);
    fillExtras(result);
}

void PEStructureView::fillHeaders(const PeInfo& pe) {
    addRow(m_headers, {QStringLiteral("Format"), fromUtf8(pe.format)});
    addRow(m_headers, {QStringLiteral("Machine"), fromUtf8(pe.machineName) + QStringLiteral(" (") +
                                               displayHex(pe.machine) + QStringLiteral(")")});
    addRow(m_headers, {QStringLiteral("Subsystem"), fromUtf8(pe.subsystemName)});
    addRow(m_headers, {QStringLiteral("Image kind"),
                       pe.isDll ? QStringLiteral("DLL") : QStringLiteral("Executable")});
    addRow(m_headers, {QStringLiteral("Linker version"), fromUtf8(pe.linkerVersion)});
    addRow(m_headers, {QStringLiteral("OS version"), fromUtf8(pe.osVersion)});
    addRow(m_headers, {QStringLiteral("Subsystem version"), fromUtf8(pe.subsystemVersion)});
    addRow(m_headers, {QStringLiteral("Compile timestamp"),
                       pe.timestampUtc.empty() ? QStringLiteral("(zero or unavailable)")
                                               : fromUtf8(pe.timestampUtc)});
    addRow(m_headers, {QStringLiteral("Entry point RVA"), displayHex(pe.entryPointRva)});
    addRow(m_headers, {QStringLiteral("Image base"), displayHex(pe.imageBase)});
    addRow(m_headers, {QStringLiteral("Section alignment"), displayHex(pe.sectionAlignment)});
    addRow(m_headers, {QStringLiteral("File alignment"), displayHex(pe.fileAlignment)});
    addRow(m_headers, {QStringLiteral("Size of image"), displayHex(pe.sizeOfImage)});
    addRow(m_headers, {QStringLiteral("Size of headers"), displayHex(pe.sizeOfHeaders)});
    addRow(m_headers, {QStringLiteral("Stored checksum"), displayHex(pe.checksum)});
    addRow(m_headers, {QStringLiteral("Computed checksum"), displayHex(pe.computedChecksum)});
    addRow(m_headers, {QStringLiteral("Checksum state"),
                       !pe.checksumPresent ? QStringLiteral("absent/zero")
                                           : (pe.checksumValid ? QStringLiteral("matches")
                                                               : QStringLiteral("mismatch"))});
    addRow(m_headers, {QStringLiteral("Sections"),
                       QStringLiteral("%1 parsed / %2 declared")
                           .arg(pe.sections.size())
                           .arg(pe.numberOfSections)});
    addRow(m_headers, {QStringLiteral("Partial parse"), yesNo(pe.partial)});
    addRow(m_headers, {QStringLiteral("DLL characteristics"),
                       displayHex(pe.dllCharacteristics)});
    addRow(m_headers, {QStringLiteral("Relocations"), yesNo(pe.hasRelocations)});
    addRow(m_headers, {QStringLiteral("CLR / .NET"), yesNo(pe.hasClrDirectory)});
    addRow(m_headers, {QStringLiteral("Rich header"), yesNo(pe.hasRichHeader)});
    addRow(m_headers, {QStringLiteral("Certificate table"),
                       pe.hasCertificateTable
                           ? QStringLiteral("present at %1, %2 bytes, %3 entries")
                                 .arg(displayHex(pe.certificateTableOffset))
                                 .arg(pe.certificateTableSize)
                                 .arg(pe.certificateEntryCount)
                           : QStringLiteral("absent")});
}

void PEStructureView::fillSections(const PeInfo& pe) {
    for (const auto& section : pe.sections) {
        addRow(m_sections,
               {fromUtf8(section.name), displayHex(section.virtualAddress),
                displayHex(section.virtualSize), displayHex(section.rawOffset),
                displayHex(section.rawSize), entropyText(section.entropy),
                sectionFlags(section)});
    }
    if (pe.sections.empty()) {
        addRow(m_sections, {QStringLiteral("(no sections parsed)"), QString(), QString(),
                            QString(), QString(), QString(), QString()});
    }
    m_sections->resizeColumnsToContents();
}

void PEStructureView::fillDirectories(const PeInfo& pe) {
    for (const auto& directory : pe.directories) {
        QString state;
        if (!directory.present) {
            state = QStringLiteral("not present");
        } else if (!directory.valid) {
            state = QStringLiteral("present but unmapped");
        } else {
            state = QStringLiteral("present");
        }
        if (!directory.note.empty()) {
            state += QStringLiteral(" \u00b7 ") + fromUtf8(directory.note);
        }
        addRow(m_directories,
               {QString::number(directory.index), fromUtf8(directory.name),
                displayHex(directory.rva), displayHex(directory.size), state});
    }
    if (pe.directories.empty()) {
        addRow(m_directories,
               {QStringLiteral("-"), QStringLiteral("(directories not parsed)"), QString(),
                QString(), QString()});
    }
    m_directories->resizeColumnsToContents();
}

void PEStructureView::fillExtras(const AnalysisResult& result) {
    const auto& pe = result.pe;
    QStringList lines;

    if (pe.overlaySize > 0) {
        lines << QStringLiteral("Overlay: %1 bytes at file offset %2")
                     .arg(pe.overlaySize)
                     .arg(displayHex(pe.overlayOffset));
    } else {
        lines << QStringLiteral("Overlay: none");
    }

    if (pe.tls.present) {
        lines << QStringLiteral("TLS: present at image base %1, callbacks address %2, "
                                "zero fill %3 bytes, %4 callback(s)")
                     .arg(displayHex(pe.tls.imageBase), displayHex(pe.tls.addressOfCallbacks))
                     .arg(pe.tls.sizeOfZeroFill)
                     .arg(pe.tls.callbacks.size());
        for (const auto callback : pe.tls.callbacks) {
            lines << QStringLiteral("  TLS callback: %1").arg(displayHex(callback));
        }
    } else {
        lines << QStringLiteral("TLS: absent");
    }

    if (!pe.debugEntries.empty()) {
        for (const auto& entry : pe.debugEntries) {
            lines << QStringLiteral("Debug entry: %1 (%2 bytes)%3")
                         .arg(fromUtf8(entry.typeName))
                         .arg(entry.dataSize)
                         .arg(entry.rawOffsetValid ? QStringLiteral("")
                                                   : QStringLiteral(" [offset invalid]"));
            if (!entry.pdbPath.empty()) {
                lines << QStringLiteral("  PDB: ") + fromUtf8(entry.pdbPath);
            }
            if (!entry.guid.empty()) {
                lines << QStringLiteral("  GUID: %1, age %2")
                             .arg(fromUtf8(entry.guid))
                             .arg(entry.age);
            }
        }
    }

    if (!pe.resources.empty()) {
        lines << QStringLiteral("Resources: %1 entries").arg(pe.resources.size());
        int shown = 0;
        for (const auto& resource : pe.resources) {
            if (shown++ >= 20) {
                lines << QStringLiteral("  ... additional entries omitted from this view");
                break;
            }
            lines << QStringLiteral("  %1 / %2 / %3: %4 bytes at RVA %5")
                         .arg(fromUtf8(resource.type), fromUtf8(resource.name),
                              fromUtf8(resource.language))
                         .arg(resource.size)
                         .arg(displayHex(resource.dataRva));
        }
    } else {
        lines << QStringLiteral("Resources: none parsed");
    }

    if (!pe.exportDllName.empty()) {
        lines << QStringLiteral("Export module: ") + fromUtf8(pe.exportDllName);
    }

    if (result.fileEntropyComputed) {
        lines << QStringLiteral("Whole-file entropy: %1 bits/byte")
                     .arg(result.fileEntropy, 0, 'f', 3);
    }

    m_extras->setPlainText(lines.join(QStringLiteral("\n")));
}

void PEStructureView::clear() {
    m_headers->setRowCount(0);
    m_sections->setRowCount(0);
    m_directories->setRowCount(0);
    m_extras->clear();
}

} // namespace explainbin::ui
