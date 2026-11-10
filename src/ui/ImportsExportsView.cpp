#include "explainbin/ui/ImportsExportsView.hpp"

#include "explainbin/ui/Theme.hpp"

#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QTableWidget>
#include <QTreeWidget>
#include <QVBoxLayout>

namespace explainbin::ui {
namespace {

QString categoryLabel(const std::string& category) {
    return category.empty() ? QStringLiteral("general") : fromUtf8(category);
}

QString functionLabel(const ImportFunction& function) {
    if (function.byOrdinal) {
        return QStringLiteral("Ordinal %1").arg(function.ordinal);
    }
    return fromUtf8(function.name);
}

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

} // namespace

ImportsExportsView::ImportsExportsView(QWidget* parent) : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(26, 22, 26, 22);
    root->setSpacing(12);

    auto* title = new QLabel(QStringLiteral("Imports & Exports"), this);
    title->setObjectName(QStringLiteral("sectionTitle"));
    auto* hint = new QLabel(
        QStringLiteral("Imported libraries and functions grouped by module, plus exported entry "
                       "points. API categories are observations, not proof of intent."),
        this);
    hint->setObjectName(QStringLiteral("pageHint"));
    hint->setWordWrap(true);
    root->addWidget(title);
    root->addWidget(hint);

    auto* filterRow = new QWidget(this);
    auto* filterLayout = new QHBoxLayout(filterRow);
    filterLayout->setContentsMargins(0, 0, 0, 0);
    filterLayout->setSpacing(10);
    m_filter = new QLineEdit(filterRow);
    m_filter->setPlaceholderText(QStringLiteral("Filter by library, function, category or insight\u2026"));
    m_filter->setClearButtonEnabled(true);
    m_summary = new QLabel(filterRow);
    m_summary->setObjectName(QStringLiteral("muted"));
    filterLayout->addWidget(m_filter, 1);
    filterLayout->addWidget(m_summary);
    root->addWidget(filterRow);

    auto* importsLabel = new QLabel(QStringLiteral("Imports"), this);
    importsLabel->setStyleSheet(QStringLiteral("font-weight: 650; font-size: 11pt;"));
    m_imports = new QTreeWidget(this);
    m_imports->setColumnCount(3);
    m_imports->setHeaderLabels({QStringLiteral("Library / function"),
                                QStringLiteral("Category"),
                                QStringLiteral("Explanation")});
    m_imports->setRootIsDecorated(true);
    m_imports->setAlternatingRowColors(true);
    m_imports->setUniformRowHeights(true);
    m_imports->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_imports->header()->setStretchLastSection(true);
    m_imports->header()->resizeSection(0, 280);
    m_imports->header()->resizeSection(1, 150);
    root->addWidget(importsLabel);
    root->addWidget(m_imports, 3);

    auto* exportsLabel = new QLabel(QStringLiteral("Exports"), this);
    exportsLabel->setStyleSheet(QStringLiteral("font-weight: 650; font-size: 11pt;"));
    m_exports = createTable({QStringLiteral("Name"), QStringLiteral("Ordinal"),
                             QStringLiteral("RVA"), QStringLiteral("Forwarder")},
                            this);
    m_exports->setMinimumHeight(150);
    root->addWidget(exportsLabel);
    root->addWidget(m_exports, 2);

    connect(m_filter, &QLineEdit::textChanged, this, &ImportsExportsView::applyFilter);
}

void ImportsExportsView::setResult(const AnalysisResult& result) {
    populateImports(result.pe);
    populateExports(result.pe);
    applyFilter(m_filter->text());
}

void ImportsExportsView::populateImports(const PeInfo& pe) {
    m_imports->clear();
    if (pe.imports.empty()) {
        auto* empty = new QTreeWidgetItem(m_imports);
        empty->setText(0, QStringLiteral("(no imports parsed)"));
        empty->setFirstColumnSpanned(true);
        return;
    }

    int functionCount = 0;
    for (const auto& library : pe.imports) {
        auto* libraryItem = new QTreeWidgetItem(m_imports);
        libraryItem->setText(0, fromUtf8(library.name) +
                                   (library.delayLoad ? QStringLiteral("  (delay-load)")
                                                      : QString()));
        libraryItem->setText(1, library.delayLoad ? QStringLiteral("delay-load")
                                                  : QStringLiteral("static import"));
        libraryItem->setText(2, QStringLiteral("%1 function(s)").arg(library.functions.size()));
        libraryItem->setFlags(libraryItem->flags() & ~Qt::ItemIsSelectable);

        for (const auto& function : library.functions) {
            auto* item = new QTreeWidgetItem(libraryItem);
            item->setText(0, functionLabel(function));
            item->setText(1, categoryLabel(function.category));
            item->setText(2, fromUtf8(function.insight));
            ++functionCount;
        }
        libraryItem->setExpanded(false);
    }

    m_summary->setText(QStringLiteral("%1 libraries \u00b7 %2 functions")
                           .arg(pe.imports.size())
                           .arg(functionCount));
}

void ImportsExportsView::populateExports(const PeInfo& pe) {
    m_exports->setRowCount(0);
    if (!pe.exportDllName.empty()) {
        addRow(m_exports, {QStringLiteral("(module) ") + fromUtf8(pe.exportDllName),
                           QStringLiteral("base %1").arg(pe.exportOrdinalBase), QString(),
                           QString()});
    }
    for (const auto& entry : pe.exports) {
        addRow(m_exports,
               {fromUtf8(entry.name), QString::number(entry.ordinal),
                displayHex(entry.rva),
                entry.forwarder ? fromUtf8(entry.forwarderName)
                                : QStringLiteral("no")});
    }
    if (pe.exports.empty()) {
        addRow(m_exports, {QStringLiteral("(no named exports)"), QString(), QString(),
                           QString()});
    }
    m_exports->resizeColumnsToContents();
    if (m_exports->columnWidth(3) < 80) {
        m_exports->setColumnWidth(3, 80);
    }
}

void ImportsExportsView::applyFilter(const QString& text) {
    const QString needle = text.trimmed();
    int visibleLibraries = 0;
    int visibleFunctions = 0;

    for (int i = 0; i < m_imports->topLevelItemCount(); ++i) {
        auto* libraryItem = m_imports->topLevelItem(i);
        int childMatches = 0;
        for (int j = 0; j < libraryItem->childCount(); ++j) {
            auto* child = libraryItem->child(j);
            bool match = needle.isEmpty();
            for (int column = 0; column < 3 && !match; ++column) {
                match = child->text(column).contains(needle, Qt::CaseInsensitive);
            }
            child->setHidden(!match);
            if (match) {
                ++childMatches;
            }
        }

        bool libraryMatch = needle.isEmpty() ||
                            libraryItem->text(0).contains(needle, Qt::CaseInsensitive) ||
                            libraryItem->text(2).contains(needle, Qt::CaseInsensitive);
        const bool visible = libraryMatch || childMatches > 0;
        libraryItem->setHidden(!visible);
        if (visible) {
            ++visibleLibraries;
            visibleFunctions += childMatches;
            if (!needle.isEmpty() && childMatches > 0) {
                libraryItem->setExpanded(true);
            }
        }
    }

    if (needle.isEmpty()) {
        m_summary->setText(QStringLiteral("%1 libraries / %2 functions shown")
                               .arg(visibleLibraries)
                               .arg(visibleFunctions));
    } else {
        m_summary->setText(QStringLiteral("%1 match(es) in %2 libraries")
                               .arg(visibleFunctions)
                               .arg(visibleLibraries));
    }
}

void ImportsExportsView::clear() {
    m_imports->clear();
    m_exports->setRowCount(0);
    m_summary->clear();
    m_filter->clear();
}

} // namespace explainbin::ui
