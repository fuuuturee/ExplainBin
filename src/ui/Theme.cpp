#include "explainbin/ui/Theme.hpp"

#include "explainbin/core/Util.hpp"

#include <QApplication>
#include <QFont>
#include <QPalette>
#include <QStyleFactory>

namespace explainbin::ui {
namespace {

QString darkStyleSheet() {
    return QStringLiteral(R"(
* { outline: 0; }
QWidget { color: #dce6f2; font-family: "Segoe UI", "Inter", sans-serif; font-size: 10pt; }
QMainWindow, QDialog, QWidget#centralRoot { background: #080b10; }
QWidget#sidebar { background: #0b1118; border-right: 1px solid #1d2b39; }
QLabel#appName { font-size: 15pt; font-weight: 700; color: #eaf6ff; }
QLabel#appTagline { color: #7d90a4; font-size: 8.5pt; }
QLabel#muted { color: #8496a9; }
QLabel#sectionTitle { font-size: 16pt; font-weight: 650; color: #eaf6ff; }
QLabel#pageHint { color: #8496a9; }
QLabel#stageLabel { color: #9fb3c7; font-size: 9pt; }
QLabel#fileChip { background: #0f1b26; border: 1px solid #223040; border-radius: 7px; padding: 7px 12px; color: #bcd6e9; }
QWidget#headerBar { background: #0b1118; border-bottom: 1px solid #1d2b39; }
QListWidget#navList { background: transparent; border: none; }
QListWidget#navList::item { padding: 10px 12px; margin: 1px 6px; border-radius: 8px; color: #9fb3c7; }
QListWidget#navList::item:hover { background: #101a24; color: #dce6f2; }
QListWidget#navList::item:selected { background: #123247; color: #eaf6ff; }
QPushButton { background: #131c26; border: 1px solid #2a3a4b; border-radius: 7px; padding: 8px 16px; color: #dce6f2; font-weight: 600; }
QPushButton:hover { background: #182432; border-color: #35506a; }
QPushButton:pressed { background: #0f1822; }
QPushButton:disabled { color: #5b6c7e; border-color: #1d2b39; background: #0d141b; }
QPushButton#primary { background: #1b6f9e; border-color: #2a8dc4; color: #f3fbff; }
QPushButton#primary:hover { background: #2180b5; }
QPushButton#primary:disabled { background: #123244; border-color: #1d4054; color: #6f8ea3; }
QFrame#card { background: #0f151d; border: 1px solid #223040; border-radius: 12px; }
QFrame#findingCard { background: #0f151d; border: 1px solid #223040; border-radius: 10px; }
QFrame#panel { background: #0f151d; border: 1px solid #223040; border-radius: 12px; }
QLabel#cardTitle { color: #8496a9; font-size: 8.5pt; font-weight: 650; letter-spacing: 1px; }
QLabel#cardValue { color: #eaf6ff; font-size: 16pt; font-weight: 700; }
QLabel#cardSubtitle { color: #7d90a4; font-size: 8.5pt; }
QTableWidget, QTreeWidget, QListWidget#plainList { background: #0f151d; alternate-background-color: #101a24; gridline-color: #1b2836; border: 1px solid #223040; border-radius: 8px; }
QTableWidget::item, QTreeWidget::item { padding: 5px; }
QTableWidget::item:selected, QTreeWidget::item:selected { background: #123247; color: #eaf6ff; }
QHeaderView::section { background: #131c26; color: #8496a9; border: none; border-bottom: 1px solid #223040; border-right: 1px solid #1b2836; padding: 7px; font-weight: 650; font-size: 9pt; }
QTableCornerButton::section { background: #131c26; border: none; }
QLineEdit, QComboBox, QSpinBox { background: #0f151d; border: 1px solid #2a3a4b; border-radius: 7px; padding: 7px 10px; color: #dce6f2; selection-background-color: #1b6f9e; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border-color: #2a8dc4; }
QComboBox::drop-down { border: none; width: 22px; }
QComboBox QAbstractItemView { background: #101a24; border: 1px solid #2a3a4b; selection-background-color: #123247; }
QSpinBox::up-button, QSpinBox::down-button { background: #131c26; border: none; width: 18px; }
QCheckBox { spacing: 9px; padding: 3px 0; }
QCheckBox::indicator { width: 17px; height: 17px; border-radius: 4px; border: 1px solid #35506a; background: #0f151d; }
QCheckBox::indicator:checked { background: #2180b5; border-color: #2a8dc4; }
QScrollArea { border: none; background: transparent; }
QScrollArea > QWidget > QWidget { background: transparent; }
QScrollBar:vertical { background: transparent; width: 11px; margin: 2px; }
QScrollBar::handle:vertical { background: #2a3a4b; border-radius: 4px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #3a5a75; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: transparent; height: 11px; margin: 2px; }
QScrollBar::handle:horizontal { background: #2a3a4b; border-radius: 4px; min-width: 30px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QProgressBar { background: #0f151d; border: 1px solid #223040; border-radius: 5px; height: 8px; text-align: center; color: transparent; }
QProgressBar::chunk { background: #2a8dc4; border-radius: 4px; }
QTabWidget::pane { border: 1px solid #223040; border-radius: 8px; background: #0f151d; top: -1px; }
QTabBar::tab { background: transparent; color: #8496a9; padding: 8px 16px; border: none; border-bottom: 2px solid transparent; }
QTabBar::tab:selected { color: #eaf6ff; border-bottom: 2px solid #2a8dc4; }
QTabBar::tab:hover { color: #dce6f2; }
QSplitter::handle { background: #1d2b39; width: 1px; }
QPlainTextEdit, QTextEdit { background: #0b1118; border: 1px solid #223040; border-radius: 8px; color: #bcd6e9; selection-background-color: #1b6f9e; }
QMenu { background: #101a24; border: 1px solid #2a3a4b; }
QMenu::item:selected { background: #123247; }
QToolTip { background: #101a24; color: #dce6f2; border: 1px solid #35506a; padding: 5px; }
QStatusBar { background: #0b1118; color: #7d90a4; border-top: 1px solid #1d2b39; }
QMessageBox { background: #0f151d; }
)");
}

QString lightStyleSheet() {
    return QStringLiteral(R"(
* { outline: 0; }
QWidget { color: #15202b; font-family: "Segoe UI", "Inter", sans-serif; font-size: 10pt; }
QMainWindow, QDialog, QWidget#centralRoot { background: #f2f5f8; }
QWidget#sidebar { background: #e8eef4; border-right: 1px solid #c8d4df; }
QLabel#appName { font-size: 15pt; font-weight: 700; color: #10202e; }
QLabel#appTagline { color: #5b6f81; font-size: 8.5pt; }
QLabel#muted { color: #5b6f81; }
QLabel#sectionTitle { font-size: 16pt; font-weight: 650; color: #10202e; }
QLabel#pageHint { color: #5b6f81; }
QLabel#stageLabel { color: #475b6d; font-size: 9pt; }
QLabel#fileChip { background: #ffffff; border: 1px solid #c8d4df; border-radius: 7px; padding: 7px 12px; color: #33485c; }
QWidget#headerBar { background: #e8eef4; border-bottom: 1px solid #c8d4df; }
QListWidget#navList { background: transparent; border: none; }
QListWidget#navList::item { padding: 10px 12px; margin: 1px 6px; border-radius: 8px; color: #475b6d; }
QListWidget#navList::item:hover { background: #dce6ef; color: #10202e; }
QListWidget#navList::item:selected { background: #cfe5f3; color: #0d3c56; }
QPushButton { background: #ffffff; border: 1px solid #bfcedb; border-radius: 7px; padding: 8px 16px; color: #1b2c3c; font-weight: 600; }
QPushButton:hover { background: #f6f9fc; border-color: #8fb0c8; }
QPushButton:pressed { background: #e8eef4; }
QPushButton:disabled { color: #9aabb9; border-color: #d8e1e9; background: #eef2f6; }
QPushButton#primary { background: #1b6f9e; border-color: #155f8a; color: #ffffff; }
QPushButton#primary:hover { background: #2180b5; }
QPushButton#primary:disabled { background: #a9c4d5; border-color: #a9c4d5; color: #eef6fb; }
QFrame#card { background: #ffffff; border: 1px solid #d3dde6; border-radius: 12px; }
QFrame#findingCard { background: #ffffff; border: 1px solid #d3dde6; border-radius: 10px; }
QFrame#panel { background: #ffffff; border: 1px solid #d3dde6; border-radius: 12px; }
QLabel#cardTitle { color: #5b6f81; font-size: 8.5pt; font-weight: 650; letter-spacing: 1px; }
QLabel#cardValue { color: #10202e; font-size: 16pt; font-weight: 700; }
QLabel#cardSubtitle { color: #5b6f81; font-size: 8.5pt; }
QTableWidget, QTreeWidget, QListWidget#plainList { background: #ffffff; alternate-background-color: #f6f9fc; gridline-color: #dde6ee; border: 1px solid #d3dde6; border-radius: 8px; color: #1b2c3c; }
QTableWidget::item, QTreeWidget::item { padding: 5px; }
QTableWidget::item:selected, QTreeWidget::item:selected { background: #cfe5f3; color: #0d3c56; }
QHeaderView::section { background: #eef3f8; color: #475b6d; border: none; border-bottom: 1px solid #d3dde6; border-right: 1px solid #dde6ee; padding: 7px; font-weight: 650; font-size: 9pt; }
QTableCornerButton::section { background: #eef3f8; border: none; }
QLineEdit, QComboBox, QSpinBox { background: #ffffff; border: 1px solid #bfcedb; border-radius: 7px; padding: 7px 10px; color: #1b2c3c; selection-background-color: #1b6f9e; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border-color: #2a8dc4; }
QComboBox::drop-down { border: none; width: 22px; }
QComboBox QAbstractItemView { background: #ffffff; border: 1px solid #bfcedb; selection-background-color: #cfe5f3; }
QSpinBox::up-button, QSpinBox::down-button { background: #eef3f8; border: none; width: 18px; }
QCheckBox { spacing: 9px; padding: 3px 0; }
QCheckBox::indicator { width: 17px; height: 17px; border-radius: 4px; border: 1px solid #9db4c7; background: #ffffff; }
QCheckBox::indicator:checked { background: #2180b5; border-color: #155f8a; }
QScrollArea { border: none; background: transparent; }
QScrollArea > QWidget > QWidget { background: transparent; }
QScrollBar:vertical { background: transparent; width: 11px; margin: 2px; }
QScrollBar::handle:vertical { background: #c1cfdb; border-radius: 4px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #9db4c7; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: transparent; height: 11px; margin: 2px; }
QScrollBar::handle:horizontal { background: #c1cfdb; border-radius: 4px; min-width: 30px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QProgressBar { background: #e8eef4; border: 1px solid #c8d4df; border-radius: 5px; height: 8px; text-align: center; color: transparent; }
QProgressBar::chunk { background: #2a8dc4; border-radius: 4px; }
QTabWidget::pane { border: 1px solid #d3dde6; border-radius: 8px; background: #ffffff; top: -1px; }
QTabBar::tab { background: transparent; color: #5b6f81; padding: 8px 16px; border: none; border-bottom: 2px solid transparent; }
QTabBar::tab:selected { color: #10202e; border-bottom: 2px solid #2a8dc4; }
QTabBar::tab:hover { color: #1b2c3c; }
QSplitter::handle { background: #d3dde6; width: 1px; }
QPlainTextEdit, QTextEdit { background: #ffffff; border: 1px solid #d3dde6; border-radius: 8px; color: #1b2c3c; selection-background-color: #1b6f9e; }
QMenu { background: #ffffff; border: 1px solid #bfcedb; }
QMenu::item:selected { background: #cfe5f3; }
QToolTip { background: #ffffff; color: #1b2c3c; border: 1px solid #bfcedb; padding: 5px; }
QStatusBar { background: #e8eef4; color: #5b6f81; border-top: 1px solid #c8d4df; }
QMessageBox { background: #ffffff; }
)");
}

} // namespace

void applyTheme(QApplication& application, bool dark) {
    application.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));

    QPalette palette;
    if (dark) {
        palette.setColor(QPalette::Window, QColor(0x08, 0x0b, 0x10));
        palette.setColor(QPalette::WindowText, QColor(0xdc, 0xe6, 0xf2));
        palette.setColor(QPalette::Base, QColor(0x0f, 0x15, 0x1d));
        palette.setColor(QPalette::AlternateBase, QColor(0x10, 0x1a, 0x24));
        palette.setColor(QPalette::Text, QColor(0xdc, 0xe6, 0xf2));
        palette.setColor(QPalette::Button, QColor(0x13, 0x1c, 0x26));
        palette.setColor(QPalette::ButtonText, QColor(0xdc, 0xe6, 0xf2));
        palette.setColor(QPalette::Highlight, QColor(0x1b, 0x6f, 0x9e));
        palette.setColor(QPalette::HighlightedText, QColor(0xf3, 0xfb, 0xff));
        palette.setColor(QPalette::ToolTipBase, QColor(0x10, 0x1a, 0x24));
        palette.setColor(QPalette::ToolTipText, QColor(0xdc, 0xe6, 0xf2));
        palette.setColor(QPalette::PlaceholderText, QColor(0x6f, 0x84, 0x99));
    } else {
        palette.setColor(QPalette::Window, QColor(0xf2, 0xf5, 0xf8));
        palette.setColor(QPalette::WindowText, QColor(0x15, 0x20, 0x2b));
        palette.setColor(QPalette::Base, QColor(0xff, 0xff, 0xff));
        palette.setColor(QPalette::AlternateBase, QColor(0xf6, 0xf9, 0xfc));
        palette.setColor(QPalette::Text, QColor(0x1b, 0x2c, 0x3c));
        palette.setColor(QPalette::Button, QColor(0xff, 0xff, 0xff));
        palette.setColor(QPalette::ButtonText, QColor(0x1b, 0x2c, 0x3c));
        palette.setColor(QPalette::Highlight, QColor(0x1b, 0x6f, 0x9e));
        palette.setColor(QPalette::HighlightedText, QColor(0xff, 0xff, 0xff));
        palette.setColor(QPalette::ToolTipBase, QColor(0xff, 0xff, 0xff));
        palette.setColor(QPalette::ToolTipText, QColor(0x1b, 0x2c, 0x3c));
        palette.setColor(QPalette::PlaceholderText, QColor(0x8a, 0x9c, 0xac));
    }
    application.setPalette(palette);

    QFont font(QStringLiteral("Segoe UI"));
    font.setPointSizeF(9.75);
    application.setFont(font);
    application.setStyleSheet(dark ? darkStyleSheet() : lightStyleSheet());
}

QColor severityColor(Severity severity) {
    switch (severity) {
    case Severity::Critical: return QColor(0xef, 0x4d, 0x64);
    case Severity::High: return QColor(0xf0, 0x7b, 0x4d);
    case Severity::Medium: return QColor(0xe0, 0xb0, 0x4a);
    case Severity::Low: return QColor(0x54, 0xb6, 0xd6);
    case Severity::Informational: return QColor(0x6b, 0x8f, 0xa8);
    }
    return QColor(0x6b, 0x8f, 0xa8);
}

QString severityLabel(Severity severity) {
    const auto text = toString(severity);
    return QString::fromUtf8(text.data(), static_cast<int>(text.size()));
}

QString severityBadgeStyle(Severity severity) {
    const QColor color = severityColor(severity);
    return QStringLiteral(
               "QLabel { color: %1; border: 1px solid %2; background: %3; "
               "border-radius: 9px; padding: 2px 9px; font-size: 8pt; font-weight: 700; "
               "letter-spacing: 1px; }")
        .arg(color.name(),
             color.darker(160).name(),
             QStringLiteral("rgba(%1,%2,%3,28)")
                 .arg(color.red())
                 .arg(color.green())
                 .arg(color.blue()));
}

QString displayHex(std::uint64_t value) {
    return QString::fromStdString(util::toHex(value));
}

QString displayBytes(std::uint64_t bytes) {
    return QString::fromStdString(util::humanBytes(bytes));
}

QString fromUtf8(const std::string& value) {
    return QString::fromUtf8(value.data(), static_cast<int>(value.size()));
}

} // namespace explainbin::ui
