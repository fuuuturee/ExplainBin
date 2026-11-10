#include "explainbin/ui/Theme.hpp"

#include "explainbin/core/Util.hpp"
#include "explainbin/ui/AppSettings.hpp"

#include <QApplication>
#include <QFont>
#include <QPalette>
#include <QStyleFactory>

namespace explainbin::ui {
namespace {

QString darkStyleSheet() {
    return QStringLiteral(R"(
* { outline: 0; }

QWidget {
    color: #dfeaf5;
    font-family: "Segoe UI Variable Text", "Segoe UI", "Inter", sans-serif;
    font-size: 10pt;
}
QMainWindow, QDialog, QWidget#centralRoot { background: #0a0f15; }

/* ---------- Sidebar ---------- */
QWidget#sidebar {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0d1620, stop:1 #0a1119);
    border-right: 1px solid #1b2836;
}
QLabel#appName {
    font-family: "Segoe UI Variable Display", "Segoe UI";
    font-size: 16pt;
    font-weight: 700;
    color: #f2f9ff;
}
QLabel#appTagline { color: #7f93a8; font-size: 8.5pt; }
QLabel#navSection {
    color: #5f7488;
    font-size: 7.8pt;
    font-weight: 700;
}
QLabel#footerStatus { color: #7f93a8; font-size: 8.2pt; }

QListWidget#navList { background: transparent; border: none; padding: 0; }
QListWidget#navList::item {
    padding: 9px 12px;
    margin: 2px 8px;
    border-radius: 9px;
    color: #9db1c5;
}
QListWidget#navList::item:hover { background: #13202c; color: #e8f3fc; }
QListWidget#navList::item:selected {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #17374c, stop:1 #112a3b);
    color: #f4fbff;
}
QWidget#navIndicator {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #5cc8f0, stop:1 #2a8dc4);
    border-radius: 2px;
}
QFrame#sidebarSeparator {
    color: #1b2836;
    background: #1b2836;
    border: none;
    max-height: 1px;
    margin: 6px 6px;
}

/* ---------- Header ---------- */
QWidget#headerBar { background: #0c131b; border-bottom: 1px solid #1b2836; }
QWidget#progressRow { background: #0c131b; border-bottom: 1px solid #15212c; }
QLabel#fileChip {
    background: #111b25;
    border: 1px solid #243546;
    border-radius: 9px;
    padding: 8px 14px;
    color: #c3d8ea;
}
QLabel#stageLabel { color: #9db1c5; font-size: 9pt; }
QLabel#sectionTitle {
    font-family: "Segoe UI Variable Display", "Segoe UI";
    font-size: 19pt;
    font-weight: 650;
    color: #f2f9ff;
}
QLabel#pageHint { color: #8498ac; font-size: 9.5pt; }
QLabel#panelTitle { font-size: 11pt; font-weight: 650; color: #dbe9f6; }
QLabel#emptyTitle { font-size: 14pt; font-weight: 650; color: #dfeaf5; }
QLabel#emptyHint { color: #8498ac; font-size: 9.5pt; }
QLabel#muted { color: #8498ac; }
QLabel#fieldLabel { color: #8fb3cc; font-weight: 650; }

/* ---------- Buttons ---------- */
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #17222e, stop:1 #121b25);
    border: 1px solid #2a3d4f;
    border-radius: 9px;
    padding: 8px 18px;
    color: #dfeaf5;
    font-weight: 600;
}
QPushButton:hover { background: #1a2937; border-color: #3c5a74; }
QPushButton:pressed { background: #101923; }
QPushButton:focus { border-color: #3a9fd4; }
QPushButton:disabled { color: #5c7185; border-color: #1d2a36; background: #0e151d; }

QPushButton#primary {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #38a3d8, stop:1 #1f7cae);
    border: 1px solid #4cb4e6;
    color: #ffffff;
}
QPushButton#primary:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #46b2e6, stop:1 #2489bd);
}
QPushButton#primary:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1c709d, stop:1 #175d84);
}
QPushButton#primary:disabled {
    background: #123244;
    border-color: #1d4054;
    color: #6f8ea3;
}

/* ---------- Surfaces ---------- */
QFrame#card {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #121c27, stop:1 #0f1721);
    border: 1px solid #223244;
    border-radius: 14px;
}
QFrame#card:hover { border-color: #32526c; }
QFrame#findingCard {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #121c27, stop:1 #0f1721);
    border: 1px solid #223244;
    border-radius: 12px;
}
QFrame#findingCard:hover { border-color: #32526c; }
QFrame#panel {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #121c27, stop:1 #0f1721);
    border: 1px solid #223244;
    border-radius: 14px;
}
QFrame#emptyPanel {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #0f1822, stop:1 #0c131b);
    border: 1px dashed #2a3e52;
    border-radius: 18px;
}
QLabel#cardTitle {
    color: #8498ac;
    font-size: 8pt;
    font-weight: 700;
}
QLabel#cardValue {
    font-family: "Segoe UI Variable Display", "Segoe UI";
    color: #f2f9ff;
    font-size: 19pt;
    font-weight: 700;
}
QLabel#cardSubtitle { color: #7f93a8; font-size: 8.5pt; }

/* ---------- Tables and lists ---------- */
QTableWidget, QTreeWidget, QListWidget#plainList {
    background: #111a24;
    alternate-background-color: #131e29;
    gridline-color: #1e2d3c;
    border: 1px solid #223244;
    border-radius: 10px;
    selection-background-color: #17374c;
    selection-color: #f4fbff;
}
QTableWidget::item, QTreeWidget::item { padding: 6px 7px; }
QTableWidget::item:selected, QTreeWidget::item:selected { background: #17374c; color: #f4fbff; }
QListWidget#plainList::item { padding: 6px 9px; }
QHeaderView::section {
    background: #14202b;
    color: #8fa4b9;
    border: none;
    border-bottom: 1px solid #223244;
    border-right: 1px solid #1b2836;
    padding: 8px 7px;
    font-weight: 650;
    font-size: 9pt;
}
QTableCornerButton::section { background: #14202b; border: none; }

/* ---------- Inputs ---------- */
QLineEdit, QComboBox, QSpinBox {
    background: #101923;
    border: 1px solid #2a3d4f;
    border-radius: 9px;
    padding: 8px 11px;
    color: #dfeaf5;
    selection-background-color: #1f7cae;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border-color: #3a9fd4; }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox QAbstractItemView {
    background: #131e29;
    border: 1px solid #2a3d4f;
    selection-background-color: #17374c;
    padding: 4px;
}
QSpinBox::up-button, QSpinBox::down-button { background: #17222e; border: none; width: 18px; }
QCheckBox { spacing: 9px; padding: 3px 0; }
QCheckBox::indicator {
    width: 17px;
    height: 17px;
    border-radius: 5px;
    border: 1px solid #3a5168;
    background: #101923;
}
QCheckBox::indicator:hover { border-color: #4d6b87; }
QCheckBox::indicator:checked {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #38a3d8, stop:1 #1f7cae);
    border-color: #4cb4e6;
    image: url(:/icons/check.svg);
}

/* ---------- Scrolling and progress ---------- */
QScrollArea { border: none; background: transparent; }
QScrollArea > QWidget > QWidget { background: transparent; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: #2a3d4f; border-radius: 3px; min-height: 32px; }
QScrollBar::handle:vertical:hover { background: #3c5a74; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px; }
QScrollBar::handle:horizontal { background: #2a3d4f; border-radius: 3px; min-width: 32px; }
QScrollBar::handle:horizontal:hover { background: #3c5a74; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QProgressBar {
    background: #101923;
    border: 1px solid #223244;
    border-radius: 4px;
    height: 7px;
    text-align: center;
    color: transparent;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2a8dc4, stop:1 #5cc8f0);
    border-radius: 3px;
}

/* ---------- Tabs, splitter and text ---------- */
QTabWidget::pane {
    border: 1px solid #223244;
    border-radius: 10px;
    background: #111a24;
    top: -1px;
}
QTabBar::tab {
    background: transparent;
    color: #8498ac;
    padding: 9px 17px;
    border: none;
    border-bottom: 2px solid transparent;
}
QTabBar::tab:selected { color: #f2f9ff; border-bottom: 2px solid #3a9fd4; }
QTabBar::tab:hover { color: #dfeaf5; }
QSplitter::handle { background: #1b2836; width: 1px; }
QPlainTextEdit, QTextEdit {
    background: #0d151d;
    border: 1px solid #223244;
    border-radius: 10px;
    color: #c3d8ea;
    selection-background-color: #1f7cae;
}
QMenu { background: #131e29; border: 1px solid #2a3d4f; border-radius: 8px; padding: 4px; }
QMenu::item { padding: 6px 22px; border-radius: 5px; }
QMenu::item:selected { background: #17374c; }
QToolTip {
    background: #131e29;
    color: #dfeaf5;
    border: 1px solid #35506a;
    border-radius: 6px;
    padding: 5px 8px;
}
QStatusBar { background: #0c131b; color: #7f93a8; border-top: 1px solid #1b2836; }
QMessageBox { background: #111a24; }
)");
}

QString lightStyleSheet() {
    return QStringLiteral(R"(
* { outline: 0; }

QWidget {
    color: #16222e;
    font-family: "Segoe UI Variable Text", "Segoe UI", "Inter", sans-serif;
    font-size: 10pt;
}
QMainWindow, QDialog, QWidget#centralRoot { background: #f3f6fa; }

/* ---------- Sidebar ---------- */
QWidget#sidebar {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #eef4fa, stop:1 #e8eff7);
    border-right: 1px solid #d5e0eb;
}
QLabel#appName {
    font-family: "Segoe UI Variable Display", "Segoe UI";
    font-size: 16pt;
    font-weight: 700;
    color: #0f2233;
}
QLabel#appTagline { color: #5d7285; font-size: 8.5pt; }
QLabel#navSection {
    color: #7a8ea1;
    font-size: 7.8pt;
    font-weight: 700;
}
QLabel#footerStatus { color: #5d7285; font-size: 8.2pt; }

QListWidget#navList { background: transparent; border: none; padding: 0; }
QListWidget#navList::item {
    padding: 9px 12px;
    margin: 2px 8px;
    border-radius: 9px;
    color: #4a5f73;
}
QListWidget#navList::item:hover { background: #e1eaf3; color: #10202e; }
QListWidget#navList::item:selected {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #d5e9f7, stop:1 #e8f3fb);
    color: #0c3a55;
}
QWidget#navIndicator {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #5cc8f0, stop:1 #2a8dc4);
    border-radius: 2px;
}
QFrame#sidebarSeparator {
    color: #d5e0eb;
    background: #d5e0eb;
    border: none;
    max-height: 1px;
    margin: 6px 6px;
}

/* ---------- Header ---------- */
QWidget#headerBar { background: #f7fafd; border-bottom: 1px solid #d5e0eb; }
QWidget#progressRow { background: #f7fafd; border-bottom: 1px solid #e4ecf4; }
QLabel#fileChip {
    background: #ffffff;
    border: 1px solid #d2dfea;
    border-radius: 9px;
    padding: 8px 14px;
    color: #3a5065;
}
QLabel#stageLabel { color: #5d7285; font-size: 9pt; }
QLabel#sectionTitle {
    font-family: "Segoe UI Variable Display", "Segoe UI";
    font-size: 19pt;
    font-weight: 650;
    color: #0f2233;
}
QLabel#pageHint { color: #5d7285; font-size: 9.5pt; }
QLabel#panelTitle { font-size: 11pt; font-weight: 650; color: #1c3348; }
QLabel#emptyTitle { font-size: 14pt; font-weight: 650; color: #16222e; }
QLabel#emptyHint { color: #5d7285; font-size: 9.5pt; }
QLabel#muted { color: #5d7285; }
QLabel#fieldLabel { color: #3a6b8f; font-weight: 650; }

/* ---------- Buttons ---------- */
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #ffffff, stop:1 #f4f8fc);
    border: 1px solid #c4d4e2;
    border-radius: 9px;
    padding: 8px 18px;
    color: #1b2d3d;
    font-weight: 600;
}
QPushButton:hover { background: #f8fbfe; border-color: #93b3cb; }
QPushButton:pressed { background: #e8eff6; }
QPushButton:focus { border-color: #2a8dc4; }
QPushButton:disabled { color: #99aab9; border-color: #dde6ee; background: #eef3f7; }

QPushButton#primary {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #38a3d8, stop:1 #1f7cae);
    border: 1px solid #2a8dc4;
    color: #ffffff;
}
QPushButton#primary:hover { background: #2f9bcf; }
QPushButton#primary:pressed { background: #1b6d99; }
QPushButton#primary:disabled { background: #aac7d9; border-color: #aac7d9; color: #eef7fc; }

/* ---------- Surfaces ---------- */
QFrame#card {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #ffffff, stop:1 #fbfdff);
    border: 1px solid #d9e3ed;
    border-radius: 14px;
}
QFrame#card:hover { border-color: #a8c2d6; }
QFrame#findingCard {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #ffffff, stop:1 #fbfdff);
    border: 1px solid #d9e3ed;
    border-radius: 12px;
}
QFrame#findingCard:hover { border-color: #a8c2d6; }
QFrame#panel {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #ffffff, stop:1 #fbfdff);
    border: 1px solid #d9e3ed;
    border-radius: 14px;
}
QFrame#emptyPanel {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #ffffff, stop:1 #f8fbfe);
    border: 1px dashed #c2d4e3;
    border-radius: 18px;
}
QLabel#cardTitle { color: #5d7285; font-size: 8pt; font-weight: 700; }
QLabel#cardValue {
    font-family: "Segoe UI Variable Display", "Segoe UI";
    color: #0f2233;
    font-size: 19pt;
    font-weight: 700;
}
QLabel#cardSubtitle { color: #5d7285; font-size: 8.5pt; }

/* ---------- Tables and lists ---------- */
QTableWidget, QTreeWidget, QListWidget#plainList {
    background: #ffffff;
    alternate-background-color: #f5f9fc;
    gridline-color: #e2eaf2;
    border: 1px solid #d9e3ed;
    border-radius: 10px;
    color: #1b2d3d;
    selection-background-color: #d5e9f7;
    selection-color: #0c3a55;
}
QTableWidget::item, QTreeWidget::item { padding: 6px 7px; }
QTableWidget::item:selected, QTreeWidget::item:selected {
    background: #d5e9f7;
    color: #0c3a55;
}
QListWidget#plainList::item { padding: 6px 9px; }
QHeaderView::section {
    background: #eff4f9;
    color: #4a5f73;
    border: none;
    border-bottom: 1px solid #d9e3ed;
    border-right: 1px solid #e2eaf2;
    padding: 8px 7px;
    font-weight: 650;
    font-size: 9pt;
}
QTableCornerButton::section { background: #eff4f9; border: none; }

/* ---------- Inputs ---------- */
QLineEdit, QComboBox, QSpinBox {
    background: #ffffff;
    border: 1px solid #c4d4e2;
    border-radius: 9px;
    padding: 8px 11px;
    color: #1b2d3d;
    selection-background-color: #2a8dc4;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border-color: #2a8dc4; }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox QAbstractItemView {
    background: #ffffff;
    border: 1px solid #c4d4e2;
    selection-background-color: #d5e9f7;
    padding: 4px;
}
QSpinBox::up-button, QSpinBox::down-button { background: #eef3f8; border: none; width: 18px; }
QCheckBox { spacing: 9px; padding: 3px 0; }
QCheckBox::indicator {
    width: 17px;
    height: 17px;
    border-radius: 5px;
    border: 1px solid #9db4c7;
    background: #ffffff;
}
QCheckBox::indicator:hover { border-color: #7397b2; }
QCheckBox::indicator:checked {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #38a3d8, stop:1 #1f7cae);
    border-color: #2a8dc4;
    image: url(:/icons/check.svg);
}

/* ---------- Scrolling and progress ---------- */
QScrollArea { border: none; background: transparent; }
QScrollArea > QWidget > QWidget { background: transparent; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: #c6d5e2; border-radius: 3px; min-height: 32px; }
QScrollBar::handle:vertical:hover { background: #9fb6ca; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px; }
QScrollBar::handle:horizontal { background: #c6d5e2; border-radius: 3px; min-width: 32px; }
QScrollBar::handle:horizontal:hover { background: #9fb6ca; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QProgressBar {
    background: #e6eef6;
    border: 1px solid #d9e3ed;
    border-radius: 4px;
    height: 7px;
    text-align: center;
    color: transparent;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2a8dc4, stop:1 #5cc8f0);
    border-radius: 3px;
}

/* ---------- Tabs, splitter and text ---------- */
QTabWidget::pane {
    border: 1px solid #d9e3ed;
    border-radius: 10px;
    background: #ffffff;
    top: -1px;
}
QTabBar::tab {
    background: transparent;
    color: #5d7285;
    padding: 9px 17px;
    border: none;
    border-bottom: 2px solid transparent;
}
QTabBar::tab:selected { color: #0f2233; border-bottom: 2px solid #2a8dc4; }
QTabBar::tab:hover { color: #1b2d3d; }
QSplitter::handle { background: #d9e3ed; width: 1px; }
QPlainTextEdit, QTextEdit {
    background: #ffffff;
    border: 1px solid #d9e3ed;
    border-radius: 10px;
    color: #1b2d3d;
    selection-background-color: #2a8dc4;
}
QMenu { background: #ffffff; border: 1px solid #c4d4e2; border-radius: 8px; padding: 4px; }
QMenu::item { padding: 6px 22px; border-radius: 5px; }
QMenu::item:selected { background: #d5e9f7; }
QToolTip {
    background: #ffffff;
    color: #16222e;
    border: 1px solid #c4d4e2;
    border-radius: 6px;
    padding: 5px 8px;
}
QStatusBar { background: #f7fafd; color: #5d7285; border-top: 1px solid #d5e0eb; }
QMessageBox { background: #ffffff; }
)");
}

} // namespace

void applyTheme(QApplication& application, bool dark) {
    application.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));

    QPalette palette;
    if (dark) {
        palette.setColor(QPalette::Window, QColor(0x0a, 0x0f, 0x15));
        palette.setColor(QPalette::WindowText, QColor(0xdf, 0xea, 0xf5));
        palette.setColor(QPalette::Base, QColor(0x11, 0x1a, 0x24));
        palette.setColor(QPalette::AlternateBase, QColor(0x13, 0x1e, 0x29));
        palette.setColor(QPalette::Text, QColor(0xdf, 0xea, 0xf5));
        palette.setColor(QPalette::Button, QColor(0x17, 0x22, 0x2e));
        palette.setColor(QPalette::ButtonText, QColor(0xdf, 0xea, 0xf5));
        palette.setColor(QPalette::Highlight, QColor(0x1f, 0x7c, 0xae));
        palette.setColor(QPalette::HighlightedText, QColor(0xf4, 0xfb, 0xff));
        palette.setColor(QPalette::ToolTipBase, QColor(0x13, 0x1e, 0x29));
        palette.setColor(QPalette::ToolTipText, QColor(0xdf, 0xea, 0xf5));
        palette.setColor(QPalette::PlaceholderText, QColor(0x6f, 0x84, 0x99));
        palette.setColor(QPalette::Mid, QColor(0x2a, 0x3d, 0x4f));
    } else {
        palette.setColor(QPalette::Window, QColor(0xf3, 0xf6, 0xfa));
        palette.setColor(QPalette::WindowText, QColor(0x16, 0x22, 0x2e));
        palette.setColor(QPalette::Base, QColor(0xff, 0xff, 0xff));
        palette.setColor(QPalette::AlternateBase, QColor(0xf5, 0xf9, 0xfc));
        palette.setColor(QPalette::Text, QColor(0x1b, 0x2d, 0x3d));
        palette.setColor(QPalette::Button, QColor(0xff, 0xff, 0xff));
        palette.setColor(QPalette::ButtonText, QColor(0x1b, 0x2d, 0x3d));
        palette.setColor(QPalette::Highlight, QColor(0x2a, 0x8d, 0xc4));
        palette.setColor(QPalette::HighlightedText, QColor(0xff, 0xff, 0xff));
        palette.setColor(QPalette::ToolTipBase, QColor(0xff, 0xff, 0xff));
        palette.setColor(QPalette::ToolTipText, QColor(0x1b, 0x2d, 0x3d));
        palette.setColor(QPalette::PlaceholderText, QColor(0x8a, 0x9c, 0xac));
        palette.setColor(QPalette::Mid, QColor(0xc6, 0xd5, 0xe2));
    }
    application.setPalette(palette);

    QFont font(QStringLiteral("Segoe UI"));
    font.setPointSizeF(9.75);
    application.setFont(font);
    application.setStyleSheet(dark ? darkStyleSheet() : lightStyleSheet());

    application.setProperty("explainbin.animations", AppSettings::load().animations);
}

QColor severityColor(Severity severity) {
    switch (severity) {
    case Severity::Critical: return QColor(0xff, 0x5d, 0x73);
    case Severity::High: return QColor(0xff, 0x8a, 0x5c);
    case Severity::Medium: return QColor(0xe8, 0xb6, 0x4c);
    case Severity::Low: return QColor(0x5c, 0xc4, 0xe6);
    case Severity::Informational: return QColor(0x7b, 0x93, 0xa8);
    }
    return QColor(0x7b, 0x93, 0xa8);
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
