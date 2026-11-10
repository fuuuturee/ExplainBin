#pragma once

#include "explainbin/core/Types.hpp"

#include <QFutureWatcher>
#include <QMainWindow>

class QLabel;
class QListWidget;
class QProgressBar;
class QPropertyAnimation;
class QPushButton;
class QShowEvent;
class QStackedWidget;
class QVBoxLayout;

namespace explainbin::ui {

class Dashboard;
class FileAnalysisView;
class ImportsExportsView;
class PEStructureView;
class ReportView;
class SettingsView;
class SignatureView;
class FindingsView;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    void openFile(const QString& path);

protected:
    void dragEnterEvent(QDragEnterEvent* event) override;
    void dropEvent(QDropEvent* event) override;
    void closeEvent(QCloseEvent* event) override;
    void showEvent(QShowEvent* event) override;

private:
    void buildInterface();
    void startAnalysis();
    void onAnalysisFinished();
    void onSettingsChanged();
    void setBusy(bool busy);
    void navigate(int index);
    void updateNavIndicator(bool animate);
    void updateViews();
    void setResult(const AnalysisResult& result);

    Dashboard* m_dashboard = nullptr;
    FileAnalysisView* m_fileAnalysis = nullptr;
    PEStructureView* m_structure = nullptr;
    ImportsExportsView* m_imports = nullptr;
    SignatureView* m_signature = nullptr;
    FindingsView* m_findings = nullptr;
    ReportView* m_reports = nullptr;
    SettingsView* m_settings = nullptr;

    QListWidget* m_navigation = nullptr;
    QStackedWidget* m_stack = nullptr;
    QWidget* m_navIndicator = nullptr;
    QPropertyAnimation* m_navIndicatorAnimation = nullptr;
    QLabel* m_fileChip = nullptr;
    QLabel* m_stage = nullptr;
    QProgressBar* m_progress = nullptr;
    QPushButton* m_openButton = nullptr;
    QPushButton* m_analyzeButton = nullptr;

    QFutureWatcher<AnalysisResult> m_watcher;
    AnalysisResult m_result;
    QString m_path;
    bool m_hasResult = false;
    bool m_closing = false;
    bool m_firstShow = true;
};

} // namespace explainbin::ui
