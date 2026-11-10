#include "explainbin/ui/SignatureView.hpp"

#include "explainbin/ui/Theme.hpp"

#include <QColor>
#include <QHeaderView>
#include <QLabel>
#include <QListWidget>
#include <QTableWidget>
#include <QVBoxLayout>

namespace explainbin::ui {
namespace {

QString statusColor(const SignatureInfo& signature) {
    switch (signature.status) {
    case SignatureStatus::Valid:
        return QStringLiteral("#5fd18b");
    case SignatureStatus::Invalid:
        return QStringLiteral("#ef4d64");
    case SignatureStatus::Unsigned:
        return QStringLiteral("#54b6d6");
    case SignatureStatus::Unknown:
        return QStringLiteral("#e0b04a");
    case SignatureStatus::NotChecked:
        break;
    }
    return QStringLiteral("#6b8fa8");
}

QString orPlaceholder(const std::string& value, const QString& placeholder) {
    return value.empty() ? placeholder : fromUtf8(value);
}

QTableWidget* createDetailTable(QWidget* parent) {
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

void addDetail(QTableWidget* table, const QString& key, const QString& value) {
    const int row = table->rowCount();
    table->insertRow(row);
    table->setItem(row, 0, new QTableWidgetItem(key));
    auto* item = new QTableWidgetItem(value);
    table->setItem(row, 1, item);
}

} // namespace

SignatureView::SignatureView(QWidget* parent) : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(26, 22, 26, 22);
    root->setSpacing(12);

    auto* title = new QLabel(QStringLiteral("Digital Signature"), this);
    title->setObjectName(QStringLiteral("sectionTitle"));
    auto* hint = new QLabel(
        QStringLiteral("Authenticode verification through the Windows trust engine. Revocation "
                       "is evaluated from the local cache only; no network requests are made."),
        this);
    hint->setObjectName(QStringLiteral("pageHint"));
    hint->setWordWrap(true);
    root->addWidget(title);
    root->addWidget(hint);

    m_status = new QLabel(this);
    m_status->setAlignment(Qt::AlignCenter);
    m_status->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Fixed);
    root->addWidget(m_status);

    m_headline = new QLabel(this);
    m_headline->setWordWrap(true);
    m_headline->setStyleSheet(QStringLiteral("font-size: 13pt; font-weight: 650;"));
    root->addWidget(m_headline);

    m_note = new QLabel(this);
    m_note->setObjectName(QStringLiteral("muted"));
    m_note->setWordWrap(true);
    root->addWidget(m_note);

    auto* detailsLabel = new QLabel(QStringLiteral("Certificate details"), this);
    detailsLabel->setStyleSheet(QStringLiteral("font-weight: 650; font-size: 11pt;"));
    m_details = createDetailTable(this);
    m_details->setMinimumHeight(220);
    root->addWidget(detailsLabel);
    root->addWidget(m_details, 3);

    auto* chainLabel = new QLabel(QStringLiteral("Certificate chain"), this);
    chainLabel->setStyleSheet(QStringLiteral("font-weight: 650; font-size: 11pt;"));
    m_chain = new QListWidget(this);
    m_chain->setObjectName(QStringLiteral("plainList"));
    m_chain->setAlternatingRowColors(true);
    m_chain->setWordWrap(true);
    m_chain->setMaximumHeight(170);
    root->addWidget(chainLabel);
    root->addWidget(m_chain, 1);
}

void SignatureView::setResult(const AnalysisResult& result) {
    const auto& signature = result.signature;
    m_details->setRowCount(0);
    m_chain->clear();

    const QColor color(statusColor(signature));
    m_status->setText(fromUtf8(std::string(toString(signature.status))).toUpper());
    m_status->setStyleSheet(QStringLiteral(
                                "QLabel { color: %1; border: 1px solid %2; "
                                "background: rgba(%3,%4,%5,30); border-radius: 9px; "
                                "padding: 4px 14px; font-size: 9pt; font-weight: 700; "
                                "letter-spacing: 1px; }")
                                .arg(color.name(), color.darker(150).name())
                                .arg(color.red())
                                .arg(color.green())
                                .arg(color.blue()));

    m_headline->setText(signature.statusText.empty()
                            ? QStringLiteral("No signature information available.")
                            : fromUtf8(signature.statusText));

    if (!signature.checked && !result.signatureRequested) {
        m_note->setText(
            QStringLiteral("Signature verification was disabled in Settings for this analysis. "
                           "The absence of a result says nothing about the file's origin."));
    } else if (!signature.checked) {
        m_note->setText(QStringLiteral("The signature could not be checked in this environment."));
    } else if (signature.status == SignatureStatus::Valid && signature.catalogSigned) {
        m_note->setText(
            QStringLiteral("This file has no embedded signature, but a trusted Windows catalog "
                           "on this system contains its hash and verified successfully. Catalog "
                           "signing only confirms publisher identity and file integrity; it does "
                           "not make the file safe to run."));
    } else if (!signature.present) {
        m_note->setText(
            QStringLiteral("No embedded Authenticode signature was found, and no matching "
                           "trusted catalog signature was verified locally. Files can still be "
                           "signed through a catalog that is not installed on this system. "
                           "Missing embedded signatures are common and not a verdict."));
    } else if (signature.status == SignatureStatus::Valid) {
        m_note->setText(
            QStringLiteral("Windows accepted the signature and its chain. A valid signature "
                           "only confirms who signed the file and that it was not modified "
                           "after signing; it does not make the file safe to run."));
    } else if (signature.status == SignatureStatus::Invalid) {
        m_note->setText(
            QStringLiteral("The embedded signature did not verify. Treat this as a strong "
                           "reason to investigate further before running the file."));
    } else {
        m_note->setText(
            QStringLiteral("The trust engine returned an inconclusive result. Review the trust "
                           "status and certificate details below."));
    }

    addDetail(m_details, QStringLiteral("Verification performed"),
              signature.checked ? QStringLiteral("yes") : QStringLiteral("no"));
    addDetail(m_details, QStringLiteral("Signature type"),
              signature.catalogSigned
                  ? QStringLiteral("Windows catalog (no embedded signature)")
                  : (signature.present ? QStringLiteral("Embedded Authenticode")
                                       : QStringLiteral("(none verified)")));
    addDetail(m_details, QStringLiteral("Embedded signature present"),
              signature.present ? QStringLiteral("yes") : QStringLiteral("no"));
    addDetail(m_details, QStringLiteral("Catalog signed"),
              signature.catalogSigned ? QStringLiteral("yes") : QStringLiteral("no"));
    addDetail(m_details, QStringLiteral("Subject"),
              orPlaceholder(signature.subject, QStringLiteral("(not available)")));
    addDetail(m_details, QStringLiteral("Issuer"),
              orPlaceholder(signature.issuer, QStringLiteral("(not available)")));
    addDetail(m_details, QStringLiteral("Serial number"),
              orPlaceholder(signature.serialNumber, QStringLiteral("(not available)")));
    addDetail(m_details, QStringLiteral("Valid from (UTC)"),
              orPlaceholder(signature.notBeforeUtc, QStringLiteral("(not available)")));
    addDetail(m_details, QStringLiteral("Valid until (UTC)"),
              orPlaceholder(signature.notAfterUtc, QStringLiteral("(not available)")));
    addDetail(m_details, QStringLiteral("Expired"),
              signature.expired ? QStringLiteral("yes") : QStringLiteral("no"));
    addDetail(m_details, QStringLiteral("Not yet valid"),
              signature.notYetValid ? QStringLiteral("yes") : QStringLiteral("no"));
    addDetail(m_details, QStringLiteral("Digest algorithm"),
              orPlaceholder(signature.digestAlgorithm, QStringLiteral("(not available)")));
    addDetail(m_details, QStringLiteral("Signature algorithm"),
              orPlaceholder(signature.signatureAlgorithm, QStringLiteral("(not available)")));
    addDetail(m_details, QStringLiteral("Revocation checked"),
              signature.revocationChecked
                  ? QStringLiteral("yes")
                  : QStringLiteral("no (offline / cache-only)"));
    addDetail(m_details, QStringLiteral("Trust status"),
              QStringLiteral("0x%1").arg(static_cast<qulonglong>(signature.trustStatus), 8, 16,
                                         QLatin1Char('0')));
    addDetail(m_details, QStringLiteral("Trust message"),
              orPlaceholder(signature.trustMessage, QStringLiteral("(none)")));

    if (signature.chain.empty()) {
        m_chain->addItem(QStringLiteral("No certificate chain was reported."));
    }
    for (const auto& certificate : signature.chain) {
        m_chain->addItem(fromUtf8(certificate));
    }
}

void SignatureView::clear() {
    m_status->clear();
    m_status->setStyleSheet(QString());
    m_headline->clear();
    m_note->clear();
    m_details->setRowCount(0);
    m_chain->clear();
}

} // namespace explainbin::ui
