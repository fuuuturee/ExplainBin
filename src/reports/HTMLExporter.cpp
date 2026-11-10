#include "explainbin/reports/ReportExporter.hpp"

#include "explainbin/core/Util.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <sstream>
#include <string>
#include <string_view>

namespace explainbin {
namespace {

std::string escape(std::string_view input) {
    std::string output;
    output.reserve(input.size() + 16);
    for (const char ch : input) {
        switch (ch) {
        case '&': output += "&amp;"; break;
        case '<': output += "&lt;"; break;
        case '>': output += "&gt;"; break;
        case '"': output += "&quot;"; break;
        case '\'': output += "&#39;"; break;
        case '\n': output += "<br>"; break;
        default: output.push_back(ch); break;
        }
    }
    return output;
}

std::string_view severityClass(Severity severity) {
    switch (severity) {
    case Severity::Informational: return "info";
    case Severity::Low: return "low";
    case Severity::Medium: return "medium";
    case Severity::High: return "high";
    case Severity::Critical: return "critical";
    }
    return "info";
}

std::string_view signatureClass(SignatureStatus status) {
    switch (status) {
    case SignatureStatus::Valid: return "ok";
    case SignatureStatus::Invalid: return "critical";
    case SignatureStatus::Unsigned: return "muted";
    case SignatureStatus::Unknown: return "medium";
    case SignatureStatus::NotChecked: return "muted";
    }
    return "muted";
}

std::string listItems(const std::vector<std::string>& items, const char* emptyText) {
    if (items.empty()) {
        return std::string("<p class=\"muted\">") + escape(emptyText) + "</p>";
    }
    std::ostringstream out;
    out << "<ul>";
    for (const auto& item : items) {
        out << "<li>" << escape(item) << "</li>";
    }
    out << "</ul>";
    return out.str();
}

std::string severityRow(const char* label, int count, int maximum) {
    const int percent = maximum <= 0 ? 0 : (count * 100) / maximum;
    std::ostringstream out;
    out << "<div class=\"severity-row\"><span>" << label << "</span>"
        << "<div class=\"bar\"><i style=\"width:" << percent << "%\"></i></div>"
        << "<b>" << count << "</b></div>";
    return out.str();
}

std::string entropyText(double entropy) {
    if (entropy < 0.0) {
        return "n/a";
    }
    std::array<char, 16> buffer{};
    std::snprintf(buffer.data(), buffer.size(), "%.3f", entropy);
    return buffer.data();
}

} // namespace

std::string HTMLExporter::render(const AnalysisResult& result) const {
    const auto counts = countSeverities(result.findings);
    const int maximum = std::max({counts.informational, counts.low, counts.medium,
                                  counts.high, counts.critical, 1});
    const auto& pe = result.pe;
    const auto& signature = result.signature;

    std::ostringstream out;
    out << R"(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>ExplainBin report - )" << escape(result.file.fileName) << R"(</title>
<style>
:root{--bg:#080b10;--panel:#0f151d;--panel2:#131c26;--line:#223040;--text:#dce6f2;--muted:#8496a9;--accent:#4cc2ff;--info:#6b8fa8;--low:#54b6d6;--medium:#e0b04a;--high:#f07b4d;--critical:#ef4d64;--ok:#5fd18b}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(1000px 500px at 15% -10%,#10283a 0,var(--bg) 60%);color:var(--text);font:14px/1.55 "Segoe UI",system-ui,-apple-system,sans-serif}
.page{max-width:1180px;margin:0 auto;padding:40px 28px 70px}
.hero{display:flex;justify-content:space-between;gap:24px;align-items:flex-start;border-bottom:1px solid var(--line);padding-bottom:26px;margin-bottom:22px}
.brand{font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--accent);font-size:12px;margin-bottom:10px}
h1{font-size:28px;line-height:1.2;margin:0 0 8px;word-break:break-all}h2{font-size:18px;margin:34px 0 14px}h3{font-size:15px;margin:0 0 8px}h4{font-size:11px;letter-spacing:.09em;text-transform:uppercase;color:var(--muted);margin:18px 0 7px}
.sub{color:var(--muted);word-break:break-all}.pill,.badge{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:3px 10px;font-size:11px;font-weight:650;letter-spacing:.04em;text-transform:uppercase}
.notice{border:1px solid #27405a;background:linear-gradient(90deg,#0d2233,#0e1922);border-radius:12px;padding:14px 18px;color:#b9d5e8;margin:0 0 24px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:12px}.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
.card .k{color:var(--muted);font-size:11px;letter-spacing:.08em;text-transform:uppercase}.card .v{font-size:20px;font-weight:650;margin-top:7px;word-break:break-word}.card .s{font-size:11px;color:var(--muted);margin-top:4px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}.two{display:grid;grid-template-columns:1.1fr .9fr;gap:16px}
.severity-row{display:grid;grid-template-columns:105px 1fr 32px;gap:10px;align-items:center;margin:8px 0}.severity-row span{font-size:12px;color:var(--muted)}.severity-row b{text-align:right}
.bar{height:8px;background:#0a1017;border-radius:99px;overflow:hidden;border:1px solid #1b2836}.bar i{display:block;height:100%;background:linear-gradient(90deg,var(--accent),#7de1ff)}
table{width:100%;border-collapse:collapse;font-size:12.5px;margin:8px 0}th{text-align:left;color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--line);padding:8px}
td{border-bottom:1px solid #18232f;padding:8px;vertical-align:top}tr:last-child td{border-bottom:0}code,.mono{font-family:"Cascadia Mono",Consolas,monospace;font-size:12px;color:#a9d7ee;word-break:break-all}
.finding{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:10px;margin:10px 0;overflow:hidden}.finding.high{border-left-color:var(--high)}.finding.critical{border-left-color:var(--critical)}.finding.medium{border-left-color:var(--medium)}.finding.low{border-left-color:var(--low)}
.finding summary{cursor:pointer;padding:14px 16px;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap;list-style:none}.finding summary::-webkit-details-marker{display:none}.finding summary::before{content:"+";color:var(--muted);font-family:monospace}.finding[open] summary::before{content:"-"}
.finding .title{font-weight:650}.finding .meta{color:var(--muted);font-size:11.5px}.finding .body{padding:0 18px 18px;border-top:1px solid #18232f}
.badge.info{border-color:#315166;color:#9bbbd0}.badge.low{border-color:#2d6172;color:#7cd3e9}.badge.medium{border-color:#6b5524;color:#edc264}.badge.high{border-color:#733f2b;color:#ff9a72}.badge.critical{border-color:#732c38;color:#ff8195}.badge.ok{border-color:#2c5e40;color:#78dfa0}.badge.muted{color:var(--muted)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}.muted{color:var(--muted)}ul{margin:6px 0;padding-left:20px}li{margin:4px 0}
.footer{margin-top:40px;border-top:1px solid var(--line);padding-top:16px;color:var(--muted);font-size:11.5px}
@media(max-width:760px){.two,.grid2{grid-template-columns:1fr}.hero{flex-direction:column}.page{padding:24px 16px}}
@media print{body{background:#fff;color:#111}.panel,.card,.finding{background:#fff;border-color:#bbb}.notice{background:#fff}.muted{color:#555}}
</style>
</head>
<body><div class="page">
<header class="hero">
 <div><div class="brand">ExplainBin / Static Analysis Report</div>
 <h1>)" << escape(result.file.fileName) << R"(</h1>
 <div class="sub">)" << escape(result.file.path) << R"(</div></div>
 <div><span class="pill">Local &middot; No execution</span></div>
</header>
<div class="notice"><strong>Static analysis is not a malware verdict.</strong> )" << escape(kStaticAnalysisDisclaimer) << R"(</div>
)";

    if (!result.success) {
        out << "<div class=\"panel\"><h2>Analysis failed</h2><p>"
            << escape(result.errorMessage.empty() ? "Unknown error." : result.errorMessage)
            << "</p></div>";
    } else {
        out << "<section class=\"cards\">"
            << "<div class=\"card\"><div class=\"k\">File size</div><div class=\"v\">"
            << util::humanBytes(result.file.size) << "</div><div class=\"s\">"
            << result.file.size << " bytes</div></div>"
            << "<div class=\"card\"><div class=\"k\">Format</div><div class=\"v\">"
            << (pe.parsed ? escape(pe.is64Bit ? "PE32+" : "PE32") : "Unknown")
            << "</div><div class=\"s\">" << (pe.parsed ? escape(pe.machineName) : "Unparsed")
            << "</div></div>"
            << "<div class=\"card\"><div class=\"k\">Architecture</div><div class=\"v\">"
            << (pe.parsed ? escape(pe.machineName) : "Unknown") << "</div><div class=\"s\">"
            << (pe.parsed ? escape(pe.subsystemName) : "No subsystem") << "</div></div>"
            << "<div class=\"card\"><div class=\"k\">Findings</div><div class=\"v\">"
            << counts.total() << "</div><div class=\"s\">" << counts.high << " high &middot; "
            << counts.critical << " critical</div></div>"
            << "<div class=\"card\"><div class=\"k\">Signature</div><div class=\"v\" style=\"font-size:15px\">"
            << escape(toString(signature.status)) << "</div><div class=\"s\">"
            << (signature.catalogSigned
                    ? "Verified via Windows catalog"
                    : (signature.checked ? "Authenticode checked" : "Not checked"))
            << "</div></div>"
            << "</section>";

        out << "<h2>Hashes and metadata</h2><div class=\"panel\"><table><tbody>"
            << "<tr><th>SHA-256</th><td class=\"mono\">" << escape(result.file.hashes.sha256) << "</td></tr>"
            << "<tr><th>SHA-1</th><td class=\"mono\">" << escape(result.file.hashes.sha1) << "</td></tr>"
            << "<tr><th>MD5</th><td class=\"mono\">" << escape(result.file.hashes.md5.empty() ? "(not computed)" : result.file.hashes.md5) << "</td></tr>"
            << "<tr><th>Last write (UTC)</th><td>" << escape(result.file.lastWriteTimeUtc) << "</td></tr>"
            << "<tr><th>Analyzed (UTC)</th><td>" << escape(result.analyzedAtUtc) << "</td></tr>"
            << "<tr><th>Analysis time</th><td>" << result.durationMs << " ms</td></tr>"
            << "</tbody></table></div>";

        out << "<h2>Severity overview</h2><div class=\"two\"><div class=\"panel\">"
            << severityRow("Informational", counts.informational, maximum)
            << severityRow("Low", counts.low, maximum)
            << severityRow("Medium", counts.medium, maximum)
            << severityRow("High", counts.high, maximum)
            << severityRow("Critical", counts.critical, maximum)
            << "<p class=\"muted\" style=\"margin-top:14px\">Counts describe observations, not a probability of malice. No combined malware score is used.</p></div>"
            << "<div class=\"panel\"><h3>PE summary</h3><table><tbody>"
            << "<tr><th>Entry point</th><td class=\"mono\">" << util::toHex(pe.entryPointRva) << "</td></tr>"
            << "<tr><th>Image base</th><td class=\"mono\">" << util::toHex(pe.imageBase) << "</td></tr>"
            << "<tr><th>Sections</th><td>" << pe.sections.size() << " parsed / " << pe.numberOfSections << " declared</td></tr>"
            << "<tr><th>Compile time</th><td>" << escape(pe.timestampUtc.empty() ? "(zero or unavailable)" : pe.timestampUtc) << "</td></tr>"
            << "<tr><th>Overlay</th><td>" << util::humanBytes(pe.overlaySize) << "</td></tr>"
            << "<tr><th>Signature</th><td>" << escape(signature.statusText) << "</td></tr>"
            << "</tbody></table></div></div>";

        out << "<h2>Findings</h2>";
        if (result.findings.empty()) {
            out << "<div class=\"panel\"><p>No findings matched the enabled rules. This does <strong>not</strong> prove that the file is safe.</p></div>";
        }
        for (const auto& finding : result.findings) {
            const bool open = finding.severity == Severity::High ||
                              finding.severity == Severity::Critical;
            out << "<details class=\"finding " << severityClass(finding.severity) << "\""
                << (open ? " open" : "") << "><summary>"
                << "<span class=\"badge " << severityClass(finding.severity) << "\">"
                << escape(toString(finding.severity)) << "</span>"
                << "<span class=\"title\">" << escape(finding.title) << "</span>"
                << "<span class=\"meta\">" << escape(finding.id) << " &middot; "
                << escape(finding.category) << " &middot; confidence "
                << escape(toString(finding.confidence)) << "</span></summary>"
                << "<div class=\"body\"><h4>What was observed</h4><p>"
                << escape(finding.description) << "</p><h4>Why it matters</h4><p>"
                << escape(finding.whyItMatters) << "</p><h4>Technical evidence</h4>"
                << listItems(finding.evidence, "No additional evidence recorded.")
                << "<div class=\"grid2\"><div><h4>Possible legitimate explanations</h4>"
                << listItems(finding.legitimateExplanations, "None recorded.")
                << "</div><div><h4>Recommended investigation</h4>"
                << listItems(finding.nextSteps, "No specific steps recorded.")
                << "</div></div></div></details>";
        }

        out << "<h2>Sections</h2><div class=\"panel\"><table><thead><tr>"
            << "<th>Name</th><th>Virtual address</th><th>Virtual size</th><th>Raw size</th>"
            << "<th>Entropy</th><th>Permissions</th></tr></thead><tbody>";
        for (const auto& section : pe.sections) {
            std::string permissions;
            if (section.readable) permissions += "R";
            if (section.writable) permissions += "W";
            if (section.executable) permissions += "X";
            out << "<tr><td class=\"mono\">" << escape(section.name) << "</td><td class=\"mono\">"
                << util::toHex(section.virtualAddress) << "</td><td>"
                << section.virtualSize << "</td><td>" << section.rawSize << "</td><td>"
                << entropyText(section.entropy)
                << "</td><td class=\"mono\">" << (permissions.empty() ? "-" : permissions)
                << "</td></tr>";
        }
        out << "</tbody></table></div>";

        out << "<h2>Imports and exports</h2><div class=\"panel\">";
        std::size_t functionCount = 0;
        for (const auto& library : pe.imports) {
            functionCount += library.functions.size();
        }
        out << "<p class=\"muted\">" << pe.imports.size() << " libraries, " << functionCount
            << " imported functions, " << pe.exports.size() << " named exports.</p>";
        if (!pe.imports.empty()) {
            out << "<table><thead><tr><th>Library</th><th>Functions</th><th>Type</th></tr></thead><tbody>";
            for (const auto& library : pe.imports) {
                out << "<tr><td class=\"mono\">" << escape(library.name) << "</td><td>"
                    << library.functions.size() << "</td><td>"
                    << (library.delayLoad ? "Delay-load" : "Import") << "</td></tr>";
            }
            out << "</tbody></table>";

            out << "<h3 style=\"margin-top:22px\">Notable imports</h3><table><thead><tr>"
                << "<th>Library</th><th>Function</th><th>Category</th><th>Context</th></tr></thead><tbody>";
            std::size_t shown = 0;
            for (const auto& library : pe.imports) {
                for (const auto& function : library.functions) {
                    if (function.insight.empty() || shown >= 300) {
                        continue;
                    }
                    out << "<tr><td class=\"mono\">" << escape(library.name) << "</td><td class=\"mono\">"
                        << escape(function.name) << "</td><td>" << escape(function.category)
                        << "</td><td>" << escape(function.insight) << "</td></tr>";
                    ++shown;
                }
            }
            out << "</tbody></table>";
            if (shown >= 300) {
                out << "<p class=\"muted\">Notable-import display truncated at 300 rows; the JSON report contains all entries.</p>";
            }
        }
        out << "</div>";

        out << "<h2>Digital signature</h2><div class=\"panel\"><p><span class=\"badge "
            << signatureClass(signature.status) << "\">" << escape(toString(signature.status))
            << "</span> <span class=\"muted\">" << escape(signature.statusText) << "</span></p>"
            << "<table><tbody>"
            << "<tr><th>Signature type</th><td>" << (signature.catalogSigned ? "Windows catalog (no embedded signature)" : (signature.present ? "Embedded Authenticode" : "(none verified)")) << "</td></tr>"
            << "<tr><th>Subject</th><td>" << escape(signature.subject.empty() ? "(unavailable)" : signature.subject) << "</td></tr>"
            << "<tr><th>Issuer</th><td>" << escape(signature.issuer.empty() ? "(unavailable)" : signature.issuer) << "</td></tr>"
            << "<tr><th>Serial</th><td class=\"mono\">" << escape(signature.serialNumber.empty() ? "(unavailable)" : signature.serialNumber) << "</td></tr>"
            << "<tr><th>Valid from</th><td>" << escape(signature.notBeforeUtc.empty() ? "(unavailable)" : signature.notBeforeUtc) << "</td></tr>"
            << "<tr><th>Valid until</th><td>" << escape(signature.notAfterUtc.empty() ? "(unavailable)" : signature.notAfterUtc) << "</td></tr>"
            << "<tr><th>Digest</th><td>" << escape(signature.digestAlgorithm.empty() ? "(unavailable)" : signature.digestAlgorithm) << "</td></tr>"
            << "<tr><th>Signature algorithm</th><td>" << escape(signature.signatureAlgorithm.empty() ? "(unavailable)" : signature.signatureAlgorithm) << "</td></tr>"
            << "<tr><th>Trust detail</th><td>" << escape(signature.trustMessage) << "</td></tr>"
            << "<tr><th>Revocation</th><td>" << (signature.revocationChecked ? "Checked online" : "Not checked online (local/cache-only policy)") << "</td></tr>"
            << "</tbody></table></div>";

        if (!pe.resources.empty() || !pe.debugEntries.empty() || !pe.tls.present) {
            out << "<h2>Resources, debug and TLS</h2><div class=\"panel\">"
                << "<p class=\"muted\">" << pe.resources.size() << " resource entries, "
                << pe.debugEntries.size() << " debug entries, TLS "
                << (pe.tls.present ? "present" : "absent") << ".</p>";
            if (!pe.debugEntries.empty()) {
                out << "<table><thead><tr><th>Debug type</th><th>PDB path</th><th>GUID</th></tr></thead><tbody>";
                for (const auto& entry : pe.debugEntries) {
                    out << "<tr><td>" << escape(entry.typeName) << "</td><td class=\"mono\">"
                        << escape(entry.pdbPath) << "</td><td class=\"mono\">" << escape(entry.guid)
                        << "</td></tr>";
                }
                out << "</tbody></table>";
            }
            out << "</div>";
        }

        if (!result.diagnostics.empty()) {
            out << "<h2>Parser diagnostics</h2><div class=\"panel\"><table><thead><tr>"
                << "<th>Code</th><th>Message</th><th>Fatal</th></tr></thead><tbody>";
            for (const auto& diagnostic : result.diagnostics) {
                out << "<tr><td class=\"mono\">" << escape(diagnostic.code) << "</td><td>"
                    << escape(diagnostic.message) << "</td><td>"
                    << (diagnostic.fatal ? "yes" : "no") << "</td></tr>";
            }
            out << "</tbody></table></div>";
        }
    }

    out << R"(<div class="footer"><strong>Limitations.</strong> This report reflects a single static pass over the selected file at the time shown. It cannot observe runtime behavior, downloaded content, configuration, or data processed after launch. A valid signature indicates provenance and integrity, not safety. Findings are heuristic observations and must be interpreted with the file's origin, publisher and intended purpose.<br><br>
Generated by )" << escape(kToolName) << " " << escape(kToolVersion)
        << " &middot; schema " << escape(kReportSchemaVersion)
        << R"( &middot; no file was executed or uploaded.</div>
</div></body></html>)" << "\n";
    return out.str();
}

} // namespace explainbin
