#include "explainbin/core/ImportAnalyzer.hpp"

#include "explainbin/core/Util.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>

namespace explainbin {
namespace {

struct CategoryInfo {
    std::string_view category;
    std::string_view insight;
};

const std::unordered_map<std::string, CategoryInfo>& apiCategories() {
    static const std::unordered_map<std::string, CategoryInfo> categories = [] {
        std::unordered_map<std::string, CategoryInfo> map;

        const auto add = [&map](CategoryInfo info,
                                std::initializer_list<std::string_view> names) {
            for (const auto name : names) {
                map.emplace(util::toLowerAscii(std::string(name)), info);
            }
        };

        add({"Process memory access",
             "Can read, write or change the protection of memory in another process. "
             "Debuggers, profiling tools and accessibility software use this legitimately; "
             "process injection also depends on it."},
            {"ReadProcessMemory", "WriteProcessMemory", "VirtualProtectEx",
             "VirtualAllocEx", "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
             "NtReadVirtualMemory", "NtProtectVirtualMemory", "Wow64WriteVirtualMemory"});

        add({"Remote execution",
             "Can start code in a different process. Legitimate uses include debuggers, "
             "automation and some security tools; it is also a common injection step."},
            {"CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx",
             "RtlCreateUserThread", "QueueUserAPC", "SetThreadContext",
             "Wow64SetThreadContext", "NtQueueApcThread"});

        add({"Keyboard and input state",
             "Reads keyboard or input state. Games, accessibility tools and hotkey managers "
             "use this; it is also associated with keystroke capture."},
            {"GetAsyncKeyState", "GetKeyState", "GetKeyboardState", "GetKeyboardLayout",
             "MapVirtualKeyA", "MapVirtualKeyW", "SendInput", "keybd_event"});

        add({"Window inspection",
             "Reads window handles, titles or the foreground window. UI automation, "
             "accessibility tools and window managers use this; spyware can also collect "
             "window titles."},
            {"GetForegroundWindow", "GetWindowTextA", "GetWindowTextW", "EnumWindows",
             "GetWindowThreadProcessId"});

        add({"Hook installation",
             "Installs a system or application hook. Hooks can implement accessibility, "
             "automation, overlays and security monitoring, or intercept input/output."},
            {"SetWindowsHookExA", "SetWindowsHookExW", "CallNextHookEx"});

        add({"Process execution",
             "Can start another program or command. Installers, launchers and update "
             "mechanisms need this; malware also uses it to run payloads."},
            {"CreateProcessA", "CreateProcessW", "CreateProcessAsUserA",
             "CreateProcessAsUserW", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA",
             "ShellExecuteExW", "WinExec", "system", "_wsystem"});

        add({"Service management",
             "Can create or control Windows services. Legitimate installers and management "
             "software use services; they are also a persistence mechanism."},
            {"CreateServiceA", "CreateServiceW", "OpenSCManagerA", "OpenSCManagerW",
             "StartServiceA", "StartServiceW", "ChangeServiceConfigA",
             "ChangeServiceConfigW", "ControlService"});

        add({"Registry modification",
             "Can read or write the Windows registry. Applications store configuration "
             "there; registry Run keys and service keys are also used for persistence."},
            {"RegCreateKeyExA", "RegCreateKeyExW", "RegSetValueExA", "RegSetValueExW",
             "RegOpenKeyExA", "RegOpenKeyExW", "RegDeleteValueA", "RegDeleteValueW",
             "RegDeleteKeyA", "RegDeleteKeyW"});

        add({"Networking",
             "Can communicate over the network. Browsers, updaters and business software "
             "need this; remote access and downloaders also use it."},
            {"WSAStartup", "socket", "connect", "send", "recv", "gethostbyname",
             "getaddrinfo", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
             "WinHttpReceiveResponse", "InternetOpenA", "InternetOpenW",
             "InternetOpenUrlA", "InternetOpenUrlW", "InternetReadFile",
             "HttpSendRequestA", "HttpSendRequestW", "URLDownloadToFileA",
             "URLDownloadToFileW", "WinHttpReadData"});

        add({"Dynamic API resolution",
             "Loads libraries and resolves functions at runtime. Plug-ins, language "
             "runtimes and installers do this legitimately; it can also hide which APIs "
             "a program ultimately calls."},
            {"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
             "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress"});

        add({"Anti-debugging",
             "Can detect or interfere with debuggers. Some protectors and anti-cheat "
             "components use it defensively; malware uses it to resist analysis."},
            {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
             "NtSetInformationThread"});

        add({"Debug output",
             "Writes diagnostic messages to an attached debugger. This is routine logging, "
             "not anti-debugging behavior."},
            {"OutputDebugStringA", "OutputDebugStringW"});

        add({"Credential access",
             "Can read credentials or decrypt protected data. Password managers, browsers "
             "and backup tools use this; credential stealers target the same interfaces."},
            {"CredReadA", "CredReadW", "CredEnumerateA", "CredEnumerateW",
             "CryptUnprotectData", "LsaOpenPolicy", "LsaRetrievePrivateData",
             "LogonUserA", "LogonUserW"});

        add({"Cryptography",
             "Provides cryptographic operations. Legitimate software uses encryption for "
             "privacy and integrity; ransomware also encrypts files."},
            {"CryptAcquireContextA", "CryptAcquireContextW", "CryptGenKey", "CryptEncrypt",
             "CryptDecrypt", "CryptImportKey", "BCryptOpenAlgorithmProvider",
             "BCryptGenerateSymmetricKey", "BCryptEncrypt", "BCryptDecrypt"});

        add({"File enumeration",
             "Enumerates files or directories. Backup, indexing and cleanup tools need "
             "this; it is also used to locate documents before encryption or exfiltration."},
            {"FindFirstFileA", "FindFirstFileW", "FindNextFileA", "FindNextFileW",
             "NtQueryDirectoryFile"});

        add({"Process enumeration",
             "Enumerates processes or modules. Task managers, monitoring software and "
             "debuggers use this; security tools and malware also inspect running processes."},
            {"CreateToolhelp32Snapshot", "Process32First", "Process32FirstW",
             "Process32Next", "Process32NextW", "Module32First", "Module32FirstW",
             "EnumProcesses", "OpenProcess"});

        add({"Token privileges",
             "Can inspect or adjust process token privileges. Administration and backup "
             "software use this; malware may attempt privilege escalation."},
            {"OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilegeValueA",
             "LookupPrivilegeValueW", "DuplicateTokenEx", "ImpersonateLoggedOnUser"});

        add({"GDI drawing",
             "Creates or uses device contexts and bitmaps for drawing. The same APIs are used "
             "for ordinary painting, printing and double-buffering; screen capture needs "
             "additional runtime setup that the import table does not show."},
            {"BitBlt", "StretchBlt", "GetDC", "GetWindowDC", "CreateCompatibleDC",
             "CreateCompatibleBitmap"});

        add({".NET runtime",
             "Loads the .NET runtime. Managed applications normally import this entry "
             "point; it is not suspicious by itself."},
            {"_CorExeMain", "_CorDllMain", "CorBindToRuntimeEx"});

        add({"Resource access",
             "Reads resources embedded in an executable. This is routine for applications "
             "that load icons, dialogs, manifests or embedded payloads."},
            {"FindResourceA", "FindResourceW", "LoadResource", "LockResource",
             "SizeofResource"});

        return map;
    }();
    return categories;
}

std::string_view libraryCategory(const std::string& libraryName) {
    const auto lower = util::toLowerAscii(libraryName);
    if (lower.find("ws2_32") != std::string::npos ||
        lower.find("winhttp") != std::string::npos ||
        lower.find("wininet") != std::string::npos ||
        lower.find("urlmon") != std::string::npos) {
        return "Networking";
    }
    if (lower.find("advapi32") != std::string::npos) {
        return "System administration";
    }
    if (lower.find("crypt32") != std::string::npos ||
        lower.find("bcrypt") != std::string::npos ||
        lower.find("ncrypt") != std::string::npos) {
        return "Cryptography";
    }
    if (lower.find("ntdll") != std::string::npos) {
        return "Native Windows API";
    }
    if (lower.find("user32") != std::string::npos) {
        return "Windows user interface";
    }
    if (lower.find("kernel32") != std::string::npos ||
        lower.find("kernelbase") != std::string::npos) {
        return "Windows core";
    }
    return "Windows API";
}

std::string referenceFor(const ImportLibrary& library, const ImportFunction& function) {
    return library.name + "!" + function.name;
}

class EvidenceCollector {
public:
    explicit EvidenceCollector(const PeInfo& pe) {
        for (const auto& library : pe.imports) {
            for (const auto& function : library.functions) {
                if (function.byOrdinal) {
                    continue;
                }
                references_.emplace(util::toLowerAscii(function.name),
                                    referenceFor(library, function));
            }
        }
        for (const auto& exportInfo : pe.exports) {
            if (!exportInfo.name.empty()) {
                exports_.insert(util::toLowerAscii(exportInfo.name));
            }
        }
    }

    [[nodiscard]] bool has(std::string_view api) const {
        return references_.find(util::toLowerAscii(std::string(api))) != references_.end();
    }

    [[nodiscard]] bool hasAny(std::initializer_list<std::string_view> apis) const {
        return std::any_of(apis.begin(), apis.end(),
                           [this](std::string_view api) { return has(api); });
    }

    [[nodiscard]] bool exports(std::string_view name) const {
        return exports_.find(util::toLowerAscii(std::string(name))) != exports_.end();
    }

    [[nodiscard]] bool exportsAny(std::initializer_list<std::string_view> names) const {
        return std::any_of(names.begin(), names.end(),
                           [this](std::string_view name) { return exports(name); });
    }

    [[nodiscard]] std::vector<std::string> evidence(
        std::initializer_list<std::string_view> apis) const {
        std::vector<std::string> result;
        for (const auto api : apis) {
            const auto key = util::toLowerAscii(std::string(api));
            const auto iterator = references_.find(key);
            if (iterator != references_.end()) {
                result.push_back(iterator->second);
            }
        }
        return result;
    }

private:
    std::map<std::string, std::string> references_;
    std::set<std::string> exports_;
};

Finding makeFinding(std::string id, std::string title, Severity severity,
                    Confidence confidence, std::string description,
                    std::string whyItMatters, std::vector<std::string> evidence,
                    std::vector<std::string> legitimateExplanations,
                    std::vector<std::string> nextSteps) {
    Finding finding;
    finding.id = std::move(id);
    finding.category = "Imports";
    finding.title = std::move(title);
    finding.severity = severity;
    finding.confidence = confidence;
    finding.description = std::move(description);
    finding.whyItMatters = std::move(whyItMatters);
    finding.evidence = std::move(evidence);
    finding.legitimateExplanations = std::move(legitimateExplanations);
    finding.nextSteps = std::move(nextSteps);
    return finding;
}

} // namespace

void ImportAnalyzer::annotate(PeInfo& pe) const {
    const auto& categories = apiCategories();
    for (auto& library : pe.imports) {
        for (auto& function : library.functions) {
            if (function.byOrdinal) {
                function.category = "Ordinal import";
                function.insight =
                    "This import is referenced by ordinal instead of by name. The meaning "
                    "depends on the exact library version.";
                continue;
            }
            const auto iterator =
                categories.find(util::toLowerAscii(function.name));
            if (iterator != categories.end()) {
                function.category = std::string(iterator->second.category);
                function.insight = std::string(iterator->second.insight);
            } else {
                function.category = std::string(libraryCategory(library.name));
            }
        }
    }
}

std::vector<Finding> ImportAnalyzer::analyze(const PeInfo& pe) const {
    std::vector<Finding> findings;
    const EvidenceCollector evidence(pe);

    if (pe.imports.empty()) {
        // A DLL that exports an API surface (for example ntdll.dll) may legitimately have no
        // imports because it talks to the kernel directly or is statically linked. Managed
        // .NET assemblies can also rely on the CLR instead of an import table.
        const auto emptyImportSeverity = (pe.hasClrDirectory || !pe.exports.empty())
                                             ? Severity::Informational
                                             : Severity::Low;
        findings.push_back(makeFinding(
            "EB-IMP-011", "No imported functions were observed", emptyImportSeverity,
            Confidence::Medium,
            "The parser found no import library entries. Statically linked programs, "
            "resource-only DLLs, low-level system modules and packed executables can "
            "legitimately look like this.",
            "Most ordinary Windows executables import functions from system DLLs. A missing "
            "import table can indicate static linking or a packer, but it is not proof of "
            "malicious behavior.",
            {"Import directory is absent, empty, or could not be parsed."},
            {"The program may use a static C/C++ runtime.",
             "The file may be a resource-only DLL or a driver-like native image.",
             "Low-level system modules such as ntdll resolve services without an import table.",
             "A packer may resolve APIs dynamically after unpacking."},
            {"Check whether the file has an executable entry point and section data.",
             "Run it in an isolated sandbox and observe loaded modules.",
             "Review the digital signature and file origin."}));
        return findings;
    }

    // Require explicit cross-process APIs. The generic native NT functions
    // (NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx) are imported by
    // ordinary system DLLs for their own local memory management and were causing
    // common Microsoft binaries to be reported as injection tools.
    const bool explicitRemoteAllocation = evidence.has("VirtualAllocEx");
    const bool allocatesRemote =
        explicitRemoteAllocation || evidence.has("NtAllocateVirtualMemory");
    const bool writesRemote = evidence.hasAny(
        {"WriteProcessMemory", "NtWriteVirtualMemory", "Wow64WriteVirtualMemory"});
    const bool explicitRemoteThread = evidence.hasAny(
        {"CreateRemoteThread", "CreateRemoteThreadEx", "RtlCreateUserThread"});
    const bool nativeRemoteThread =
        explicitRemoteAllocation && evidence.has("NtCreateThreadEx");
    const bool startsRemoteThread = explicitRemoteThread || nativeRemoteThread;
    // API provider modules such as kernel32.dll and kernelbase.dll both export and import
    // these functions (they forward to or wrap the real implementation). That is not
    // evidence that the module performs injection itself.
    const bool isInjectionApiProvider =
        evidence.exports("VirtualAllocEx") && evidence.exports("WriteProcessMemory") &&
        evidence.exportsAny({"CreateRemoteThread", "CreateRemoteThreadEx"});
    if (!isInjectionApiProvider && allocatesRemote && writesRemote && startsRemoteThread) {
        auto proof = evidence.evidence({"VirtualAllocEx", "NtAllocateVirtualMemory",
                                        "WriteProcessMemory", "NtWriteVirtualMemory",
                                        "Wow64WriteVirtualMemory", "CreateRemoteThread",
                                        "CreateRemoteThreadEx", "RtlCreateUserThread",
                                        "NtCreateThreadEx"});
        findings.push_back(makeFinding(
            "EB-IMP-001", "Imports include a classic process-injection capability sequence",
            Severity::Medium, Confidence::Medium,
            "The import table contains APIs for allocating memory in another process, "
            "writing data into that memory, and creating a remote thread. This is the "
            "canonical API sequence used for process injection, but imports show capability "
            "only; they do not show that the code uses it.",
            "Process injection lets code run inside another process, which can hide activity "
            "from simple process listings and evade some security controls. The imports show "
            "capability only; they do not show that the capability is used.",
            std::move(proof),
            {"Debuggers and profiling tools attach to and modify other processes.",
             "Accessibility, automation and game overlay software may inject helper code.",
             "Security agents and anti-cheat products often use injection defensively.",
             "Some installers inject code to display custom UI."},
            {"Inspect cross-references and call sites in a disassembler.",
             "Run the sample in an isolated sandbox with process-creation monitoring.",
             "Check whether the file is digitally signed and by whom.",
             "Compare the hash with known-good vendor builds."}));
    }

    const bool inputState = evidence.hasAny(
        {"GetAsyncKeyState", "GetKeyState", "GetKeyboardState"});
    const bool installsHook = evidence.hasAny({"SetWindowsHookExA", "SetWindowsHookExW"});
    if (inputState && installsHook) {
        findings.push_back(makeFinding(
            "EB-IMP-002", "Keyboard hook and key-state APIs are present",
            Severity::Low, Confidence::Low,
            "The file imports SetWindowsHookEx together with APIs that read key state. The hook "
            "type (for example WH_KEYBOARD or WH_KEYBOARD_LL) is a runtime argument and is not "
            "visible in the import table, so this combination cannot distinguish a hotkey "
            "manager from keystroke capture.",
            "Keystroke capture can expose passwords and other sensitive input. The same APIs are "
            "also used by hotkey managers, accessibility software, input methods, games and UI "
            "frameworks, so this is a weak capability observation rather than a verdict.",
            evidence.evidence({"SetWindowsHookExA", "SetWindowsHookExW",
                               "GetAsyncKeyState", "GetKeyState", "GetKeyboardState"}),
            {"Window procedures commonly install hooks to receive keyboard messages.",
             "Hotkey managers and macro software watch keyboard input.",
             "Accessibility tools, input methods and on-screen keyboards intercept input.",
             "Game overlays and remote-support tools can use the same APIs."},
            {"Inspect the hook procedure and which key events it records.",
             "Run in a sandbox and observe any file or network output while typing.",
             "Verify the publisher signature and distribution channel."}));
    }

    const bool network = evidence.hasAny(
        {"WSAStartup", "WinHttpOpen", "InternetOpenA", "InternetOpenW",
         "InternetOpenUrlA", "InternetOpenUrlW", "URLDownloadToFileA",
         "URLDownloadToFileW"});
    const bool execution = evidence.hasAny(
        {"CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW",
         "ShellExecuteExA", "ShellExecuteExW", "WinExec"});
    if (network && execution) {
        findings.push_back(makeFinding(
            "EB-IMP-003", "Imports support downloading and starting another program",
            Severity::Low, Confidence::Medium,
            "The file can access the network and start a separate process. This combination "
            "is common in updaters and installers, and is also used by downloaders.",
            "Download-and-execute behavior can retrieve a payload that was not present when "
            "the file was analyzed. Static imports alone do not show what would be downloaded "
            "or whether the behavior occurs.",
            evidence.evidence({"WSAStartup", "WinHttpOpen", "InternetOpenA", "InternetOpenW",
                               "InternetOpenUrlA", "InternetOpenUrlW",
                               "URLDownloadToFileA", "URLDownloadToFileW", "CreateProcessA",
                               "CreateProcessW", "ShellExecuteA", "ShellExecuteW",
                               "ShellExecuteExA", "ShellExecuteExW", "WinExec"}),
            {"Updaters download and launch new versions.",
             "Installers fetch optional components.",
             "Enterprise launchers may retrieve signed internal tools."},
            {"Inspect string references near the network and process-creation calls.",
             "Observe network destinations in an isolated sandbox.",
             "Verify that downloaded content is signed and served over HTTPS."}));
    }

    const bool createsService = evidence.hasAny({"CreateServiceA", "CreateServiceW"});
    const bool startsService = evidence.hasAny({"StartServiceA", "StartServiceW",
                                                "ChangeServiceConfigA",
                                                "ChangeServiceConfigW"});
    if (createsService && startsService) {
        findings.push_back(makeFinding(
            "EB-IMP-004", "Imports can create and start a Windows service",
            Severity::Low, Confidence::Medium,
            "The file imports service creation and service control APIs. Windows services can "
            "start automatically and run without an interactive logon.",
            "Service creation is a well-known persistence technique. Legitimate installers, "
            "agents and management tools also create services.",
            evidence.evidence({"CreateServiceA", "CreateServiceW", "StartServiceA",
                               "StartServiceW", "ChangeServiceConfigA",
                               "ChangeServiceConfigW"}),
            {"Application installers register background services.",
             "Backup, monitoring and endpoint-management agents run as services.",
             "Some hardware drivers ship with a user-mode service component."},
            {"Inspect service names, binary paths and start types in strings or disassembly.",
             "Monitor service creation in a sandbox.",
             "Verify the signature and the expected installation workflow."}));
    }

    const bool modifiesRegistry = evidence.hasAny(
        {"RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW"});
    if (modifiesRegistry) {
        findings.push_back(makeFinding(
            "EB-IMP-005", "The file can modify the Windows registry",
            Severity::Informational, Confidence::High,
            "The import table contains APIs that create registry keys or write registry "
            "values. Registry use is extremely common in Windows software.",
            "Registry Run keys, service keys and shell extensions can provide persistence, "
            "but the same APIs are used for ordinary configuration storage.",
            evidence.evidence({"RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
                               "RegCreateKeyExW"}),
            {"Almost every installed Windows application stores settings in the registry.",
             "Components register COM objects, file associations and shell extensions.",
             "Licensing and update mechanisms often use registry keys."},
            {"Identify registry paths referenced by the program.",
             "Check specifically for Run, RunOnce, Services and Winlogon keys.",
             "Compare observed writes with the application's documented behavior."}));
    }

    const bool antiDebug = evidence.hasAny(
        {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
         "NtSetInformationThread"});
    if (antiDebug) {
        findings.push_back(makeFinding(
            "EB-IMP-006", "APIs associated with debugger detection are present",
            Severity::Informational, Confidence::Low,
            "The import table contains APIs commonly used to detect a debugger or change "
            "debugging behavior.",
            "Anti-debugging can protect intellectual property or game integrity, but it can "
            "also make legitimate security analysis harder. Its presence is not malicious by "
            "itself.",
            evidence.evidence({"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                               "NtQueryInformationProcess", "NtSetInformationThread"}),
            {"Commercial protectors and anti-cheat systems use anti-debugging.",
             "Some applications change behavior when a debugger is attached.",
             "Developer builds may include diagnostic guards."},
            {"Note it as an analysis obstacle rather than a verdict.",
             "Use a debugger with anti-anti-debug support only in an isolated environment.",
             "Focus on observable behavior instead of evasion checks."}));
    }

    const bool credentialAccess = evidence.hasAny(
        {"CredReadA", "CredReadW", "CredEnumerateA", "CredEnumerateW",
         "CryptUnprotectData", "LsaRetrievePrivateData", "LsaOpenPolicy"});
    if (credentialAccess) {
        findings.push_back(makeFinding(
            "EB-IMP-007", "The file can access stored credentials or protected data",
            Severity::Low, Confidence::Low,
            "The file imports APIs that read Windows credential stores or decrypt data "
            "protected for the current user.",
            "These APIs are used by password managers, browsers, backup tools and legitimate "
            "system utilities. They are also targeted by credential-stealing malware.",
            evidence.evidence({"CredReadA", "CredReadW", "CredEnumerateA", "CredEnumerateW",
                               "CryptUnprotectData", "LsaRetrievePrivateData",
                               "LsaOpenPolicy"}),
            {"Password managers and browsers retrieve their own stored secrets.",
             "Backup and migration tools need to preserve protected configuration.",
             "Single sign-on and enterprise agents use Windows credential facilities."},
            {"Check which credential targets or data blobs are referenced.",
             "Observe whether secrets are sent over the network.",
             "Verify the publisher and whether credential access is documented."}));
    }

    const bool encryption = evidence.hasAny(
        {"CryptEncrypt", "BCryptEncrypt", "CryptGenKey",
         "BCryptGenerateSymmetricKey"});
    const bool fileEnumeration = evidence.hasAny(
        {"FindFirstFileA", "FindFirstFileW", "FindNextFileA", "FindNextFileW",
         "NtQueryDirectoryFile"});
    if (encryption && fileEnumeration) {
        findings.push_back(makeFinding(
            "EB-IMP-008", "Encryption and file enumeration capabilities are both present",
            Severity::Low, Confidence::Low,
            "The file can enumerate files and perform encryption. This is a capability "
            "pattern seen in ransomware, but also in backup, archiving and secure-storage "
            "software.",
            "If combined at runtime, file enumeration and encryption can transform user "
            "documents. Static imports do not show which files are processed or whether a "
            "recovery mechanism exists.",
            evidence.evidence({"CryptEncrypt", "BCryptEncrypt", "CryptGenKey",
                               "BCryptGenerateSymmetricKey", "FindFirstFileA",
                               "FindFirstFileW", "FindNextFileA", "FindNextFileW",
                               "NtQueryDirectoryFile"}),
            {"Backup and archive tools compress and encrypt collections of files.",
             "Document-management and secure-storage software encrypt user data.",
             "Sync clients encrypt cached content."},
            {"Inspect file paths, extensions and key-management behavior.",
             "Run in a sandbox with a disposable directory and monitor file writes.",
             "Check for a documented backup or recovery feature."}));
    }

    const bool loadsLibraries = evidence.hasAny(
        {"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "LdrLoadDll"});
    const bool resolvesFunctions = evidence.hasAny(
        {"GetProcAddress", "LdrGetProcedureAddress"});
    if (loadsLibraries && resolvesFunctions) {
        findings.push_back(makeFinding(
            "EB-IMP-009", "APIs are resolved dynamically at runtime", Severity::Informational,
            Confidence::High,
            "The file imports LoadLibrary and GetProcAddress-style APIs, so it can load "
            "libraries and resolve functions that are not visible in the static import table.",
            "Dynamic resolution is normal for plug-ins and portable software, but it means "
            "this static report may not list every API the program eventually calls.",
            evidence.evidence({"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA",
                               "LoadLibraryExW", "LdrLoadDll", "GetProcAddress",
                               "LdrGetProcedureAddress"}),
            {"Plug-in architectures load modules on demand.",
             "Applications support multiple Windows versions by resolving optional APIs.",
             "Language runtimes and installers commonly use dynamic loading."},
            {"Combine this report with runtime API monitoring if behavior matters.",
             "Inspect strings for library and function names.",
             "Do not treat missing imports as evidence of safety."}));
    }

    if (network && !execution) {
        findings.push_back(makeFinding(
            "EB-IMP-010", "The file contains networking APIs", Severity::Informational,
            Confidence::High,
            "The import table shows the program can use Windows networking interfaces.",
            "Network access is expected for browsers, updaters, collaboration tools and many "
            "business applications. The finding only establishes capability.",
            evidence.evidence({"WSAStartup", "WinHttpOpen", "WinHttpConnect", "InternetOpenA",
                               "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
                               "URLDownloadToFileA", "URLDownloadToFileW"}),
            {"The application may check for updates or synchronize data.",
             "It may contact a license or telemetry service.",
             "It may be a network client by design."},
            {"Review configured endpoints if available.",
             "Observe outbound connections in an isolated environment.",
             "Confirm that network use matches the application's purpose."}));
    }

    const bool gdiBlit = evidence.hasAny({"BitBlt", "StretchBlt"}) &&
                         evidence.hasAny({"GetDC", "GetWindowDC", "CreateCompatibleDC"}) &&
                         evidence.has("CreateCompatibleBitmap");
    if (gdiBlit) {
        findings.push_back(makeFinding(
            "EB-IMP-012", "GDI pixel-copying APIs are present", Severity::Informational,
            Confidence::Low,
            "The import table contains GDI functions that copy pixels between device contexts. "
            "Normal drawing, double-buffering and rendering code uses the same functions, so "
            "this does not show that screen contents are captured.",
            "Screen capture would additionally need a desktop or window device context and a "
            "way to store or transmit the image. Those runtime details are not visible in the "
            "static import table.",
            evidence.evidence({"BitBlt", "StretchBlt", "GetDC", "GetWindowDC",
                               "CreateCompatibleDC", "CreateCompatibleBitmap"}),
            {"Ordinary applications blit their own window contents for painting.",
             "Games and rendering applications copy frames between buffers.",
             "Accessibility magnifiers and screenshot tools use the same GDI APIs."},
            {"Observe runtime GDI calls if screen capture is a specific concern.",
             "Check whether captured images are written to disk or sent over the network.",
             "Do not treat generic GDI imports as evidence of surveillance."}));
    }

    return findings;
}

} // namespace explainbin
