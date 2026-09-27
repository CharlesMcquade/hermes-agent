// Disposable attribution experiment. Not a production service supervisor.
import AppKit
import AVFoundation
import ApplicationServices

struct RuntimeSettings: Decodable {
    let pythonHome: String
    let bridge: String
}
struct Settings: Decodable {
    let root: String
    let pythonHome: String
    let bridge: String
    let runtimes: [String: RuntimeSettings]?
}
func emit(_ event: String, _ values: [String: Any] = [:]) {
    var record = values
    record["event"] = event
    let data = try! JSONSerialization.data(withJSONObject: record, options: [.sortedKeys])
    FileHandle.standardOutput.write(data + Data([10]))
}
let args = Array(CommandLine.arguments.dropFirst())
let modes = ["check", "request-finder", "request-camera", "sleep", "fail",
             "permissions-check", "permissions-request", "permissions-sleep", "network-check", "network-request"]
guard args.count == 2, ["a", "b"].contains(args[0]), modes.contains(args[1]),
      let resources = Bundle.main.resourceURL else { exit(64) }
let config = try JSONDecoder().decode(Settings.self, from: Data(contentsOf: resources.appendingPathComponent("settings.json")))
let root = URL(fileURLWithPath: config.root).standardizedFileURL
let python = root.appendingPathComponent("runtimes/\(args[0])/python")
let mode = args[1]
let selectedRuntime = config.runtimes?[args[0]] ?? RuntimeSettings(pythonHome: config.pythonHome, bridge: config.bridge)
#if REVISION_FOUR
let buildGeneration = "four"
#elseif REVISION_THREE
let buildGeneration = "three"
#elseif REVISION_TWO
let buildGeneration = "two"
#else
let buildGeneration = "one"
#endif
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let child = Process()
var signals: [DispatchSourceSignal] = []
var terminating = false
var childGroup: pid_t = 0

func killOwnedChildGroup() {
    // Foundation Process creates a separate process group, checked after spawn.
    // Never signal the host/launcher's group or an unverified group.
    if childGroup > 0 { kill(-childGroup, SIGKILL) }
}

func startChild() {
    child.executableURL = python
    let script = mode.hasPrefix("permissions-") ? "permissions_probe.py" : (mode.hasPrefix("network-") ? "network_probe.py" : "probe.py")
    child.arguments = ["-S", "-s", "-P", "-u", resources.appendingPathComponent(script).path, mode, selectedRuntime.bridge]
    child.currentDirectoryURL = root
    child.environment = ["HOME": NSHomeDirectory(), "PATH": "/usr/bin:/bin", "PYTHONHOME": selectedRuntime.pythonHome,
                         "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": root.appendingPathComponent("tmp").path]
    child.standardInput = FileHandle.nullDevice
    child.standardOutput = FileHandle.standardOutput
    child.standardError = FileHandle.standardError
    child.terminationHandler = { task in
        DispatchQueue.main.async {
            killOwnedChildGroup()
            emit("child-exit", ["pid": task.processIdentifier, "status": task.terminationStatus,
                                "reason": task.terminationReason.rawValue])
            exit(terminating ? 143 : task.terminationStatus)
        }
    }
    do {
        try child.run()
        if child.isRunning {
            guard getpgid(child.processIdentifier) == child.processIdentifier else {
                child.terminate()
                emit("spawn-error", ["type": "UnexpectedChildProcessGroup"]); exit(70)
            }
            childGroup = child.processIdentifier
        }
        emit("child-start", ["host_pid": getpid(), "child_pid": child.processIdentifier, "slot": args[0]])
    } catch {
        emit("spawn-error", ["type": String(describing: type(of: error))]); exit(70)
    }
}
for number in [SIGTERM, SIGINT] {
    signal(number, SIG_IGN)
    let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
    source.setEventHandler {
        terminating = true
        emit("host-signal", ["signal": number])
        if child.isRunning {
            child.terminate()
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                killOwnedChildGroup()
            }
        } else { exit(143) }
    }
    source.resume(); signals.append(source)
}
emit("host-start", ["pid": getpid(), "ppid": getppid(), "bundle": Bundle.main.bundleIdentifier ?? "missing",
                    "executable": Bundle.main.executablePath ?? "missing", "mode": mode, "build_generation": buildGeneration,
                    "camera": AVCaptureDevice.authorizationStatus(for: .video).rawValue,
                    "accessibility": AXIsProcessTrusted(), "screen": CGPreflightScreenCaptureAccess()])
DispatchQueue.main.async {
    if mode == "request-camera" && AVCaptureDevice.authorizationStatus(for: .video) == .notDetermined {
        AVCaptureDevice.requestAccess(for: .video) { granted in
            emit("native-camera-consent", ["granted": granted])
            DispatchQueue.main.async { startChild() }
        }
    } else { startChild() }
}
// Bounded experiment, even if consent is unanswered. No perpetual daemon.
let lifetime: Double = mode == "permissions-sleep" ? 5 : (mode == "permissions-request" ? 600 : 240)
DispatchQueue.main.asyncAfter(deadline: .now() + lifetime) {
    emit("deadline")
    killOwnedChildGroup()
    exit(124)
}
app.run()
