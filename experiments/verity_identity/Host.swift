// Disposable attribution experiment. Not a production service supervisor.
import AppKit
import AVFoundation
import ApplicationServices

struct Settings: Decodable {
    let root: String
    let pythonHome: String
    let bridge: String
}
func emit(_ event: String, _ values: [String: Any] = [:]) {
    var record = values
    record["event"] = event
    let data = try! JSONSerialization.data(withJSONObject: record, options: [.sortedKeys])
    FileHandle.standardOutput.write(data + Data([10]))
}
let args = Array(CommandLine.arguments.dropFirst())
let modes = ["check", "request-finder", "request-camera", "sleep", "fail"]
guard args.count == 2, ["a", "b"].contains(args[0]), modes.contains(args[1]),
      let resources = Bundle.main.resourceURL else { exit(64) }
let config = try JSONDecoder().decode(Settings.self, from: Data(contentsOf: resources.appendingPathComponent("settings.json")))
let root = URL(fileURLWithPath: config.root).standardizedFileURL
let python = root.appendingPathComponent("runtimes/\(args[0])/python")
let mode = args[1]
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let child = Process()
var signals: [DispatchSourceSignal] = []
var terminating = false

func startChild() {
    child.executableURL = python
    child.arguments = ["-S", "-s", "-P", "-u", resources.appendingPathComponent("probe.py").path, mode, config.bridge]
    child.currentDirectoryURL = root
    child.environment = ["HOME": NSHomeDirectory(), "PATH": "/usr/bin:/bin", "PYTHONHOME": config.pythonHome,
                         "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": root.appendingPathComponent("tmp").path]
    child.standardInput = FileHandle.nullDevice
    child.standardOutput = FileHandle.standardOutput
    child.standardError = FileHandle.standardError
    child.terminationHandler = { task in
        emit("child-exit", ["pid": task.processIdentifier, "status": task.terminationStatus,
                            "reason": task.terminationReason.rawValue])
        exit(terminating ? 143 : task.terminationStatus)
    }
    do {
        try child.run()
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
                if child.isRunning { kill(child.processIdentifier, SIGKILL) }
            }
        } else { exit(143) }
    }
    source.resume(); signals.append(source)
}
emit("host-start", ["pid": getpid(), "ppid": getppid(), "bundle": Bundle.main.bundleIdentifier ?? "missing",
                    "executable": Bundle.main.executablePath ?? "missing", "mode": mode,
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
DispatchQueue.main.asyncAfter(deadline: .now() + 240) {
    emit("deadline")
    if child.isRunning { kill(child.processIdentifier, SIGKILL) }
    exit(124)
}
app.run()
