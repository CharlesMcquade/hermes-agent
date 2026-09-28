// Isolated controller integration host. Not installed in production.
// posix_spawn deliberately retains the launchd job's process group: Foundation
// Process creates a separate group which launchd can leave alive on host SIGKILL.
import Foundation
import CryptoKit
import Darwin

struct ServiceSettings: Decodable {
    let base: String
    let bootstrap_python: String
    let launcher: String
    let launcher_sha256: String
    let roles: [String]
    let bootstrap_environment: [String: String]?
}
func validateSettings(_ data: Data) throws {
    let required: Set<String> = ["base", "bootstrap_python", "launcher", "launcher_sha256", "roles"]
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(object.keys) == required || Set(object.keys) == required.union(["bootstrap_environment"])
    else { throw CocoaError(.fileReadCorruptFile) }
    if let raw = object["bootstrap_environment"] {
        let keys: Set<String> = ["HOME", "TMPDIR", "HERMES_HOME", "PATH",
                                 "PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE"]
        guard let env = raw as? [String: String], Set(env.keys) == keys,
              env.values.allSatisfy({ !$0.contains("\u{0}") }),
              ["HOME", "TMPDIR", "HERMES_HOME"].allSatisfy({ env[$0]!.hasPrefix("/") }),
              env["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin",
              env["PYTHONNOUSERSITE"] == "1", env["PYTHONDONTWRITEBYTECODE"] == "1"
        else { throw CocoaError(.fileReadCorruptFile) }
    }
}
func emit(_ event: String, _ values: [String: Any] = [:]) {
    var record = values
    record["event"] = event
    if let data = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]) {
        FileHandle.standardOutput.write(data + Data([10]))
    }
}
func ownedFile(_ path: String) throws -> Data {
    let url = URL(fileURLWithPath: path)
    let info = try FileManager.default.attributesOfItem(atPath: path)
    guard info[.ownerAccountID] as? UInt32 == getuid(),
          let mode = info[.posixPermissions] as? UInt16, mode & 0o022 == 0,
          info[.type] as? FileAttributeType == .typeRegular else { throw CocoaError(.fileReadNoPermission) }
    return try Data(contentsOf: url)
}
let args = Array(CommandLine.arguments.dropFirst())
// The guard owns no service or permissions. Its inherited pipe reaches EOF even
// if the host is SIGKILLed. Kill only this launchd-owned group, including ourselves.
if args.count == 3, args[0] == "--group-guard",
   let input = Int32(args[1]), let ready = Int32(args[2]),
   getppid() == getpgrp(), getpgrp() > 1, getpid() != getpgrp() {
    signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN)
    var byte: UInt8 = 1
    guard write(ready, &byte, 1) == 1 else { exit(70) }
    close(ready)
    while true {
        let count = read(input, &byte, 1)
        if count == 0 { kill(-getpgrp(), SIGKILL); exit(70) }
        if count < 0 && errno != EINTR { exit(70) }
    }
}
guard args.count == 1, ["agent", "webui"].contains(args[0]),
      getppid() == 1, getpgrp() == getpid(),
      let resources = Bundle.main.resourceURL else { exit(64) }
let config: ServiceSettings
do {
    let settingsData = try ownedFile(resources.appendingPathComponent("service-settings.json").path)
    try validateSettings(settingsData)
    config = try JSONDecoder().decode(ServiceSettings.self, from: settingsData)
    guard config.roles == ["agent", "webui"],
          config.launcher == config.base + "/production_launcher.py",
          config.base.hasPrefix("/"), config.bootstrap_python.hasPrefix("/") else { exit(78) }
    let data = try ownedFile(config.launcher)
    let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    guard hash == config.launcher_sha256 else { exit(78) }
} catch {
    emit("host-refused", ["error_type": String(describing: type(of: error))]); exit(78)
}
guard chdir(config.base) == 0 else { exit(78) }
let command = [config.bootstrap_python, "-I", "-B", config.launcher, args[0],
               "--manifest", config.base + "/production-release.json"]
let environment = config.bootstrap_environment.map { env in
    env.keys.sorted().map { $0 + "=" + env[$0]! }
} ?? ["HOME=" + config.base + "/home", "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
      "TMPDIR=" + config.base + "/tmp", "HERMES_HOME=" + config.base + "/state",
      "PYTHONNOUSERSITE=1", "PYTHONDONTWRITEBYTECODE=1"]
var argv = command.map { strdup($0) } + [nil]
var envp = environment.map { strdup($0) } + [nil]
// One close-on-exec writer stays in the host; neither runtime nor guard inherits
// it. Handshake before spawning Python so every service is covered from birth.
var lifetime = [Int32](repeating: 0, count: 2)
var readiness = [Int32](repeating: 0, count: 2)
guard pipe(&lifetime) == 0, pipe(&readiness) == 0 else { exit(70) }
guard fcntl(lifetime[1], F_SETFD, FD_CLOEXEC) == 0 else { exit(70) }
var guardActions: posix_spawn_file_actions_t?
posix_spawn_file_actions_init(&guardActions)
posix_spawn_file_actions_addclose(&guardActions, lifetime[1])
posix_spawn_file_actions_addclose(&guardActions, readiness[0])
let guardCommand: [String] = [CommandLine.arguments[0], "--group-guard",
                              String(lifetime[0]), String(readiness[1])]
var guardArgs: [UnsafeMutablePointer<CChar>?] = guardCommand.map { strdup($0) }
guardArgs.append(nil)
var guardPID: pid_t = 0
let guardCode = posix_spawn(&guardPID, CommandLine.arguments[0], &guardActions, nil, &guardArgs, &envp)
posix_spawn_file_actions_destroy(&guardActions)
for ptr in guardArgs { free(ptr) }
close(lifetime[0]); close(readiness[1])
guard guardCode == 0 else { exit(70) }
var pollFD = pollfd(fd: readiness[0], events: Int16(POLLIN), revents: 0)
var readyByte: UInt8 = 0
guard poll(&pollFD, 1, 2000) == 1, read(readiness[0], &readyByte, 1) == 1,
      readyByte == 1 else { kill(-getpid(), SIGKILL); exit(70) }
close(readiness[0])
var attr: posix_spawnattr_t?
posix_spawnattr_init(&attr)
var defaults = sigset_t()
sigemptyset(&defaults)
sigaddset(&defaults, SIGTERM); sigaddset(&defaults, SIGINT)
posix_spawnattr_setsigdefault(&attr, &defaults)
var mask = sigset_t(); sigemptyset(&mask)
posix_spawnattr_setsigmask(&attr, &mask)
posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK))
var child: pid_t = 0
let code = posix_spawn(&child, config.bootstrap_python, nil, &attr, &argv, &envp)
posix_spawnattr_destroy(&attr)
for ptr in argv + envp { free(ptr) }
guard code == 0 else { emit("spawn-error", ["errno": code]); exit(70) }
emit("service-host", ["pid": getpid(), "ppid": getppid(), "pgid": getpgrp(),
                      "child_pid": child, "guard_pid": guardPID, "role": args[0]])
var sources: [DispatchSourceSignal] = []
var terminating = false
for number in [SIGTERM, SIGINT] {
    signal(number, SIG_IGN)
    let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
    source.setEventHandler {
        if !terminating {
            terminating = true
            kill(child, SIGTERM)
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                // Our launchd-owned group only, including us. launchd restarts it.
                kill(-getpid(), SIGKILL)
            }
        }
    }
    source.resume(); sources.append(source)
}
let exited = DispatchSource.makeProcessSource(identifier: child, eventMask: .exit, queue: .main)
exited.setEventHandler {
    var status: Int32 = 0
    guard waitpid(child, &status, 0) == child else { exit(70) }
    let signalNumber = status & 0x7f
    let code = signalNumber == 0 ? (status >> 8) & 0xff : 128 + signalNumber
    emit("service-exit", ["child_pid": child, "status": code])
    exit(terminating ? 143 : code)
}
exited.resume()
let guardExited = DispatchSource.makeProcessSource(identifier: guardPID, eventMask: .exit, queue: .main)
guardExited.setEventHandler { kill(-getpid(), SIGKILL); exit(70) }
guardExited.resume()
dispatchMain()
