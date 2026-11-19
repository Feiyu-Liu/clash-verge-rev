use super::CmdResult;

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, specta::Type)]
#[serde(rename_all = "snake_case")]
pub enum NetworkGuardStatus {
    Unavailable,
    Off,
    Active,
    Blocking,
    Unverified,
}

#[tauri::command]
#[specta::specta]
pub async fn get_network_guard_status() -> CmdResult<NetworkGuardStatus> {
    #[cfg(target_os = "macos")]
    return tauri::async_runtime::spawn_blocking(macos::status)
        .await
        .map_err(super::CommandFailure::plain);

    #[cfg(not(target_os = "macos"))]
    Ok(NetworkGuardStatus::Unavailable)
}

#[tauri::command]
#[specta::specta]
pub async fn set_network_guard_enabled(enabled: bool) -> CmdResult {
    #[cfg(target_os = "macos")]
    return macos::set_enabled(enabled).await;

    #[cfg(not(target_os = "macos"))]
    {
        let _ = enabled;
        Err("Network protection is unavailable on this platform".into())
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::{
        fs,
        os::unix::fs::MetadataExt as _,
        path::Path,
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::NetworkGuardStatus;
    use crate::cmd::{CmdResult, CommandFailure, StringifyErr as _};

    const ROOT: &str = "/Library/Application Support/clash-guard";
    const PLIST: &str = "/Library/LaunchDaemons/local.clash-guard.plist";
    const JOB: &str = "system/local.clash-guard";
    const ADMIN_SCRIPT: &str = "on run argv\n  do shell script (item 1 of argv) with administrator privileges\nend run";
    static MUTATION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[derive(serde::Deserialize)]
    struct Heartbeat {
        time: f64,
        tun: Option<String>,
        pid: u32,
    }

    fn trusted(path: &Path, directory: bool) -> bool {
        fs::symlink_metadata(path)
            .is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0 && if directory { m.is_dir() } else { m.is_file() })
    }

    fn installed() -> bool {
        let root = Path::new(ROOT);
        trusted(Path::new("/Library/Application Support"), true)
            && trusted(Path::new("/Library/LaunchDaemons"), true)
            && trusted(root, true)
            && trusted(&root.join("guard-daemon.py"), false)
            && trusted(Path::new(PLIST), false)
    }

    pub(super) fn status() -> NetworkGuardStatus {
        use NetworkGuardStatus::{Active, Blocking, Off, Unavailable, Unverified};
        if !installed() {
            return Unavailable;
        }
        let root = Path::new(ROOT);
        let Ok(job) = Command::new("/bin/launchctl").args(["print", JOB]).output() else {
            return Unverified;
        };
        let pid = String::from_utf8_lossy(if job.status.success() { &job.stdout } else { &[] })
            .lines()
            .find_map(|line| line.trim().strip_prefix("pid = ")?.parse::<u32>().ok());
        if root.join("disabled").exists() {
            return if pid.is_none() && trusted(&root.join("disabled-confirmed"), false) {
                Off
            } else {
                Unverified
            };
        }
        let heartbeat = fs::read(root.join("status.json"))
            .ok()
            .and_then(|data| serde_json::from_slice::<Heartbeat>(&data).ok());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        match heartbeat {
            Some(h)
                if !root.join("disabled").exists() && Some(h.pid) == pid && (0.0..=8.0).contains(&(now - h.time)) =>
            {
                if h.tun.is_some() {
                    Active
                } else {
                    Blocking
                }
            }
            _ => Unverified,
        }
    }

    pub(super) async fn set_enabled(enabled: bool) -> CmdResult {
        let _guard = MUTATION.lock().await;
        tauri::async_runtime::spawn_blocking(move || change(enabled))
            .await
            .stringify_err()?
    }

    fn change(enabled: bool) -> CmdResult {
        if !installed() {
            return Err("The macOS network protection service is not installed or its files are not trusted".into());
        }
        let before = status();
        if enabled && before == NetworkGuardStatus::Active {
            return Ok(());
        }
        if enabled && before != NetworkGuardStatus::Off {
            return Err("Turn off network protection before restarting it".into());
        }
        let shell = if enabled {
            let uid = Command::new("/usr/bin/id").arg("-u").output().stringify_err()?;
            let uid: u32 = String::from_utf8_lossy(&uid.stdout).trim().parse().stringify_err()?;
            enable_command(uid)
        } else {
            DISABLE_COMMAND.to_owned()
        };
        let output = Command::new("/usr/bin/osascript")
            .args(["-e", ADMIN_SCRIPT, "--", &shell])
            .output()
            .stringify_err()?;
        if !output.status.success() {
            return Err(CommandFailure::plain(String::from_utf8_lossy(&output.stderr).trim()));
        }
        Ok(())
    }

    fn enable_command(uid: u32) -> String {
        format!(
            r#"set -eu
root='{ROOT}'
enabled=$(/usr/bin/curl -q --noproxy '*' --max-time 2 -fsS --unix-socket '/var/run/clash-verge-service/users/{uid}/verge-mihomo.sock' http://localhost/configs)
flag=$(/usr/bin/printf '%s' "$enabled" | /usr/bin/plutil -extract tun.enable raw -o - -)
device=$(/usr/bin/printf '%s' "$enabled" | /usr/bin/plutil -extract tun.device raw -o - -)
if [ "$flag" != true ] || ! /usr/bin/printf '%s\n' "$device" | /usr/bin/grep -Eq '^utun[0-9]+$' || ! /sbin/ifconfig "$device" >/dev/null; then
  /usr/bin/printf '%s\n' 'Turn on TUN mode before enabling network protection.' >&2
  exit 1
fi
if /bin/launchctl print '{JOB}' >/dev/null 2>&1; then
  /bin/launchctl bootout '{JOB}'
fi
/bin/rm -f "$root/status.json" "$root/disabled-confirmed" "$root/disabled"
if /bin/launchctl bootstrap system '{PLIST}'; then
  i=0
  while [ "$i" -lt 10 ]; do
    rules=$(/sbin/pfctl -a com.apple/clash-guard -sr 2>/dev/null || :)
    if [ "$(/usr/bin/plutil -extract tun raw -o - "$root/status.json" 2>/dev/null || :)" = "$device" ] &&
       /usr/bin/printf '%s\n' "$rules" | /usr/bin/grep -Fxq 'block drop out quick all' &&
       /usr/bin/printf '%s\n' "$rules" | /usr/bin/grep -Fxq "pass out quick on $device all no state" &&
       /sbin/pfctl -sr 2>/dev/null | /usr/bin/grep -Eq '^anchor "com[.]apple/(\*|clash-guard)"([[:space:]]|$)' &&
       /sbin/pfctl -s info 2>/dev/null | /usr/bin/grep -q '^Status: Enabled'; then
      exit 0
    fi
    /bin/sleep 1
    i=$((i+1))
  done
fi
{DISABLE_COMMAND}
/usr/bin/printf '%s\n' 'Protection could not be started and was turned off.' >&2
exit 1"#
        )
    }

    const DISABLE_COMMAND: &str = r#"set -eu
root='/Library/Application Support/clash-guard'
/bin/rm -f "$root/disabled-confirmed"
/usr/bin/touch "$root/disabled"
if /bin/launchctl print system/local.clash-guard >/dev/null 2>&1; then
  /bin/launchctl bootout system/local.clash-guard
fi
/sbin/pfctl -a com.apple/clash-guard -F rules
rules=$(/sbin/pfctl -a com.apple/clash-guard -sr)
if [ -n "$rules" ]; then
  /usr/bin/printf '%s\n' 'Protection rules are still loaded. Retry turning protection off.' >&2
  exit 1
fi
if [ -f "$root/pf-token" ]; then
  token=$(/bin/cat "$root/pf-token")
  if ! /sbin/pfctl -X "$token"; then
    refs=$(/sbin/pfctl -s References)
    if /usr/bin/printf '%s\n' "$refs" | /usr/bin/grep -Fwq -- "$token"; then
      exit 1
    fi
  fi
  /bin/rm -f "$root/pf-token"
fi
/bin/rm -f "$root/status.json"
/usr/bin/touch "$root/disabled-confirmed"
"#;
}
