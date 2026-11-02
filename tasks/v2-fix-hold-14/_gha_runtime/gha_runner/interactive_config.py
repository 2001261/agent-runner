"""Interactive Runtime 配置解析与校验（v2.0 规格）。

遵循《2.0 迭代.md》第二十章配置设计。
支持从 YAML 文本、字典或默认值加载，并提供严格类型与默认回退。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore


@dataclass
class RunnerConfig:
    platform: str = "ubuntu-24.04"


@dataclass
class GraphicalConfig:
    enabled: bool = True
    display: str = ":99"
    resolution: List[int] = field(default_factory=lambda: [1280, 800])
    depth: int = 24
    window_manager: str = "openbox"


@dataclass
class BrowserConfig:
    enabled: bool = True
    engine: str = "chromium"
    automation: str = "playwright"
    accessibility: bool = True
    cdp_port: int = 9222


@dataclass
class DesktopConfig:
    enabled: bool = True
    automation: str = "agent-desktop"


@dataclass
class HandoffConfig:
    browser: bool = True
    desktop: bool = True
    timeout_seconds: int = 300
    max_controllers: int = 1


@dataclass
class TunnelConfig:
    provider: str = "quick"  # "named" | "quick"
    hostname: Optional[str] = None
    token_secret: Optional[str] = None
    token_file: Optional[str] = None
    email_auth: bool = False


@dataclass
class RendezvousConfig:
    provider: str = "cloudflare_worker"  # "https_callback" | "cloudflare_worker"
    endpoint: Optional[str] = None
    auth_token: Optional[str] = None


@dataclass
class GatewayConfig:
    bind: str = "127.0.0.1"
    port: int = 8765
    authentication: str = "required"


@dataclass
class AuthStatePersistenceConfig:
    enabled: bool = True
    include_indexeddb: bool = True
    checkpoint_after_handoff: bool = True
    checkpoint_on_finish: bool = True
    session_storage: str = "site_adapter"
    encrypt: bool = True


@dataclass
class BrowserProfilePersistenceConfig:
    enabled: bool = True
    archive_on_finish: bool = True
    restore_if_compatible: bool = True


@dataclass
class CredentialsPersistenceConfig:
    managed_vault: bool = True
    allow_user_supplied: bool = True
    native_password_database: str = "profile_backup_only"
    allow_plaintext_export: bool = False


@dataclass
class VideoRecordingConfig:
    enabled: bool = False
    segment_seconds: int = 60
    max_resolution: List[int] = field(default_factory=lambda: [1280, 800])
    max_fps: int = 10


@dataclass
class TransferConfig:
    chunk_size_mib: int = 4
    retries: int = 3
    verify_sha256: bool = True
    encrypt_sensitive: bool = True
    require_host_ack: bool = True
    concurrent_files: int = 2


@dataclass
class PersistenceConfig:
    enabled: bool = True
    target: str = "agent_host"
    transport: str = "private_https"
    auth_state: AuthStatePersistenceConfig = field(default_factory=AuthStatePersistenceConfig)
    browser_profile: BrowserProfilePersistenceConfig = field(default_factory=BrowserProfilePersistenceConfig)
    credentials: CredentialsPersistenceConfig = field(default_factory=CredentialsPersistenceConfig)
    browser_video: VideoRecordingConfig = field(default_factory=VideoRecordingConfig)
    desktop_video: VideoRecordingConfig = field(default_factory=VideoRecordingConfig)
    traces: bool = False
    files: bool = True
    transfer: TransferConfig = field(default_factory=TransferConfig)


@dataclass
class CleanupConfig:
    revoke_tokens: bool = True
    stop_tunnel: bool = True
    delete_runner_private_files: bool = True


@dataclass
class InteractiveConfig:
    enabled: bool = True
    runner: RunnerConfig = field(default_factory=RunnerConfig)
    graphical: GraphicalConfig = field(default_factory=GraphicalConfig)
    browser: BrowserConfig = field(default_factory=BrowserConfig)
    desktop: DesktopConfig = field(default_factory=DesktopConfig)
    handoff: HandoffConfig = field(default_factory=HandoffConfig)
    tunnel: TunnelConfig = field(default_factory=TunnelConfig)
    rendezvous: RendezvousConfig = field(default_factory=RendezvousConfig)
    gateway: GatewayConfig = field(default_factory=GatewayConfig)
    persistence: PersistenceConfig = field(default_factory=PersistenceConfig)
    cleanup: CleanupConfig = field(default_factory=CleanupConfig)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InteractiveConfig":
        raw = data.get("interactive", data)
        cfg = cls()
        if not isinstance(raw, dict):
            return cfg

        cfg.enabled = bool(raw.get("enabled", cfg.enabled))

        if "runner" in raw and isinstance(raw["runner"], dict):
            cfg.runner.platform = str(raw["runner"].get("platform", cfg.runner.platform))

        if "graphical" in raw and isinstance(raw["graphical"], dict):
            g = raw["graphical"]
            cfg.graphical.enabled = bool(g.get("enabled", cfg.graphical.enabled))
            cfg.graphical.display = str(g.get("display", cfg.graphical.display))
            if "resolution" in g and isinstance(g["resolution"], list):
                cfg.graphical.resolution = [int(x) for x in g["resolution"][:2]]
            cfg.graphical.depth = int(g.get("depth", cfg.graphical.depth))
            cfg.graphical.window_manager = str(g.get("window_manager", cfg.graphical.window_manager))

        if "browser" in raw and isinstance(raw["browser"], dict):
            b = raw["browser"]
            cfg.browser.enabled = bool(b.get("enabled", cfg.browser.enabled))
            cfg.browser.engine = str(b.get("engine", cfg.browser.engine))
            cfg.browser.automation = str(b.get("automation", cfg.browser.automation))
            cfg.browser.accessibility = bool(b.get("accessibility", cfg.browser.accessibility))
            cfg.browser.cdp_port = int(b.get("cdp_port", cfg.browser.cdp_port))

        if "desktop" in raw and isinstance(raw["desktop"], dict):
            d = raw["desktop"]
            cfg.desktop.enabled = bool(d.get("enabled", cfg.desktop.enabled))
            cfg.desktop.automation = str(d.get("automation", cfg.desktop.automation))

        if "handoff" in raw and isinstance(raw["handoff"], dict):
            h = raw["handoff"]
            cfg.handoff.browser = bool(h.get("browser", cfg.handoff.browser))
            cfg.handoff.desktop = bool(h.get("desktop", cfg.handoff.desktop))
            cfg.handoff.timeout_seconds = int(h.get("timeout_seconds", cfg.handoff.timeout_seconds))
            cfg.handoff.max_controllers = int(h.get("max_controllers", cfg.handoff.max_controllers))

        if "tunnel" in raw and isinstance(raw["tunnel"], dict):
            t = raw["tunnel"]
            cfg.tunnel.provider = str(t.get("provider", cfg.tunnel.provider)).lower()
            cfg.tunnel.hostname = t.get("hostname")
            cfg.tunnel.token_secret = t.get("token_secret")
            cfg.tunnel.token_file = t.get("token_file")
            cfg.tunnel.email_auth = bool(t.get("email_auth", cfg.tunnel.email_auth))

        if "rendezvous" in raw and isinstance(raw["rendezvous"], dict):
            r = raw["rendezvous"]
            cfg.rendezvous.provider = str(r.get("provider", cfg.rendezvous.provider))
            cfg.rendezvous.endpoint = r.get("endpoint")
            cfg.rendezvous.auth_token = r.get("auth_token")

        if "gateway" in raw and isinstance(raw["gateway"], dict):
            gw = raw["gateway"]
            cfg.gateway.bind = str(gw.get("bind", cfg.gateway.bind))
            cfg.gateway.port = int(gw.get("port", cfg.gateway.port))
            cfg.gateway.authentication = str(gw.get("authentication", cfg.gateway.authentication))

        if "persistence" in raw and isinstance(raw["persistence"], dict):
            p = raw["persistence"]
            cfg.persistence.enabled = bool(p.get("enabled", cfg.persistence.enabled))
            cfg.persistence.target = str(p.get("target", cfg.persistence.target))
            cfg.persistence.transport = str(p.get("transport", cfg.persistence.transport))
            cfg.persistence.traces = bool(p.get("traces", cfg.persistence.traces))
            cfg.persistence.files = bool(p.get("files", cfg.persistence.files))

            if "auth_state" in p and isinstance(p["auth_state"], dict):
                a = p["auth_state"]
                cfg.persistence.auth_state.enabled = bool(a.get("enabled", cfg.persistence.auth_state.enabled))
                cfg.persistence.auth_state.include_indexeddb = bool(a.get("include_indexeddb", cfg.persistence.auth_state.include_indexeddb))
                cfg.persistence.auth_state.checkpoint_after_handoff = bool(a.get("checkpoint_after_handoff", cfg.persistence.auth_state.checkpoint_after_handoff))
                cfg.persistence.auth_state.checkpoint_on_finish = bool(a.get("checkpoint_on_finish", cfg.persistence.auth_state.checkpoint_on_finish))
                cfg.persistence.auth_state.session_storage = str(a.get("session_storage", cfg.persistence.auth_state.session_storage))
                cfg.persistence.auth_state.encrypt = bool(a.get("encrypt", cfg.persistence.auth_state.encrypt))

            if "browser_profile" in p and isinstance(p["browser_profile"], dict):
                bp = p["browser_profile"]
                cfg.persistence.browser_profile.enabled = bool(bp.get("enabled", cfg.persistence.browser_profile.enabled))
                cfg.persistence.browser_profile.archive_on_finish = bool(bp.get("archive_on_finish", cfg.persistence.browser_profile.archive_on_finish))
                cfg.persistence.browser_profile.restore_if_compatible = bool(bp.get("restore_if_compatible", cfg.persistence.browser_profile.restore_if_compatible))

            if "credentials" in p and isinstance(p["credentials"], dict):
                c = p["credentials"]
                cfg.persistence.credentials.managed_vault = bool(c.get("managed_vault", cfg.persistence.credentials.managed_vault))
                cfg.persistence.credentials.allow_user_supplied = bool(c.get("allow_user_supplied", cfg.persistence.credentials.allow_user_supplied))
                cfg.persistence.credentials.native_password_database = str(c.get("native_password_database", cfg.persistence.credentials.native_password_database))
                cfg.persistence.credentials.allow_plaintext_export = bool(c.get("allow_plaintext_export", cfg.persistence.credentials.allow_plaintext_export))

            if "browser_video" in p and isinstance(p["browser_video"], dict):
                bv = p["browser_video"]
                cfg.persistence.browser_video.enabled = bool(bv.get("enabled", cfg.persistence.browser_video.enabled))
                cfg.persistence.browser_video.segment_seconds = int(bv.get("segment_seconds", cfg.persistence.browser_video.segment_seconds))

            if "desktop_video" in p and isinstance(p["desktop_video"], dict):
                dv = p["desktop_video"]
                cfg.persistence.desktop_video.enabled = bool(dv.get("enabled", cfg.persistence.desktop_video.enabled))
                cfg.persistence.desktop_video.segment_seconds = int(dv.get("segment_seconds", cfg.persistence.desktop_video.segment_seconds))
                if "max_resolution" in dv and isinstance(dv["max_resolution"], list):
                    cfg.persistence.desktop_video.max_resolution = [int(x) for x in dv["max_resolution"][:2]]
                cfg.persistence.desktop_video.max_fps = int(dv.get("max_fps", cfg.persistence.desktop_video.max_fps))

            if "transfer" in p and isinstance(p["transfer"], dict):
                tr = p["transfer"]
                cfg.persistence.transfer.chunk_size_mib = int(tr.get("chunk_size_mib", cfg.persistence.transfer.chunk_size_mib))
                cfg.persistence.transfer.retries = int(tr.get("retries", cfg.persistence.transfer.retries))
                cfg.persistence.transfer.verify_sha256 = bool(tr.get("verify_sha256", cfg.persistence.transfer.verify_sha256))
                cfg.persistence.transfer.encrypt_sensitive = bool(tr.get("encrypt_sensitive", cfg.persistence.transfer.encrypt_sensitive))
                cfg.persistence.transfer.require_host_ack = bool(tr.get("require_host_ack", cfg.persistence.transfer.require_host_ack))

        if "cleanup" in raw and isinstance(raw["cleanup"], dict):
            cl = raw["cleanup"]
            cfg.cleanup.revoke_tokens = bool(cl.get("revoke_tokens", cfg.cleanup.revoke_tokens))
            cfg.cleanup.stop_tunnel = bool(cl.get("stop_tunnel", cfg.cleanup.stop_tunnel))
            cfg.cleanup.delete_runner_private_files = bool(cl.get("delete_runner_private_files", cfg.cleanup.delete_runner_private_files))

        return cfg

    @classmethod
    def from_yaml_str(cls, content: str) -> "InteractiveConfig":
        if yaml is not None:
            parsed = yaml.safe_load(content) or {}
            return cls.from_dict(parsed)
        # Fallback simple parser for basic keys if PyYAML not present
        return cls()

    @classmethod
    def load(cls, path: str) -> "InteractiveConfig":
        if not os.path.isfile(path):
            return cls()
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        return cls.from_yaml_str(content)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "interactive": {
                "enabled": self.enabled,
                "runner": {"platform": self.runner.platform},
                "graphical": {
                    "enabled": self.graphical.enabled,
                    "display": self.graphical.display,
                    "resolution": self.graphical.resolution,
                    "depth": self.graphical.depth,
                    "window_manager": self.graphical.window_manager,
                },
                "browser": {
                    "enabled": self.browser.enabled,
                    "engine": self.browser.engine,
                    "automation": self.browser.automation,
                    "accessibility": self.browser.accessibility,
                    "cdp_port": self.browser.cdp_port,
                },
                "desktop": {
                    "enabled": self.desktop.enabled,
                    "automation": self.desktop.automation,
                },
                "handoff": {
                    "browser": self.handoff.browser,
                    "desktop": self.handoff.desktop,
                    "timeout_seconds": self.handoff.timeout_seconds,
                    "max_controllers": self.handoff.max_controllers,
                },
                "tunnel": {
                    "provider": self.tunnel.provider,
                    "hostname": self.tunnel.hostname,
                    "token_secret": self.tunnel.token_secret,
                    "token_file": self.tunnel.token_file,
                    "email_auth": self.tunnel.email_auth,
                },
                "rendezvous": {
                    "provider": self.rendezvous.provider,
                    "endpoint": self.rendezvous.endpoint,
                    "auth_token": self.rendezvous.auth_token,
                },
                "gateway": {
                    "bind": self.gateway.bind,
                    "port": self.gateway.port,
                    "authentication": self.gateway.authentication,
                },
                "persistence": {
                    "enabled": self.persistence.enabled,
                    "target": self.persistence.target,
                    "transport": self.persistence.transport,
                    "auth_state": {
                        "enabled": self.persistence.auth_state.enabled,
                        "include_indexeddb": self.persistence.auth_state.include_indexeddb,
                        "checkpoint_after_handoff": self.persistence.auth_state.checkpoint_after_handoff,
                        "checkpoint_on_finish": self.persistence.auth_state.checkpoint_on_finish,
                        "session_storage": self.persistence.auth_state.session_storage,
                        "encrypt": self.persistence.auth_state.encrypt,
                    },
                    "browser_profile": {
                        "enabled": self.persistence.browser_profile.enabled,
                        "archive_on_finish": self.persistence.browser_profile.archive_on_finish,
                        "restore_if_compatible": self.persistence.browser_profile.restore_if_compatible,
                    },
                    "credentials": {
                        "managed_vault": self.persistence.credentials.managed_vault,
                        "allow_user_supplied": self.persistence.credentials.allow_user_supplied,
                        "native_password_database": self.persistence.credentials.native_password_database,
                        "allow_plaintext_export": self.persistence.credentials.allow_plaintext_export,
                    },
                    "browser_video": {
                        "enabled": self.persistence.browser_video.enabled,
                        "segment_seconds": self.persistence.browser_video.segment_seconds,
                    },
                    "desktop_video": {
                        "enabled": self.persistence.desktop_video.enabled,
                        "segment_seconds": self.persistence.desktop_video.segment_seconds,
                        "max_resolution": self.persistence.desktop_video.max_resolution,
                        "max_fps": self.persistence.desktop_video.max_fps,
                    },
                    "traces": self.persistence.traces,
                    "files": self.persistence.files,
                    "transfer": {
                        "chunk_size_mib": self.persistence.transfer.chunk_size_mib,
                        "retries": self.persistence.transfer.retries,
                        "verify_sha256": self.persistence.transfer.verify_sha256,
                        "encrypt_sensitive": self.persistence.transfer.encrypt_sensitive,
                        "require_host_ack": self.persistence.transfer.require_host_ack,
                    },
                },
                "cleanup": {
                    "revoke_tokens": self.cleanup.revoke_tokens,
                    "stop_tunnel": self.cleanup.stop_tunnel,
                    "delete_runner_private_files": self.cleanup.delete_runner_private_files,
                },
            }
        }
