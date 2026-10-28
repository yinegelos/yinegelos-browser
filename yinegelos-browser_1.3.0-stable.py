#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YinegelOS Browser
=============
PyQt6 + Qt WebEngine (Chromium) tabanlı, özellik dolu masaüstü web tarayıcısı.

Kurulum :  pip install PyQt6 PyQt6-WebEngine cryptography keyring
Çalıştır:  python yinegelos_browser.py [--private] [adres | dosya ...]
"""
from __future__ import annotations

import base64
import html
import json
import os
import re
import shutil
import signal
import subprocess
import sqlite3
import sys
import tempfile
import time
import traceback
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import quote, quote_plus, urlsplit

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    sys.stderr.write("cryptography paketi bulunamadı. Kurmak için: pip install cryptography\n")
    sys.exit(1)

try:
    import keyring
    from keyring.errors import KeyringError
    _KEYRING_AVAILABLE = True
except ImportError:
    keyring = None
    KeyringError = Exception
    _KEYRING_AVAILABLE = False

try:
    from PyQt6.QtCore import (
        PYQT_VERSION_STR, QT_VERSION_STR, QBuffer, QByteArray, QCoreApplication,
        QEvent, QIODevice, QLocale, QObject, QPoint, QRect, QSize, QStandardPaths,
        QStringListModel, Qt, QTimer, QUrl, pyqtSignal,
    )
    from PyQt6.QtGui import (
        QAction, QColor, QDesktopServices, QFont, QIcon, QKeySequence, QPainter,
        QPalette, QPixmap, QShortcut,
    )
    from PyQt6.QtNetwork import QAuthenticator, QLocalServer, QLocalSocket
    from PyQt6.QtPrintSupport import QPrintDialog, QPrinter
    from PyQt6.QtSvg import QSvgRenderer
    from PyQt6.QtWebEngineCore import (
        QWebEngineDownloadRequest, QWebEnginePage, QWebEngineProfile,
        QWebEngineSettings, QWebEngineUrlRequestInfo, QWebEngineUrlRequestInterceptor,
        QWebEngineUrlRequestJob, QWebEngineUrlScheme, QWebEngineUrlSchemeHandler,
        QWebEngineClientHints,
    )
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    from PyQt6.QtWidgets import (
        QApplication, QCheckBox, QComboBox, QCompleter, QDialog, QDialogButtonBox,
        QFileDialog, QFormLayout, QFrame, QHBoxLayout, QInputDialog, QLabel,
        QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMenu, QMessageBox,
        QProgressBar, QPushButton, QScrollArea, QSizePolicy, QSplitter,
        QStackedWidget, QSystemTrayIcon, QTabBar, QTabWidget, QToolBar,
        QToolButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
        QAbstractItemView,
    )
except ImportError as _exc:
    sys.stderr.write("Gerekli paketler bulunamadı: %s\nKurmak için: pip install PyQt6 PyQt6-WebEngine cryptography keyring\n" % _exc)
    sys.exit(1)

try:
    from PyQt6 import sip
except Exception:
    sip = None

# --------------------------------------------------------------------------- #
#  Sabitler
# --------------------------------------------------------------------------- #
APP_NAME = "YinegelOS Browser"
APP_FULL = "YinegelOS Browser"
ORG_NAME = "YinegelOS"
VERSION = "1.3.0"
SCHEME = "yinegelos"
NEWTAB_URL = "yinegelos://newtab"

# === Google oturum açma için gerçek UA (uygulama token'ı içerir, sahte Chrome değil) ===
# Araştırma: Google, Chrome gibi görünen UA'ları reddediyor, ancak uygulama tanımlayıcı
# token içeren UA'ları kabul ediyor [citation:8][citation:13]
APP_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0.0.0 Safari/537.36 "
    "YinegelOS/1.3"
)

KEYRING_SERVICE = "yinegelos-browser-vault"
KEYRING_USERNAME = "vault-master-key"

SEARCH_ENGINES = {
    "DuckDuckGo": "https://duckduckgo.com/?q=%s",
    "Google": "https://www.google.com/search?q=%s",
    "Bing": "https://www.bing.com/search?q=%s",
    "Brave": "https://search.brave.com/search?q=%s",
    "Ecosia": "https://www.ecosia.org/search?q=%s",
    "Yandex": "https://yandex.com.tr/search/?text=%s",
}
CUSTOM_ENGINE = "Özel"

ZOOM_STEPS = [0.25, 0.33, 0.5, 0.67, 0.75, 0.8, 0.9, 1.0, 1.1, 1.25, 1.5,
              1.75, 2.0, 2.5, 3.0, 4.0, 5.0]

PERMISSION_TEXT = {
    "Geolocation": "konumunuzu görmek",
    "Notifications": "size bildirim göndermek",
    "MediaAudioCapture": "mikrofonunuzu kullanmak",
    "MediaVideoCapture": "kameranızı kullanmak",
    "MediaAudioVideoCapture": "kameranızı ve mikrofonunuzu kullanmak",
    "DesktopVideoCapture": "ekranınızı paylaşmak",
    "DesktopAudioVideoCapture": "ekranınızı ve sesi paylaşmak",
    "MouseLock": "fare imlecini kilitlemek",
    "ClipboardReadWrite": "panonuzu okumak",
    "LocalFontsAccess": "yerel yazı tiplerinize erişmek",
}

BLOCKLIST = frozenset("""
doubleclick.net googlesyndication.com googleadservices.com google-analytics.com
adservice.google.com pagead2.googlesyndication.com ads.google.com
adnxs.com adsrvr.org advertising.com amazon-adsystem.com moatads.com
rubiconproject.com pubmatic.com openx.net casalemedia.com contextweb.com lijit.com
sharethrough.com teads.tv zedo.com serving-sys.com 2mdn.net smartadserver.com
taboola.com outbrain.com criteo.com criteo.net scorecardresearch.com quantserve.com
bluekai.com krxd.net demdex.net everesttech.net mathtag.com bidswitch.net
adform.net yieldmo.com adsymptotic.com popads.net popcash.net propellerads.com
exoclick.com ads-twitter.com analytics.twitter.com pixel.facebook.com
bat.bing.com clarity.ms ads.yahoo.com an.yandex.ru hotjar.com mouseflow.com
""".split())

# --------------------------------------------------------------------------- #
#  Genel yardımcılar
# --------------------------------------------------------------------------- #
_LOG_PATH: Path | None = None


def log(msg: str) -> None:
    line = "[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        sys.stderr.write(line + "\n")
        if _LOG_PATH is not None:
            with open(_LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
    except Exception:
        pass


def excepthook(exc_type, exc, tb) -> None:
    log("Yakalanmamış hata:\n" + "".join(traceback.format_exception(exc_type, exc, tb)))


def atomic_write_json(path: Path, obj) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2), "utf-8")
        os.replace(tmp, path)
    except OSError as exc:
        log("Dosya yazılamadı %s: %s" % (path, exc))


def human_size(n: int) -> str:
    if n < 0:
        return "?"
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return "%d B" % size if unit == "B" else "%.1f %s" % (size, unit)
        size /= 1024
    return "%d B" % n


def fmt_time(ts: float) -> str:
    try:
        return time.strftime("%d.%m.%Y %H:%M", time.localtime(ts))
    except (OverflowError, OSError, ValueError):
        return ""


def elide(text: str, limit: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: max(1, limit - 1)] + "…"


_BAD_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def safe_filename(name: str, fallback: str = "indirme") -> str:
    name = _BAD_CHARS.sub("_", os.path.basename(name or "")).strip(" .")
    if not name:
        name = fallback
    if len(name) > 180:
        stem, ext = os.path.splitext(name)
        name = stem[: 180 - len(ext)] + ext
    return name


def unique_path(directory: Path, name: str, reserved: set) -> Path:
    candidate = directory / name
    stem, suffix = candidate.stem, candidate.suffix
    i = 1
    while candidate.exists() or str(candidate) in reserved:
        candidate = directory / ("%s (%d)%s" % (stem, i, suffix))
        i += 1
    return candidate


def is_web_url(url: str) -> bool:
    return url.lower().startswith(("http://", "https://"))


def is_blocked_host(host: str) -> bool:
    parts = host.lower().strip(".").split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in BLOCKLIST:
            return True
    return False


_HOST_RE = re.compile(r"^(?:[\w\-]+\.)+[^\W\d_]{2,}(?::\d{1,5})?(?:[/?#].*)?$", re.UNICODE)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?(?:[/?#].*)?$")
_LOCAL_RE = re.compile(r"^(?:localhost|[\w\-]+\.local)(?::\d{1,5})?(?:[/?#].*)?$", re.I)
_SCHEME_SLASH_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_WIN_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")


def user_input_to_url(text: str, template: str) -> QUrl:
    text = (text or "").strip()
    if not text:
        return QUrl()
    if (text.startswith("/") or _WIN_PATH_RE.match(text)) and os.path.exists(text):
        return QUrl.fromLocalFile(os.path.abspath(text))
    if not any(ch.isspace() for ch in text):
        if _LOCAL_RE.match(text) or _IPV4_RE.match(text):
            url = QUrl("http://" + text)
            if url.isValid():
                return url
        if _SCHEME_SLASH_RE.match(text):
            url = QUrl(text, QUrl.ParsingMode.TolerantMode)
            if url.isValid() and url.scheme() != "javascript":
                return url
        elif text.lower().startswith(("about:", "view-source:", "file:", "data:")):
            url = QUrl(text, QUrl.ParsingMode.TolerantMode)
            if url.isValid():
                return url
        elif _HOST_RE.match(text):
            url = QUrl("https://" + text, QUrl.ParsingMode.TolerantMode)
            if url.isValid():
                return url
    return QUrl(template.replace("%s", quote_plus(text)))


def normalize_cli_arg(arg: str) -> str:
    try:
        if os.path.exists(arg):
            return QUrl.fromLocalFile(os.path.abspath(arg)).toString()
    except (OSError, ValueError):
        pass
    return arg


def app_data_dir() -> Path:
    p = Path(QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation))
    p.mkdir(parents=True, exist_ok=True)
    return p


def app_cache_dir() -> Path:
    p = Path(QStandardPaths.writableLocation(QStandardPaths.StandardLocation.CacheLocation))
    p.mkdir(parents=True, exist_ok=True)
    return p


# --------------------------------------------------------------------------- #
#  Ayarlar
# --------------------------------------------------------------------------- #
class AppSettings:
    DEFAULTS = {
        "home_page": "https://duckduckgo.com/",
        "startup": "restore",
        "search_engine": "DuckDuckGo",
        "custom_search": "https://example.com/search?q=%s",
        "theme": "system",
        "show_bookmarks_bar": True,
        "adblock": True,
        "dnt": True,
        "javascript": True,
        "smooth_scroll": True,
        "force_dark_web": False,
        "pdf_viewer": True,
        "download_dir": "",
        "download_ask": False,
        "default_zoom": 100,
        "wipe_storage": False,
        "geometry": "",
        "site_zoom": {},
        "permissions": {},
        "password_manager_enabled": True,
        "password_autofill": True,
        # === YENİ: ana sayfa kısayolları ===
        "shortcuts": [
            {"url": "https://www.google.com/", "title": "Google"},
            {"url": "https://www.youtube.com/", "title": "YouTube"},
            {"url": "https://github.com/", "title": "GitHub"},
            {"url": "https://duckduckgo.com/", "title": "DuckDuckGo"},
            {"url": "https://www.wikipedia.org/", "title": "Wikipedia"},
            {"url": "https://web.telegram.org/", "title": "Telegram"},
        ],
        # === YENİ SONU ===
    }

    def __init__(self, path: Path):
        self.path = path
        self.data = json.loads(json.dumps(self.DEFAULTS))
        try:
            if path.exists():
                raw = json.loads(path.read_text("utf-8"))
                if isinstance(raw, dict):
                    for key, value in raw.items():
                        if key in self.DEFAULTS and type(value) is type(self.DEFAULTS[key]):
                            self.data[key] = value
        except (OSError, ValueError) as exc:
            log("Ayar dosyası okunamadı (yedeklendi): %s" % exc)
            try:
                path.replace(path.with_suffix(".bak"))
            except OSError:
                pass

    def get(self, key: str):
        return self.data.get(key, self.DEFAULTS.get(key))

    def set(self, key: str, value, save: bool = True) -> None:
        self.data[key] = value
        if save:
            self.save()

    def save(self) -> None:
        atomic_write_json(self.path, self.data)


# --------------------------------------------------------------------------- #
#  Veritabanı
# --------------------------------------------------------------------------- #
def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class _BookmarkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.items: list[tuple[str, str]] = []
        self._href: str | None = None
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            self._href = dict(attrs).get("href")
            self._buf = []

    def handle_data(self, data):
        if self._href is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            if is_web_url(self._href):
                self.items.append((self._href, "".join(self._buf).strip()))
            self._href = None


class Database:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY, url TEXT NOT NULL UNIQUE,
        title TEXT NOT NULL DEFAULT '', visit_count INTEGER NOT NULL DEFAULT 1,
        last_visit REAL NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_history_last ON history(last_visit DESC);
    CREATE TABLE IF NOT EXISTS bookmarks (
        id INTEGER PRIMARY KEY, url TEXT NOT NULL UNIQUE,
        title TEXT NOT NULL DEFAULT '', created REAL NOT NULL);
    """

    def __init__(self, path: Path):
        try:
            self.conn = sqlite3.connect(str(path), timeout=5)
            self.conn.row_factory = sqlite3.Row
            self.conn.executescript(self.SCHEMA)
            self.conn.commit()
        except sqlite3.Error as exc:
            log("Veritabanı açılamadı: %s" % exc)
            self.conn = sqlite3.connect(":memory:")
            self.conn.row_factory = sqlite3.Row
            self.conn.executescript(self.SCHEMA)

    def _run(self, sql: str, params=(), fetch: bool = False):
        try:
            cur = self.conn.execute(sql, params)
            rows = cur.fetchall() if fetch else None
            self.conn.commit()
            return rows if fetch else True
        except sqlite3.Error as exc:
            log("SQL hatası: %s" % exc)
            return [] if fetch else False

    def close(self) -> None:
        try:
            self.conn.commit()
            self.conn.close()
        except sqlite3.Error:
            pass

    def add_visit(self, url: str, title: str) -> None:
        self._run(
            "INSERT INTO history(url,title,visit_count,last_visit) VALUES(?,?,1,?) "
            "ON CONFLICT(url) DO UPDATE SET "
            "title=CASE WHEN excluded.title!='' THEN excluded.title ELSE title END, "
            "visit_count=visit_count+1, last_visit=excluded.last_visit",
            (url, title or "", time.time()))

    def update_title(self, url: str, title: str) -> None:
        if title:
            self._run("UPDATE history SET title=? WHERE url=?", (title, url))

    def search_history(self, query: str = "", limit: int = 500):
        if query:
            return self._run(
                "SELECT * FROM history WHERE url LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\' "
                "ORDER BY last_visit DESC LIMIT ?", (_like(query), _like(query), limit), True)
        return self._run("SELECT * FROM history ORDER BY last_visit DESC LIMIT ?", (limit,), True)

    def top_sites(self, limit: int = 20):
        return self._run("SELECT * FROM history ORDER BY visit_count DESC, last_visit DESC LIMIT ?",
                         (limit,), True)

    def delete_history(self, urls) -> None:
        for url in urls:
            self._run("DELETE FROM history WHERE url=?", (url,))

    def clear_history(self) -> None:
        self._run("DELETE FROM history")

    def is_bookmarked(self, url: str) -> bool:
        rows = self._run("SELECT 1 FROM bookmarks WHERE url=?", (url,), True)
        return bool(rows)

    def add_bookmark(self, url: str, title: str) -> None:
        self._run("INSERT OR IGNORE INTO bookmarks(url,title,created) VALUES(?,?,?)",
                  (url, title or url, time.time()))

    def remove_bookmark(self, url: str) -> None:
        self._run("DELETE FROM bookmarks WHERE url=?", (url,))

    def rename_bookmark(self, url: str, title: str) -> None:
        self._run("UPDATE bookmarks SET title=? WHERE url=?", (title, url))

    def list_bookmarks(self, query: str = "", limit: int = 1000):
        if query:
            return self._run(
                "SELECT * FROM bookmarks WHERE url LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\' "
                "ORDER BY created DESC LIMIT ?", (_like(query), _like(query), limit), True)
        return self._run("SELECT * FROM bookmarks ORDER BY created DESC LIMIT ?", (limit,), True)

    def import_bookmarks_html(self, text: str) -> int:
        parser = _BookmarkParser()
        parser.feed(text)
        count = 0
        for url, title in parser.items:
            if not self.is_bookmarked(url):
                self.add_bookmark(url, title or url)
                count += 1
        return count

    def export_bookmarks_html(self) -> str:
        lines = ['<!DOCTYPE NETSCAPE-Bookmark-file-1>',
                 '<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">',
                 '<TITLE>Yer imleri</TITLE>', '<H1>Yer imleri</H1>', '<DL><p>']
        for r in reversed(self.list_bookmarks(limit=100000)):
            lines.append('    <DT><A HREF="%s" ADD_DATE="%d">%s</A>' % (
                html.escape(r["url"], quote=True), int(r["created"]), html.escape(r["title"])))
        lines.append('</DL><p>')
        return "\n".join(lines)

    def _count(self, table: str) -> int:
        rows = self._run("SELECT COUNT(*) AS n FROM %s" % table, fetch=True)
        return rows[0]["n"] if rows else 0

    def import_history_rows(self, rows) -> int:
        before = self._count("history")
        try:
            self.conn.executemany(
                "INSERT INTO history(url,title,visit_count,last_visit) VALUES(?,?,?,?) "
                "ON CONFLICT(url) DO UPDATE SET "
                "title=CASE WHEN history.title='' THEN excluded.title ELSE history.title END, "
                "visit_count=MAX(history.visit_count, excluded.visit_count), "
                "last_visit=MAX(history.last_visit, excluded.last_visit)", rows)
            self.conn.commit()
        except sqlite3.Error as exc:
            log("Geçmiş içe aktarılamadı: %s" % exc)
            self.conn.rollback()
        return self._count("history") - before

    def import_bookmark_rows(self, rows) -> int:
        before = self._count("bookmarks")
        try:
            self.conn.executemany("INSERT OR IGNORE INTO bookmarks(url,title,created) VALUES(?,?,?)", rows)
            self.conn.commit()
        except sqlite3.Error as exc:
            log("Yer imleri içe aktarılamadı: %s" % exc)
            self.conn.rollback()
        return self._count("bookmarks") - before


# --------------------------------------------------------------------------- #
#  İkonlar ve tema
# --------------------------------------------------------------------------- #
_SVG = {
    "arrow-left": '<path d="M19 12H5M12 19l-7-7 7-7"/>',
    "arrow-right": '<path d="M5 12h14M12 5l7 7-7 7"/>',
    "rotate-cw": '<path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/>',
    "x": '<path d="M18 6L6 18M6 6l12 12"/>',
    "home": '<path d="M3 10l9-7 9 7v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M9 22V12h6v10"/>',
    "star": '<path d="M12 2l3.1 6.3 6.9 1-5 4.9 1.2 6.8L12 17.8 5.8 21l1.2-6.8-5-4.9 6.9-1z"/>',
    "lock": '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    "alert": '<path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "menu": '<path d="M4 6h16M4 12h16M4 18h16"/>',
    "download": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5M12 15V3"/>',
    "search": '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
    "chevron-up": '<path d="M18 15l-6-6-6 6"/>',
    "chevron-down": '<path d="M6 9l6 6 6-6"/>',
    "globe": '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15 15 0 0 1 4 10 15 15 0 0 1-4 10 15 15 0 0 1-4-10 15 15 0 0 1 4-10z"/>',
    "loader": '<path d="M12 2a10 10 0 1 0 10 10"/>',
    "file": '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
    "pause": '<path d="M8 5v14M16 5v14"/>',
    "play": '<path d="M7 4l13 8-13 8z"/>',
    "folder": '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    "trash": '<path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/>',
    "key": '<circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.5 12.5L21 2M17 6l3 3M14 9l3 3"/>',
    "eye": '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
    "eye-off": '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><path d="M1 1l22 22"/>',
    # === YENİ: kısayol ikonları ===
    "grid": '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    # === YENİ SONU ===
}
_icon_cache: dict = {}


def svg_pixmap(name: str, color: str, size: int = 20, fill: bool = False, scale: int = 2) -> QPixmap:
    inner = _SVG.get(name, _SVG["globe"])
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" '
           'fill="%s" stroke="%s" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">%s</svg>'
           % (color if fill else "none", color, inner))
    renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    pm = QPixmap(size * scale, size * scale)
    pm.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pm)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    renderer.render(painter)
    painter.end()
    pm.setDevicePixelRatio(scale)
    return pm


def svg_icon(name: str, color: str, size: int = 20, fill: bool = False) -> QIcon:
    key = (name, color, size, fill)
    icon = _icon_cache.get(key)
    if icon is None:
        icon = QIcon(svg_pixmap(name, color, size, fill))
        _icon_cache[key] = icon
    return icon


def make_app_icon() -> QIcon:
    icon = QIcon()
    for size in (16, 32, 48, 64, 128, 256):
        pm = QPixmap(size, size)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#1a73e8"))
        p.drawRoundedRect(0, 0, size, size, size * 0.22, size * 0.22)
        p.setPen(QColor("#ffffff"))
        font = QFont()
        font.setBold(True)
        font.setPixelSize(max(6, int(size * 0.58)))
        p.setFont(font)
        p.drawText(QRect(0, 0, size, size), Qt.AlignmentFlag.AlignCenter, "Y")
        p.end()
        icon.addPixmap(pm)
    return icon


def theme_colors(dark: bool) -> dict:
    if dark:
        return dict(window="#1f2023", toolbar="#2b2c30", surface="#1a1b1e", text="#e8eaed",
                    muted="#9aa0a6", border="#44464a", hover="#3a3b3f", hover_tab="#292a2e",
                    accent="#8ab4f8", accent_text="#0b1b33", danger="#f28b82", ok="#81c995",
                    page_bg="#202124", card="#2b2c30")
    return dict(window="#dfe3e8", toolbar="#ffffff", surface="#eef1f5", text="#1f2328",
                muted="#5f6368", border="#c9ced6", hover="#e8ebf0", hover_tab="#eceff3",
                accent="#1a73e8", accent_text="#ffffff", danger="#d93025", ok="#188038",
                page_bg="#ffffff", card="#f1f3f4")


def build_palette(c: dict) -> QPalette:
    p = QPalette()
    roles = QPalette.ColorRole
    mapping = {
        roles.Window: c["window"], roles.WindowText: c["text"], roles.Base: c["surface"],
        roles.AlternateBase: c["toolbar"], roles.Text: c["text"], roles.Button: c["toolbar"],
        roles.ButtonText: c["text"], roles.ToolTipBase: c["toolbar"], roles.ToolTipText: c["text"],
        roles.Highlight: c["accent"], roles.HighlightedText: c["accent_text"],
        roles.Link: c["accent"], roles.PlaceholderText: c["muted"], roles.BrightText: "#ffffff",
    }
    for role, color in mapping.items():
        p.setColor(role, QColor(color))
    for role in (roles.WindowText, roles.Text, roles.ButtonText):
        p.setColor(QPalette.ColorGroup.Disabled, role, QColor(c["muted"]))
    return p


QSS_TEMPLATE = """
QMainWindow, QDialog { background: @window@; }
QWidget#tabStrip { background: @window@; }
QToolBar { background: @toolbar@; border: none; padding: 4px 6px; spacing: 4px; }
QToolBar#bookmarksBar { border-bottom: 1px solid @border@; padding: 0px 6px 3px 6px; spacing: 2px; }
QToolButton { background: transparent; border: none; border-radius: 6px; padding: 5px; color: @text@; }
QToolButton:hover { background: @hover@; }
QToolButton:pressed { background: @border@; }
QToolButton::menu-indicator { image: none; }
QToolBar#bookmarksBar QToolButton { padding: 3px 7px; font-size: 12px; }
QLineEdit { background: @surface@; border: 1px solid transparent; border-radius: 15px;
            padding: 5px 10px; color: @text@; selection-background-color: @accent@;
            selection-color: @accent_text@; }
QLineEdit:focus { border: 1px solid @accent@; }
QMenu { background: @toolbar@; color: @text@; border: 1px solid @border@; padding: 4px; }
QMenu::item { padding: 6px 28px 6px 12px; border-radius: 4px; }
QMenu::item:selected { background: @hover@; }
QMenu::item:disabled { color: @muted@; }
QMenu::separator { height: 1px; background: @border@; margin: 4px 8px; }
QStatusBar { background: @toolbar@; color: @muted@; }
QStatusBar::item { border: none; }
QProgressBar#progress { background: @toolbar@; border: none; border-radius: 0px; }
QProgressBar#progress::chunk { background: @accent@; }
QProgressBar { border: 1px solid @border@; border-radius: 4px; background: @surface@;
               text-align: center; color: @text@; max-height: 12px; }
QProgressBar::chunk { background: @accent@; border-radius: 3px; }
QTabBar::tab { background: transparent; color: @muted@; padding: 7px 8px 7px 10px;
               margin: 5px 1px 0px 1px; border-top-left-radius: 9px; border-top-right-radius: 9px; }
QTabBar::tab:selected { background: @toolbar@; color: @text@; }
QTabBar::tab:hover:!selected { background: @hover_tab@; }
QTabBar::close-button { image: url("@close@"); subcontrol-position: right; padding: 2px; border-radius: 4px; }
QTabBar::close-button:hover { background: @border@; image: url("@close_hover@"); }
QFrame#findBar { background: @toolbar@; border-top: 1px solid @border@; }
QFrame#infoBar { background: @surface@; border-bottom: 1px solid @border@; }
QFrame#dlItem { background: @surface@; border: 1px solid @border@; border-radius: 8px; }
QLabel#privateBadge { background: #5b3a8c; color: #ffffff; border-radius: 10px; padding: 2px 10px; }
QToolTip { background: @toolbar@; color: @text@; border: 1px solid @border@; padding: 4px; }
QPushButton { background: @surface@; border: 1px solid @border@; border-radius: 6px;
              padding: 6px 14px; color: @text@; }
QPushButton:hover { background: @hover@; }
QPushButton:disabled { color: @muted@; }
QPushButton:default { background: @accent@; color: @accent_text@; border-color: @accent@; }
QAbstractItemView { background: @surface@; color: @text@; border: 1px solid @border@;
                    alternate-background-color: @toolbar@; selection-background-color: @accent@;
                    selection-color: @accent_text@; outline: none; }
QHeaderView::section { background: @toolbar@; color: @muted@; border: none; padding: 4px 6px; }
QComboBox, QCheckBox, QLabel { color: @text@; }
QScrollArea { border: none; background: transparent; }
"""


def build_qss(c: dict, close_path: str, close_hover_path: str) -> str:
    qss = QSS_TEMPLATE
    values = dict(c)
    values["close"] = close_path
    values["close_hover"] = close_hover_path
    for key, val in values.items():
        qss = qss.replace("@%s@" % key, val)
    return qss


# --------------------------------------------------------------------------- #
#  Yeni sekme sayfası (KISAYOLLAR)
# --------------------------------------------------------------------------- #
NEWTAB_TEMPLATE = """<!doctype html>
<html lang="tr"><head><meta charset="utf-8"><title>Yeni sekme</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:@bg@;--fg:@fg@;--muted:@muted@;--card:@card@;--border:@border@;--accent:@accent@}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
display:flex;flex-direction:column;align-items:center;padding:0 24px}
.spacer{flex:0 0 14vh}
h1{font-size:52px;letter-spacing:-1px;margin:0 0 6px;font-weight:700}
h1 span{color:var(--accent)}
p.sub{color:var(--muted);margin:0 0 28px}
form{width:100%;max-width:620px}
input{width:100%;padding:14px 22px;border-radius:28px;border:1px solid var(--border);background:var(--card);
color:var(--fg);font-size:16px;outline:none}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(128,160,255,.25)}
/* Kısayol ızgarası */
.shortcuts-title{margin:44px 0 16px;color:var(--muted);font-size:13px;text-transform:uppercase;
letter-spacing:1px;display:flex;align-items:center;gap:8px;width:100%;max-width:720px}
.shortcuts-title::after{content:"";flex:1;height:1px;background:var(--border)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:14px;
width:100%;max-width:720px}
.tile{position:relative;display:flex;flex-direction:column;align-items:center;gap:10px;padding:18px 10px;
border-radius:16px;text-decoration:none;color:var(--fg);background:var(--card);border:1px solid transparent;
transition:border-color .15s,transform .1s}
.tile:hover{border-color:var(--border);transform:translateY(-1px)}
.tile .ico{width:52px;height:52px;border-radius:14px;display:flex;align-items:center;justify-content:center;
color:#fff;font-weight:700;font-size:22px}
.tile .t{font-size:13px;text-align:center;max-width:100%;overflow:hidden;text-overflow:ellipsis;
white-space:nowrap;font-weight:500}
.tile .x{position:absolute;top:6px;right:6px;width:20px;height:20px;border-radius:50%;display:none;
align-items:center;justify-content:center;background:var(--border);color:var(--muted);font-size:13px;
cursor:pointer;line-height:1}
.tile:hover .x{display:flex}
.tile .x:hover{background:var(--danger);color:#fff}
.add-tile{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;
padding:18px 10px;border-radius:16px;border:2px dashed var(--border);color:var(--muted);
cursor:pointer;background:transparent;font:inherit;transition:border-color .15s,color .15s}
.add-tile:hover{border-color:var(--accent);color:var(--accent)}
.add-tile .plus{font-size:28px;font-weight:300;line-height:1}
.note{margin-top:36px;max-width:560px;text-align:center;color:var(--muted);font-size:13px}
.empty-hint{width:100%;max-width:720px;padding:32px;text-align:center;color:var(--muted);
border:2px dashed var(--border);border-radius:16px}
</style></head><body>
<div class="spacer"></div>
<h1>@heading@</h1><p class="sub">@sub@</p>
<form id="f"><input id="q" type="text" placeholder="Ara veya adres gir" autocomplete="off" spellcheck="false"></form>
@content@
<script>
(function(){
var TPL=@tpl@;
document.getElementById('f').addEventListener('submit',function(e){
 e.preventDefault();
 var q=document.getElementById('q').value.trim(); if(!q) return;
 var u;
 if(/^[a-z][a-z0-9+.-]*:\\/\\//i.test(q)) u=q;
 else if(/^[^\\s\\/]+\\.[a-z]{2,}(:\\d+)?(\\/\\S*)?$/i.test(q)) u='https://'+q;
 else u=TPL.replace('%s',encodeURIComponent(q));
 location.href=u;
});
// Kısayol silme: tarayıcı tarafında özel protokolle ilet
document.querySelectorAll('.tile .x').forEach(function(el){
  el.addEventListener('click',function(ev){
    ev.preventDefault(); ev.stopPropagation();
    var url = this.parentElement.getAttribute('href');
    if (url) location.href = 'yinegelos://remove-shortcut?url=' + encodeURIComponent(url);
  });
});
// Kısayol ekleme
var addBtn = document.getElementById('add-shortcut');
if (addBtn) {
  addBtn.addEventListener('click', function(){
    var url = prompt('Kısayol adresi (örn. https://example.com):');
    if (url) location.href = 'yinegelos://add-shortcut?url=' + encodeURIComponent(url);
  });
}
})();
</script></body></html>"""

READER_JS = r"""
(function(){
 var ID='__yinegelos_reader__';
 var old=document.getElementById(ID);
 if(old){ if(old.__close){old.__close();} else {old.remove();} return 'off'; }
 var scores=new Map(), ps=document.querySelectorAll('p');
 for(var i=0;i<ps.length;i++){
   var len=(ps[i].innerText||'').trim().length;
   if(len>40){ var par=ps[i].parentElement; if(par){ scores.set(par,(scores.get(par)||0)+len); } }
 }
 var best=null,bs=0;
 scores.forEach(function(v,k){ if(v>bs){bs=v;best=k;} });
 if(!best||bs<200){ return 'unavailable'; }
 var art=best.closest('article');
 if(art && (art.innerText||'').length < (best.innerText||'').length*3){ best=art; }
 var clone=best.cloneNode(true);
 var kill=clone.querySelectorAll('script,style,iframe,object,embed,form,nav,aside,footer,noscript,button,input,select,textarea,svg,link,meta');
 for(var k=0;k<kill.length;k++){ kill[k].remove(); }
 var all=clone.querySelectorAll('*');
 for(var j=0;j<all.length;j++){
   var el=all[j], attrs=Array.prototype.slice.call(el.attributes);
   for(var a=0;a<attrs.length;a++){
     var n=attrs[a].name.toLowerCase();
     if(n.indexOf('on')===0||n==='style'||n==='class'||n==='id'){ el.removeAttribute(attrs[a].name); }
   }
   if(el.tagName==='A'){
     var h=el.getAttribute('href')||'';
     if(/^\s*javascript:/i.test(h)){ el.removeAttribute('href'); }
     el.setAttribute('rel','noopener noreferrer');
   }
 }
 var h1=document.querySelector('h1');
 var title=(h1&&h1.innerText.trim())||document.title;
 var dark=__DARK__;
 var bg=dark?'#1b1c1f':'#fbfaf7', fg=dark?'#e4e4e4':'#222', ac=dark?'#8ab4f8':'#1a5fb4';
 var root=document.createElement('div'); root.id=ID;
 root.style.cssText='position:fixed;left:0;top:0;right:0;bottom:0;z-index:2147483647;overflow:auto;background:'+bg+';color:'+fg+';';
 var st=document.createElement('style');
 st.textContent='#'+ID+' .w{max-width:720px;margin:0 auto;padding:48px 22px 96px;font:19px/1.75 Georgia,"Times New Roman",serif}'
  +'#'+ID+' h1{font:700 34px/1.25 system-ui,sans-serif;margin:0 0 28px}'
  +'#'+ID+' h2,#'+ID+' h3{font-family:system-ui,sans-serif;line-height:1.3;margin:1.6em 0 .5em}'
  +'#'+ID+' img,#'+ID+' video{max-width:100%;height:auto;border-radius:6px}'
  +'#'+ID+' a{color:'+ac+'}#'+ID+' pre,#'+ID+' code{font:15px/1.5 monospace;white-space:pre-wrap}'
  +'#'+ID+' blockquote{margin:1em 0;padding-left:1em;border-left:3px solid '+ac+';opacity:.9}'
  +'#'+ID+' .x{position:fixed;top:14px;right:18px;font:14px system-ui,sans-serif;cursor:pointer;padding:6px 12px;border-radius:14px;background:'+ac+';color:'+(dark?'#0b1b33':'#fff')+'}';
 var wrap=document.createElement('div'); wrap.className='w';
 var t=document.createElement('h1'); t.textContent=title; wrap.appendChild(t); wrap.appendChild(clone);
 var x=document.createElement('div'); x.className='x'; x.textContent='Kapat (Esc)';
 var prevOverflow=document.documentElement.style.overflow;
 function onKey(e){ if(e.key==='Escape'){ close(); } }
 function close(){ document.removeEventListener('keydown',onKey,true); root.remove(); document.documentElement.style.overflow=prevOverflow; }
 root.__close=close; x.addEventListener('click',close);
 document.addEventListener('keydown',onKey,true);
 root.appendChild(st); root.appendChild(wrap); root.appendChild(x);
 document.documentElement.style.overflow='hidden';
 document.documentElement.appendChild(root);
 return 'on';
})();
"""


# --------------------------------------------------------------------------- #
#  WebEngine yardımcı sınıfları
# --------------------------------------------------------------------------- #
class RequestInterceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self, ctrl: "Controller", parent=None):
        super().__init__(parent)
        self.ctrl = ctrl

    def interceptRequest(self, info):  # noqa: N802
        try:
            s = self.ctrl.settings
            if s.get("adblock"):
                main = QWebEngineUrlRequestInfo.ResourceType.ResourceTypeMainFrame
                if info.resourceType() != main and is_blocked_host(info.requestUrl().host()):
                    info.block(True)
                    self.ctrl.blocked_count += 1
                    return
            if s.get("dnt"):
                info.setHttpHeader(QByteArray(b"DNT"), QByteArray(b"1"))
                info.setHttpHeader(QByteArray(b"Sec-GPC"), QByteArray(b"1"))
        except Exception:
            pass


class YinegelSchemeHandler(QWebEngineUrlSchemeHandler):
    def __init__(self, ctrl: "Controller", private: bool, parent=None):
        super().__init__(parent)
        self.ctrl = ctrl
        self.private = private

    def requestStarted(self, job):  # noqa: N802
        try:
            url = job.requestUrl()
            host = url.host()
            if host == "newtab":
                body = self.ctrl.render_newtab(self.private).encode("utf-8")
                buf = QBuffer(job)
                buf.setData(QByteArray(body))
                buf.open(QIODevice.OpenModeFlag.ReadOnly)
                job.reply(QByteArray(b"text/html"), buf)
            elif host == "add-shortcut":
                # Kısayol ekleme isteği
                from urllib.parse import parse_qs
                query = parse_qs(url.query())
                target = query.get("url", [""])[0]
                if target:
                    self.ctrl.add_shortcut(target)
                # Yeni sekme sayfasına geri dön
                job.redirect(QUrl(NEWTAB_URL))
            elif host == "remove-shortcut":
                from urllib.parse import parse_qs
                query = parse_qs(url.query())
                target = query.get("url", [""])[0]
                if target:
                    self.ctrl.remove_shortcut(target)
                job.redirect(QUrl(NEWTAB_URL))
            else:
                job.fail(QWebEngineUrlRequestJob.Error.UrlNotFound)
        except Exception as exc:
            log("yinegelos:// isteği başarısız: %s" % exc)
            try:
                job.fail(QWebEngineUrlRequestJob.Error.RequestFailed)
            except Exception:
                pass


class BrowserView(QWebEngineView):
    zoom_wheel = pyqtSignal(int)

    def childEvent(self, event):  # noqa: N802
        try:
            if event.type() == QEvent.Type.ChildAdded and isinstance(event.child(), QWidget):
                event.child().installEventFilter(self)
        except Exception:
            pass
        super().childEvent(event)

    def eventFilter(self, obj, event):  # noqa: N802
        try:
            if (event.type() == QEvent.Type.Wheel
                    and bool(event.modifiers() & Qt.KeyboardModifier.ControlModifier)):
                delta = event.angleDelta().y()
                if delta:
                    self.zoom_wheel.emit(1 if delta > 0 else -1)
                return True
        except Exception:
            pass
        return super().eventFilter(obj, event)


class BrowserPage(QWebEnginePage):
    EXTERNAL_SCHEMES = ("mailto", "tel", "sms", "magnet", "callto")

    def __init__(self, profile, parent_view, tab: "BrowserTab"):
        super().__init__(profile, parent_view)
        self.tab = tab

    def createWindow(self, window_type):  # noqa: N802
        try:
            return self.tab.win.create_page_for_window(self.tab, window_type)
        except Exception as exc:
            log("Yeni pencere oluşturulamadı: %s" % exc)
            return None

    def acceptNavigationRequest(self, url, nav_type, is_main_frame):  # noqa: N802
        if url.scheme().lower() in self.EXTERNAL_SCHEMES:
            QDesktopServices.openUrl(url)
            return False
        return super().acceptNavigationRequest(url, nav_type, is_main_frame)

    def javaScriptConsoleMessage(self, level, message, line, source):  # noqa: N802
        pass


# --------------------------------------------------------------------------- #
#  Küçük diyaloglar / bileşenler
# --------------------------------------------------------------------------- #
def add_menu_action(menu: QMenu, text: str, slot, enabled: bool = True,
                    checkable: bool = False, checked: bool = False) -> QAction:
    action = QAction(text, menu)
    action.setEnabled(enabled)
    if checkable:
        action.setCheckable(True)
        action.setChecked(checked)
    action.triggered.connect(lambda _checked=False: slot())
    menu.addAction(action)
    return action


class AuthDialog(QDialog):
    def __init__(self, parent, message: str):
        super().__init__(parent)
        self.setWindowTitle("Kimlik doğrulama gerekli")
        self.setMinimumWidth(380)
        lay = QVBoxLayout(self)
        label = QLabel(message)
        label.setWordWrap(True)
        lay.addWidget(label)
        form = QFormLayout()
        self.user = QLineEdit()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Kullanıcı adı", self.user)
        form.addRow("Parola", self.password)
        lay.addLayout(form)
        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)
        lay.addWidget(box)


class AddressBar(QLineEdit):
    escaped = pyqtSignal()
    alt_enter = pyqtSignal()

    def mousePressEvent(self, event):  # noqa: N802
        had_focus = self.hasFocus()
        super().mousePressEvent(event)
        if not had_focus:
            self.selectAll()

    def keyPressEvent(self, event):  # noqa: N802
        key = event.key()
        if key == Qt.Key.Key_Escape:
            self.escaped.emit()
            return
        if (key in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
                and bool(event.modifiers() & Qt.KeyboardModifier.AltModifier)):
            self.alt_enter.emit()
            return
        super().keyPressEvent(event)


class FindEdit(QLineEdit):
    next_requested = pyqtSignal(bool)
    escape = pyqtSignal()

    def keyPressEvent(self, event):  # noqa: N802
        key = event.key()
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self.next_requested.emit(bool(event.modifiers() & Qt.KeyboardModifier.ShiftModifier))
            return
        if key == Qt.Key.Key_Escape:
            self.escape.emit()
            return
        super().keyPressEvent(event)


class FindBar(QFrame):
    search = pyqtSignal(bool)
    closed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("findBar")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 6, 10, 6)
        lay.setSpacing(6)
        self.edit = FindEdit()
        self.edit.setPlaceholderText("Sayfada ara")
        self.edit.setMinimumWidth(240)
        self.edit.setMaximumWidth(340)
        self.case = QCheckBox("Büyük/küçük harf")
        self.label = QLabel("")
        self.btn_prev = QToolButton()
        self.btn_next = QToolButton()
        self.btn_close = QToolButton()
        self.btn_prev.setToolTip("Önceki (Shift+Enter)")
        self.btn_next.setToolTip("Sonraki (Enter)")
        self.btn_close.setToolTip("Kapat (Esc)")
        for w in (self.edit, self.btn_prev, self.btn_next, self.label, self.case):
            lay.addWidget(w)
        lay.addStretch(1)
        lay.addWidget(self.btn_close)
        self.edit.textChanged.connect(lambda _t: self.search.emit(False))
        self.edit.next_requested.connect(self.search.emit)
        self.edit.escape.connect(self.closed.emit)
        self.btn_next.clicked.connect(lambda: self.search.emit(False))
        self.btn_prev.clicked.connect(lambda: self.search.emit(True))
        self.btn_close.clicked.connect(self.closed.emit)
        self.case.toggled.connect(lambda _c: self.search.emit(False))

    def set_icons(self, color: str) -> None:
        self.btn_prev.setIcon(svg_icon("chevron-up", color, 18))
        self.btn_next.setIcon(svg_icon("chevron-down", color, 18))
        self.btn_close.setIcon(svg_icon("x", color, 18))

    def set_result(self, active: int | None, total: int | None) -> None:
        if active is None or total is None:
            self.label.setText("")
        elif total <= 0:
            self.label.setText("Bulunamadı")
        else:
            self.label.setText("%d / %d" % (active, total))

    def focus_field(self) -> None:
        self.edit.setFocus(Qt.FocusReason.ShortcutFocusReason)
        self.edit.selectAll()


class TabBar(QTabBar):
    new_tab_requested = pyqtSignal()
    context_requested = pyqtSignal(int, QPoint)

    PINNED_WIDTH = 44
    TAB_WIDTH = 190

    def __init__(self):
        super().__init__()
        self.setTabsClosable(True)
        self.setMovable(True)
        self.setExpanding(False)
        self.setDocumentMode(True)
        self.setDrawBase(False)
        self.setUsesScrollButtons(True)
        self.setElideMode(Qt.TextElideMode.ElideRight)

    def tabSizeHint(self, index):  # noqa: N802
        size = super().tabSizeHint(index)
        width = self.PINNED_WIDTH if self.tabData(index) == "pinned" else self.TAB_WIDTH
        return QSize(width, size.height())

    def mouseReleaseEvent(self, event):  # noqa: N802
        if event.button() == Qt.MouseButton.MiddleButton:
            i = self.tabAt(event.position().toPoint())
            if i >= 0:
                self.tabCloseRequested.emit(i)
                event.accept()
                return
        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event):  # noqa: N802
        if (event.button() == Qt.MouseButton.LeftButton
                and self.tabAt(event.position().toPoint()) < 0):
            self.new_tab_requested.emit()
            event.accept()
            return
        super().mouseDoubleClickEvent(event)

    def contextMenuEvent(self, event):  # noqa: N802
        self.context_requested.emit(self.tabAt(event.pos()), event.globalPos())
        event.accept()


def history_key(url: QUrl) -> str:
    return url.adjusted(QUrl.UrlFormattingOption.RemoveFragment).toString()


# --------------------------------------------------------------------------- #
#  Sekme
# --------------------------------------------------------------------------- #
class BrowserTab(QWidget):
    def __init__(self, win: "BrowserWindow"):
        super().__init__()
        self.win = win
        self.ctrl = win.ctrl
        self.private = win.private
        self.loading = False
        self.progress = 0
        self.pinned = False
        self.pending_url = ""
        self.pending_title = ""
        self.crash_count = 0
        self.devtools_view: QWebEngineView | None = None
        self._perm_queue: list = []
        self._perm_active = None
        self._recorded_url = ""
        self._recorded_at = 0.0
        self._autofill_done = False

        self.view = BrowserView(self)
        self.page = BrowserPage(win.profile, self.view, self)
        self.view.setPage(self.page)
        self.page.setBackgroundColor(QColor(self.ctrl.colors["page_bg"]))
        self.view.zoom_wheel.connect(lambda d: self.win.zoom_step(d, self))

        self.infobar = QFrame()
        self.infobar.setObjectName("infoBar")
        ib = QHBoxLayout(self.infobar)
        ib.setContentsMargins(12, 6, 12, 6)
        self.info_label = QLabel()
        self.btn_allow = QPushButton("İzin ver")
        self.btn_deny = QPushButton("Engelle")
        ib.addWidget(self.info_label, 1)
        ib.addWidget(self.btn_allow)
        ib.addWidget(self.btn_deny)
        self.btn_allow.clicked.connect(lambda: self._answer_permission(True))
        self.btn_deny.clicked.connect(lambda: self._answer_permission(False))
        self.infobar.hide()

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.setChildrenCollapsible(False)
        self.splitter.addWidget(self.view)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        lay.addWidget(self.infobar)
        lay.addWidget(self.splitter, 1)

        v, p = self.view, self.page
        v.titleChanged.connect(self._on_title)
        v.urlChanged.connect(self._on_url)
        v.iconChanged.connect(lambda _i: self.win.tab_updated(self, icon=True))
        v.loadStarted.connect(self._on_load_started)
        v.loadProgress.connect(self._on_progress)
        v.loadFinished.connect(self._on_load_finished)
        p.linkHovered.connect(self._on_link_hovered)
        p.windowCloseRequested.connect(self._on_close_requested)
        p.fullScreenRequested.connect(self._on_fullscreen)
        p.recentlyAudibleChanged.connect(lambda _a: self.win.tab_updated(self, audio=True))
        p.renderProcessTerminated.connect(self._on_render_terminated)
        p.authenticationRequired.connect(self._on_auth)
        p.proxyAuthenticationRequired.connect(self._on_proxy_auth)
        p.certificateError.connect(self._on_cert_error)
        p.findTextFinished.connect(lambda r: self.win.on_find_result(self, r))
        p.pdfPrintingFinished.connect(self._on_pdf_finished)
        if hasattr(QWebEnginePage, "permissionRequested"):
            p.permissionRequested.connect(self._on_permission_new)
        elif hasattr(QWebEnginePage, "featurePermissionRequested"):
            p.featurePermissionRequested.connect(self._on_permission_old)
        if hasattr(QWebEnginePage, "printRequested"):
            p.printRequested.connect(lambda: self.win.print_page(self))

    def load(self, url) -> None:
        if isinstance(url, str):
            url = QUrl(url)
        self.pending_url = ""
        self._autofill_done = False
        self.view.load(url)

    def ensure_loaded(self) -> None:
        if self.pending_url:
            url, self.pending_url = self.pending_url, ""
            self.view.load(QUrl(url))

    def url_string(self) -> str:
        return self.pending_url or self.view.url().toString()

    def host(self) -> str:
        return QUrl(self.url_string()).host()

    def is_newtab(self) -> bool:
        return self.url_string().startswith(NEWTAB_URL)

    def display_title(self) -> str:
        if self.pending_url:
            return self.pending_title or self.pending_url
        title = self.view.title()
        if self.is_newtab():
            return "Yeni sekme"
        if title:
            return title
        if self.loading:
            return "Yükleniyor…"
        url = self.url_string()
        return url if url and url != "about:blank" else "Yeni sekme"

    def _on_title(self, title: str) -> None:
        self.win.tab_updated(self, title=True)
        if not self.private and title and self._recorded_url:
            key = history_key(self.view.url())
            if key == self._recorded_url and title != key:
                self.ctrl.db.update_title(key, title)

    def _on_url(self, _url) -> None:
        self._apply_site_zoom()
        self.win.tab_updated(self, url=True)

    def _on_load_started(self) -> None:
        self.loading = True
        self.progress = max(self.progress if self.loading and self.progress < 100 else 0, 5)
        self.win.tab_updated(self, load=True)

    def _on_progress(self, value: int) -> None:
        self.progress = value
        self.win.tab_updated(self, load=True)

    def _on_load_finished(self, ok: bool) -> None:
        self.loading = False
        self.progress = 100 if ok else 0
        if ok:
            self._apply_site_zoom()
            self._record_visit()
            if (not self.private
                    and self.ctrl.settings.get("password_manager_enabled")
                    and self.ctrl.settings.get("password_autofill")):
                self._try_autofill()
        self.win.tab_updated(self, load=True, title=True, icon=True)

    def _try_autofill(self) -> None:
        if self._autofill_done:
            return
        host = self.host()
        if not host:
            return
        entries = self.ctrl.get_passwords(host)
        if not entries:
            return
        self._autofill_done = True
        entry = entries[0]
        js = r"""
        (function(){
            try {
                var u = document.querySelector('input[type="text"][autocomplete*="user"], input[type="email"], input[name*="user" i], input[name*="email" i], input[name*="login" i]');
                var p = document.querySelector('input[type="password"]');
                if (!u) {
                    var texts = document.querySelectorAll('input[type="text"]');
                    for (var i=0; i<texts.length; i++) {
                        if (texts[i].offsetParent !== null) { u = texts[i]; break; }
                    }
                }
                if (u && p && !u.value && !p.value) {
                    u.value = %s;
                    p.value = %s;
                    u.dispatchEvent(new Event('input', {bubbles:true}));
                    p.dispatchEvent(new Event('input', {bubbles:true}));
                    u.dispatchEvent(new Event('change', {bubbles:true}));
                    p.dispatchEvent(new Event('change', {bubbles:true}));
                }
            } catch(e) {}
        })();
        """ % (json.dumps(entry["username"]), json.dumps(entry["password"]))
        try:
            self.page.runJavaScript(js)
        except RuntimeError:
            return

    def _record_visit(self) -> None:
        if self.private:
            return
        url = self.view.url()
        if url.scheme() not in ("http", "https"):
            return
        key = history_key(url)
        now = time.time()
        if key == self._recorded_url and now - self._recorded_at < 3:
            return
        self._recorded_url, self._recorded_at = key, now
        title = self.view.title()
        if title in (key, url.toString()):
            title = ""
        self.ctrl.record_visit(key, title)

    def _apply_site_zoom(self) -> None:
        z = self.ctrl.zoom_for_host(self.host(), self.private)
        try:
            if abs(self.view.zoomFactor() - z) > 0.001:
                self.view.setZoomFactor(z)
        except RuntimeError:
            return
        self.win.update_zoom_label(self)

    def _on_link_hovered(self, link: str) -> None:
        if self.win.current_tab() is self:
            if link:
                self.win.statusBar().showMessage(link)
            else:
                self.win.statusBar().clearMessage()

    def _on_close_requested(self) -> None:
        QTimer.singleShot(0, lambda: self.win.close_tab(self, remember=False))

    def _on_fullscreen(self, request) -> None:
        request.accept()
        self.win.set_html_fullscreen(self, request.toggleOn())

    def _on_pdf_finished(self, path: str, ok: bool) -> None:
        self.win.statusBar().showMessage(
            ("PDF kaydedildi: " + path) if ok else "PDF oluşturulamadı.", 6000)

    def _on_render_terminated(self, status, _code) -> None:
        if status == QWebEnginePage.RenderProcessTerminationStatus.NormalTerminationStatus:
            return
        self.crash_count += 1
        if self.crash_count <= 3:
            self.win.statusBar().showMessage(
                "Sayfa süreci beklenmedik şekilde sonlandı, yeniden yükleniyor…", 5000)
            QTimer.singleShot(300, self.view.reload)
        else:
            self.view.setHtml(
                "<html><body style='font-family:sans-serif;padding:48px'>"
                "<h2>Bu sayfa tekrar tekrar çöktü</h2>"
                "<p>Sayfayı elle yenileyerek tekrar deneyebilirsiniz.</p></body></html>")

    def _cancel_auth(self, authenticator) -> None:
        try:
            if sip is not None and hasattr(sip, "assign"):
                sip.assign(authenticator, QAuthenticator())
        except Exception:
            pass

    def _ask_credentials(self, authenticator, message: str) -> None:
        realm = authenticator.realm()
        if realm:
            message += "\nBölge: %s" % realm
        dlg = AuthDialog(self.win, message)
        if dlg.exec():
            authenticator.setUser(dlg.user.text())
            authenticator.setPassword(dlg.password.text())
        else:
            self._cancel_auth(authenticator)

    def _on_auth(self, url, authenticator) -> None:
        self._ask_credentials(authenticator,
                              "%s adresi kullanıcı adı ve parola istiyor." % url.host())

    def _on_proxy_auth(self, _url, authenticator, proxy_host: str) -> None:
        self._ask_credentials(authenticator,
                              "%s vekil sunucusu kimlik doğrulaması istiyor." % proxy_host)

    def _on_cert_error(self, error) -> None:
        ctrl = self.ctrl
        host = error.url().host()
        key = (host, error.type())
        if key in ctrl.cert_exceptions:
            error.acceptCertificate()
            return
        if not error.isOverridable():
            error.rejectCertificate()
            return
        if key in ctrl.cert_pending or time.time() - ctrl.cert_rejected.get(key, 0) < 8:
            error.rejectCertificate()
            return
        ctrl.cert_pending.add(key)
        try:
            box = QMessageBox(self.win)
            box.setIcon(QMessageBox.Icon.Warning)
            box.setWindowTitle("Güvenlik uyarısı")
            box.setText("<b>%s</b> sitesinin güvenlik sertifikası doğrulanamadı." % html.escape(host))
            box.setInformativeText(
                "%s\n\nDevam ederseniz bu sitedeki şifreleriniz ve kişisel bilgileriniz "
                "üçüncü kişilerce görülebilir." % error.description())
            back = box.addButton("Güvenli sayfaya dön", QMessageBox.ButtonRole.RejectRole)
            go = box.addButton("Yine de devam et (güvenli değil)", QMessageBox.ButtonRole.DestructiveRole)
            box.setDefaultButton(back)
            box.exec()
            proceed = box.clickedButton() is go
        finally:
            ctrl.cert_pending.discard(key)
        if proceed:
            ctrl.cert_exceptions.add(key)
            error.acceptCertificate()
        else:
            ctrl.cert_rejected[key] = time.time()
            error.rejectCertificate()

    def _on_permission_new(self, permission) -> None:
        try:
            name = permission.permissionType().name
            origin = permission.origin()
            host = origin.host() or origin.toString()
        except Exception:
            return
        if name == "Unsupported":
            permission.deny()
            return

        def decide(allow: bool, perm=permission) -> None:
            try:
                perm.grant() if allow else perm.deny()
            except Exception:
                pass
        self.ask_permission(host, name, decide)

    def _on_permission_old(self, origin, feature) -> None:
        name = feature.name
        policy = QWebEnginePage.PermissionPolicy

        def decide(allow: bool) -> None:
            try:
                self.page.setFeaturePermission(
                    origin, feature,
                    policy.PermissionGrantedByUser if allow else policy.PermissionDeniedByUser)
            except Exception:
                pass
        self.ask_permission(origin.host() or origin.toString(), name, decide)

    def ask_permission(self, host: str, name: str, callback) -> None:
        store = self.ctrl.permission_store(self.private)
        stored = store.get("%s|%s" % (host, name))
        if stored in ("allow", "deny"):
            callback(stored == "allow")
            return
        self._perm_queue.append((host, name, callback))
        self._show_next_permission()

    def _show_next_permission(self) -> None:
        if self._perm_active is not None or not self._perm_queue:
            return
        self._perm_active = self._perm_queue.pop(0)
        host, name, _cb = self._perm_active
        what = PERMISSION_TEXT.get(name, "“%s” iznini kullanmak" % name)
        self.info_label.setText("<b>%s</b> %s istiyor." % (html.escape(host), what))
        self.infobar.show()

    def _answer_permission(self, allow: bool) -> None:
        active, self._perm_active = self._perm_active, None
        self.infobar.hide()
        if active:
            host, name, callback = active
            self.ctrl.remember_permission(self.private, "%s|%s" % (host, name), allow)
            try:
                callback(allow)
            except Exception as exc:
                log("İzin yanıtı uygulanamadı: %s" % exc)
        self._show_next_permission()

    def toggle_devtools(self) -> None:
        if self.devtools_view is not None:
            self.close_devtools()
            return
        self.ensure_loaded()
        dv = QWebEngineView()
        dp = QWebEnginePage(self.win.profile, dv)
        dv.setPage(dp)
        self.page.setDevToolsPage(dp)
        self.splitter.addWidget(dv)
        total = max(self.splitter.width(), 600)
        self.splitter.setSizes([int(total * 0.62), int(total * 0.38)])
        self.devtools_view = dv

    def close_devtools(self) -> None:
        dv, self.devtools_view = self.devtools_view, None
        if dv is None:
            return
        try:
            self.page.setDevToolsPage(None)
        except Exception:
            pass
        dv.hide()
        dv.deleteLater()

    def dispose(self) -> None:
        try:
            self.close_devtools()
            self.view.stop()
        except Exception:
            pass
        self.hide()
        self.deleteLater()


# --------------------------------------------------------------------------- #
#  İndirmeler
# --------------------------------------------------------------------------- #
class DownloadItem(QFrame):
    removed = pyqtSignal(object)

    def __init__(self, ctrl: "Controller", request: QWebEngineDownloadRequest):
        super().__init__()
        self.ctrl = ctrl
        self.request = request
        self.setObjectName("dlItem")
        self._last_time = time.monotonic()
        self._last_bytes = 0
        self._speed = 0.0
        self.path = self._current_path()

        outer = QHBoxLayout(self)
        outer.setContentsMargins(12, 10, 10, 10)
        info = QVBoxLayout()
        info.setSpacing(4)
        self.name = QLabel()
        f = self.name.font()
        f.setBold(True)
        self.name.setFont(f)
        self.status = QLabel()
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setRange(0, 100)
        info.addWidget(self.name)
        info.addWidget(self.bar)
        info.addWidget(self.status)
        outer.addLayout(info, 1)

        c = ctrl.colors
        self.btn_pause = QToolButton()
        self.btn_cancel = QToolButton()
        self.btn_open = QPushButton("Aç")
        self.btn_folder = QPushButton("Klasör")
        self.btn_remove = QToolButton()
        self.btn_pause.setIcon(svg_icon("pause", c["text"], 18))
        self.btn_cancel.setIcon(svg_icon("x", c["text"], 18))
        self.btn_remove.setIcon(svg_icon("trash", c["text"], 18))
        self.btn_pause.setToolTip("Duraklat / devam et")
        self.btn_cancel.setToolTip("İptal")
        self.btn_remove.setToolTip("Listeden kaldır")
        for w in (self.btn_pause, self.btn_cancel, self.btn_open, self.btn_folder, self.btn_remove):
            outer.addWidget(w)

        self.btn_pause.clicked.connect(self._toggle_pause)
        self.btn_cancel.clicked.connect(self._cancel)
        self.btn_open.clicked.connect(self._open)
        self.btn_folder.clicked.connect(self._show_in_folder)
        self.btn_remove.clicked.connect(self._remove)

        request.receivedBytesChanged.connect(self._on_progress)
        request.totalBytesChanged.connect(self._on_progress)
        request.stateChanged.connect(self._refresh)
        request.isPausedChanged.connect(self._refresh)
        self._refresh()

    def _current_path(self) -> Path:
        try:
            return Path(self.request.downloadDirectory()) / self.request.downloadFileName()
        except RuntimeError:
            return getattr(self, "path", Path(""))

    def is_active(self) -> bool:
        try:
            S = QWebEngineDownloadRequest.DownloadState
            return self.request.state() in (S.DownloadInProgress, S.DownloadRequested)
        except RuntimeError:
            return False

    def _on_progress(self) -> None:
        now = time.monotonic()
        try:
            received = self.request.receivedBytes()
        except RuntimeError:
            return
        if now - self._last_time >= 0.6:
            self._speed = max(0.0, (received - self._last_bytes) / (now - self._last_time))
            self._last_time, self._last_bytes = now, received
        self._refresh()

    def _refresh(self, *_args) -> None:
        r = self.request
        try:
            S = QWebEngineDownloadRequest.DownloadState
            state = r.state()
            received, total = r.receivedBytes(), r.totalBytes()
            paused = r.isPaused()
            reason = r.interruptReasonString() if state == S.DownloadInterrupted else ""
        except RuntimeError:
            return
        self.path = self._current_path()
        self.name.setText(self.path.name or "İndirme")
        active = state in (S.DownloadInProgress, S.DownloadRequested)
        done = state == S.DownloadCompleted
        if done:
            self.bar.setRange(0, 100)
            self.bar.setValue(100)
            self.status.setText("Tamamlandı — %s" % human_size(received))
            self.ctrl.release_download_path(self.path)
        elif state == S.DownloadCancelled:
            self.status.setText("İptal edildi")
            self.ctrl.release_download_path(self.path)
        elif state == S.DownloadInterrupted:
            self.status.setText("Kesildi: %s" % (reason or "bilinmeyen neden"))
            self.ctrl.release_download_path(self.path)
        else:
            if total > 0:
                self.bar.setRange(0, 100)
                self.bar.setValue(int(received * 100 / total))
                text = "%s / %s" % (human_size(received), human_size(total))
            else:
                self.bar.setRange(0, 0)
                text = human_size(received)
            if paused:
                text += " — duraklatıldı"
            elif self._speed > 0:
                text += " — %s/sn" % human_size(int(self._speed))
            self.status.setText(text)
        self.bar.setVisible(active)
        self.btn_pause.setVisible(active)
        self.btn_cancel.setVisible(active)
        self.btn_open.setVisible(done)
        self.btn_folder.setVisible(done)
        c = self.ctrl.colors
        self.btn_pause.setIcon(svg_icon("play" if paused else "pause", c["text"], 18))

    def _toggle_pause(self) -> None:
        try:
            self.request.resume() if self.request.isPaused() else self.request.pause()
        except RuntimeError:
            pass

    def _cancel(self) -> None:
        try:
            self.request.cancel()
        except RuntimeError:
            pass

    def _open(self) -> None:
        if self.path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.path)))
        else:
            QMessageBox.information(self, "Dosya bulunamadı", "Dosya taşınmış veya silinmiş.")

    def _show_in_folder(self) -> None:
        try:
            if sys.platform.startswith("win") and self.path.exists():
                subprocess.Popen(["explorer", "/select,", str(self.path)])
            elif sys.platform == "darwin" and self.path.exists():
                subprocess.Popen(["open", "-R", str(self.path)])
            else:
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.path.parent)))
        except OSError:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.path.parent)))

    def _remove(self) -> None:
        if self.is_active():
            self._cancel()
        self.removed.emit(self)


class DownloadsDialog(QDialog):
    def __init__(self, ctrl: "Controller"):
        super().__init__(None)
        self.ctrl = ctrl
        self.items: list[DownloadItem] = []
        self.setWindowTitle("İndirilenler")
        self.resize(680, 500)
        lay = QVBoxLayout(self)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.container = QWidget()
        self.vbox = QVBoxLayout(self.container)
        self.vbox.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.vbox.setSpacing(8)
        self.empty = QLabel("Henüz indirme yok.")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.vbox.addWidget(self.empty)
        self.scroll.setWidget(self.container)
        lay.addWidget(self.scroll, 1)
        row = QHBoxLayout()
        b_clear = QPushButton("Tamamlananları temizle")
        b_dir = QPushButton("İndirme klasörünü aç")
        b_clear.clicked.connect(self.clear_finished)
        b_dir.clicked.connect(lambda: QDesktopServices.openUrl(
            QUrl.fromLocalFile(self.ctrl.download_dir())))
        row.addWidget(b_clear)
        row.addStretch(1)
        row.addWidget(b_dir)
        lay.addLayout(row)

    def add_download(self, request) -> None:
        item = DownloadItem(self.ctrl, request)
        item.removed.connect(self._on_removed)
        self.items.insert(0, item)
        self.vbox.insertWidget(0, item)
        self.empty.hide()
        self.present()

    def present(self) -> None:
        self.show()
        self.raise_()
        self.activateWindow()

    def _on_removed(self, item: DownloadItem) -> None:
        if item in self.items:
            self.items.remove(item)
        self.vbox.removeWidget(item)
        item.hide()
        item.deleteLater()
        if not self.items:
            self.empty.show()

    def clear_finished(self) -> None:
        for item in list(self.items):
            if not item.is_active():
                self._on_removed(item)

    def active_count(self) -> int:
        return sum(1 for i in self.items if i.is_active())


# --------------------------------------------------------------------------- #
#  Geçmiş / Yer imleri
# --------------------------------------------------------------------------- #
class HistoryDialog(QDialog):
    def __init__(self, ctrl: "Controller"):
        super().__init__(None)
        self.ctrl = ctrl
        self.setWindowTitle("Geçmiş")
        self.resize(900, 580)
        lay = QVBoxLayout(self)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Geçmişte ara…")
        self.search.setClearButtonEnabled(True)
        lay.addWidget(self.search)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Başlık", "Adres", "Son ziyaret"])
        self.tree.setRootIsDecorated(False)
        self.tree.setAlternatingRowColors(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.setColumnWidth(0, 330)
        self.tree.setColumnWidth(1, 330)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        lay.addWidget(self.tree, 1)
        row = QHBoxLayout()
        b_del = QPushButton("Seçilenleri sil")
        b_clear = QPushButton("Tüm geçmişi temizle")
        row.addWidget(b_del)
        row.addStretch(1)
        row.addWidget(b_clear)
        lay.addLayout(row)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(200)
        self._timer.timeout.connect(self.reload)
        self.search.textChanged.connect(lambda _t: self._timer.start())
        self.tree.itemActivated.connect(lambda item, _c: self._open(item))
        self.tree.customContextMenuRequested.connect(self._menu)
        b_del.clicked.connect(self._delete_selected)
        b_clear.clicked.connect(self._clear_all)
        self.reload()

    def present(self) -> None:
        self.reload()
        self.show()
        self.raise_()
        self.activateWindow()

    def reload(self) -> None:
        rows = self.ctrl.db.search_history(self.search.text().strip(), 500)
        self.tree.setUpdatesEnabled(False)
        self.tree.clear()
        for r in rows:
            item = QTreeWidgetItem([r["title"] or r["url"], r["url"], fmt_time(r["last_visit"])])
            item.setData(0, Qt.ItemDataRole.UserRole, r["url"])
            item.setToolTip(1, r["url"])
            self.tree.addTopLevelItem(item)
        self.tree.setUpdatesEnabled(True)

    def _urls(self) -> list[str]:
        return [i.data(0, Qt.ItemDataRole.UserRole) for i in self.tree.selectedItems()]

    def _open(self, item, new_tab: bool = True) -> None:
        self.ctrl.open_in_active(item.data(0, Qt.ItemDataRole.UserRole), new_tab=new_tab)

    def _menu(self, pos) -> None:
        urls = self._urls()
        menu = QMenu(self)
        add_menu_action(menu, "Yeni sekmede aç", lambda: [self.ctrl.open_in_active(u) for u in urls],
                        enabled=bool(urls))
        add_menu_action(menu, "Adresi kopyala",
                        lambda: QApplication.clipboard().setText("\n".join(urls)), enabled=bool(urls))
        menu.addSeparator()
        add_menu_action(menu, "Geçmişten sil", self._delete_selected, enabled=bool(urls))
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def _delete_selected(self) -> None:
        urls = self._urls()
        if urls:
            self.ctrl.db.delete_history(urls)
            self.ctrl.request_suggestions_refresh()
            self.reload()

    def _clear_all(self) -> None:
        ans = QMessageBox.question(self, "Geçmişi temizle", "Tüm tarama geçmişi silinsin mi?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                   QMessageBox.StandardButton.No)
        if ans == QMessageBox.StandardButton.Yes:
            self.ctrl.db.clear_history()
            self.ctrl.request_suggestions_refresh()
            self.reload()


class BookmarksDialog(QDialog):
    def __init__(self, ctrl: "Controller"):
        super().__init__(None)
        self.ctrl = ctrl
        self.setWindowTitle("Yer imleri")
        self.resize(820, 540)
        lay = QVBoxLayout(self)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Yer imlerinde ara…")
        self.search.setClearButtonEnabled(True)
        lay.addWidget(self.search)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Başlık", "Adres"])
        self.tree.setRootIsDecorated(False)
        self.tree.setAlternatingRowColors(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.setColumnWidth(0, 340)
        lay.addWidget(self.tree, 1)
        row = QHBoxLayout()
        b_open = QPushButton("Aç")
        b_rename = QPushButton("Yeniden adlandır")
        b_del = QPushButton("Sil")
        b_imp = QPushButton("İçe aktar (HTML)…")
        b_exp = QPushButton("Dışa aktar (HTML)…")
        for b in (b_open, b_rename, b_del):
            row.addWidget(b)
        row.addStretch(1)
        row.addWidget(b_imp)
        row.addWidget(b_exp)
        lay.addLayout(row)
        self.search.textChanged.connect(lambda _t: self.reload())
        self.tree.itemActivated.connect(lambda item, _c: self.ctrl.open_in_active(
            item.data(0, Qt.ItemDataRole.UserRole)))
        b_open.clicked.connect(lambda: [self.ctrl.open_in_active(u) for u in self._urls()])
        b_rename.clicked.connect(self._rename)
        b_del.clicked.connect(self._delete)
        b_imp.clicked.connect(self._import)
        b_exp.clicked.connect(self._export)
        self.reload()

    def present(self) -> None:
        self.reload()
        self.show()
        self.raise_()
        self.activateWindow()

    def reload(self) -> None:
        self.tree.clear()
        for r in self.ctrl.db.list_bookmarks(self.search.text().strip()):
            item = QTreeWidgetItem([r["title"] or r["url"], r["url"]])
            item.setData(0, Qt.ItemDataRole.UserRole, r["url"])
            self.tree.addTopLevelItem(item)

    def _urls(self) -> list[str]:
        return [i.data(0, Qt.ItemDataRole.UserRole) for i in self.tree.selectedItems()]

    def _rename(self) -> None:
        items = self.tree.selectedItems()
        if not items:
            return
        item = items[0]
        url = item.data(0, Qt.ItemDataRole.UserRole)
        text, ok = QInputDialog.getText(self, "Yeniden adlandır", "Yeni ad:", text=item.text(0))
        if ok and text.strip():
            self.ctrl.db.rename_bookmark(url, text.strip())
            self.ctrl.bookmarks_changed()

    def _delete(self) -> None:
        urls = self._urls()
        for u in urls:
            self.ctrl.db.remove_bookmark(u)
        if urls:
            self.ctrl.bookmarks_changed()

    def _import(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Yer imlerini içe aktar", "",
                                              "HTML yer imi dosyası (*.html *.htm);;Tüm dosyalar (*)")
        if not path:
            return
        try:
            text = Path(path).read_text("utf-8", errors="replace")
        except OSError as exc:
            QMessageBox.warning(self, "Hata", "Dosya okunamadı: %s" % exc)
            return
        count = self.ctrl.db.import_bookmarks_html(text)
        self.ctrl.bookmarks_changed()
        QMessageBox.information(self, "İçe aktarma", "%d yer imi eklendi." % count)

    def _export(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Yer imlerini dışa aktar", "yer-imleri.html",
                                              "HTML (*.html)")
        if not path:
            return
        try:
            Path(path).write_text(self.ctrl.db.export_bookmarks_html(), "utf-8")
        except OSError as exc:
            QMessageBox.warning(self, "Hata", "Dosya yazılamadı: %s" % exc)


# --------------------------------------------------------------------------- #
#  Parola Yöneticisi Diyalogları
# --------------------------------------------------------------------------- #
class PasswordPromptDialog(QDialog):
    def __init__(self, parent, host: str, title: str = "Parola kaydet"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(420)
        lay = QVBoxLayout(self)
        lbl = QLabel("Site: <b>%s</b>" % html.escape(host))
        lbl.setWordWrap(True)
        lay.addWidget(lbl)
        form = QFormLayout()
        self.user = QLineEdit()
        self.user.setPlaceholderText("kullanıcı adı veya e-posta")
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("parola")
        self.show_pw = QToolButton()
        self.show_pw.setCheckable(True)
        self.show_pw.setIcon(svg_icon("eye", "#888888", 18))
        self.show_pw.setToolTip("Parolayı göster / gizle")
        self.show_pw.toggled.connect(self._toggle_echo)

        pw_row = QHBoxLayout()
        pw_row.addWidget(self.password, 1)
        pw_row.addWidget(self.show_pw)

        form.addRow("Kullanıcı adı", self.user)
        form.addRow("Parola", pw_row)
        lay.addLayout(form)
        box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        box.button(QDialogButtonBox.StandardButton.Save).setText("Kaydet")
        box.button(QDialogButtonBox.StandardButton.Cancel).setText("Vazgeç")
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)
        lay.addWidget(box)

    def _toggle_echo(self, on: bool) -> None:
        self.password.setEchoMode(
            QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password)
        self.show_pw.setIcon(svg_icon("eye-off" if on else "eye", "#888888", 18))

    def values(self):
        return self.user.text().strip(), self.password.text()


class PasswordVaultDialog(QDialog):
    def __init__(self, ctrl: "Controller"):
        super().__init__(None)
        self.ctrl = ctrl
        self.setWindowTitle("Parola Yöneticisi")
        self.resize(760, 520)
        lay = QVBoxLayout(self)
        intro = QLabel(
            "Kayıtlı parolalar Fernet ile şifrelenir; şifreleme anahtarı işletim sisteminin "
            "güvenli kimlik bilgisi deposunda (Windows Credential Manager, macOS Keychain, "
            "Linux Secret Service) saklanır. Parolalar düz metin olarak hiçbir yere yazılmaz.")
        intro.setWordWrap(True)
        lay.addWidget(intro)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Site veya kullanıcı adı ara…")
        self.search.setClearButtonEnabled(True)
        lay.addWidget(self.search)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Site", "Kullanıcı Adı", "Kayıt Tarihi", ""])
        self.tree.setRootIsDecorated(False)
        self.tree.setAlternatingRowColors(True)
        self.tree.setColumnWidth(0, 260)
        self.tree.setColumnWidth(1, 220)
        self.tree.setColumnWidth(2, 160)
        lay.addWidget(self.tree, 1)

        row = QHBoxLayout()
        b_add = QPushButton("Yeni parola ekle…")
        b_open = QPushButton("Siteyi aç")
        b_reveal = QPushButton("Parolayı göster")
        b_copy = QPushButton("Parolayı kopyala")
        b_del = QPushButton("Sil")
        for b in (b_add, b_open, b_reveal, b_copy, b_del):
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)

        self.search.textChanged.connect(lambda _t: self.reload())
        self.tree.itemDoubleClicked.connect(lambda _i, _c: self._open_site())
        b_add.clicked.connect(self._add)
        b_open.clicked.connect(self._open_site)
        b_reveal.clicked.connect(self._reveal)
        b_copy.clicked.connect(self._copy)
        b_del.clicked.connect(self._delete)
        self.reload()

    def present(self) -> None:
        self.reload()
        self.show()
        self.raise_()
        self.activateWindow()

    def _vault(self) -> dict:
        return self.ctrl._load_vault()

    def reload(self) -> None:
        q = self.search.text().strip().lower()
        self.tree.clear()
        for host, entries in self._vault().items():
            for i, e in enumerate(entries):
                username = e.get("username", "")
                if q and q not in host.lower() and q not in username.lower():
                    continue
                item = QTreeWidgetItem([
                    host, username, fmt_time(e.get("created", 0)), "••••••"])
                item.setData(0, Qt.ItemDataRole.UserRole, (host, i))
                self.tree.addTopLevelItem(item)

    def _selected(self):
        item = self.tree.currentItem()
        if item is None:
            return None
        return item.data(0, Qt.ItemDataRole.UserRole)

    def _add(self) -> None:
        host, ok = QInputDialog.getText(self, "Yeni parola", "Site alan adı (örn. example.com):")
        if not ok or not host.strip():
            return
        host = host.strip().lower()
        dlg = PasswordPromptDialog(self, host, "Yeni parola kaydet")
        if dlg.exec():
            user, pw = dlg.values()
            if user and pw:
                self.ctrl.store_password(host, user, pw)
                self.reload()

    def _open_site(self) -> None:
        sel = self._selected()
        if sel is None:
            return
        host, _i = sel
        self.ctrl.open_in_active("https://%s/" % host)

    def _reveal(self) -> None:
        sel = self._selected()
        if sel is None:
            return
        host, i = sel
        vault = self._vault()
        if host in vault and 0 <= i < len(vault[host]):
            entry = vault[host][i]
            QMessageBox.information(
                self, "Parola — %s" % host,
                "<p><b>Kullanıcı:</b> %s</p><p><b>Parola:</b> <code>%s</code></p>"
                % (html.escape(entry["username"]), html.escape(entry["password"])))

    def _copy(self) -> None:
        sel = self._selected()
        if sel is None:
            return
        host, i = sel
        vault = self._vault()
        if host in vault and 0 <= i < len(vault[host]):
            QApplication.clipboard().setText(vault[host][i]["password"])
            w = self.ctrl.active_window()
            if w is not None:
                w.msg("Parola panoya kopyalandı. 60 saniye içinde temizlenecek.", 4000)
            QTimer.singleShot(60000, self._clear_clipboard)

    @staticmethod
    def _clear_clipboard() -> None:
        try:
            QApplication.clipboard().clear()
        except Exception:
            pass

    def _delete(self) -> None:
        sel = self._selected()
        if sel is None:
            return
        host, i = sel
        ans = QMessageBox.question(
            self, "Parolayı sil",
            "%s için kayıtlı parola silinsin mi?" % html.escape(host),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if ans != QMessageBox.StandardButton.Yes:
            return
        self.ctrl.delete_password(host, i)
        self.reload()


# --------------------------------------------------------------------------- #
#  Ayarlar / veri temizleme / sekme arama
# --------------------------------------------------------------------------- #
class SettingsDialog(QDialog):
    def __init__(self, ctrl: "Controller"):
        super().__init__(None)
        self.ctrl = ctrl
        s = ctrl.settings
        self.setWindowTitle("Ayarlar")
        self.setMinimumWidth(560)
        root = QVBoxLayout(self)
        tabs = QTabWidget()
        root.addWidget(tabs)

        general = QWidget()
        f = QFormLayout(general)
        self.startup = QComboBox()
        for label, data in (("Önceki oturumu geri yükle", "restore"),
                            ("Yeni sekme sayfasını aç", "newtab"),
                            ("Ana sayfayı aç", "home")):
            self.startup.addItem(label, data)
        self.startup.setCurrentIndex(max(0, self.startup.findData(s.get("startup"))))
        self.home = QLineEdit(s.get("home_page"))
        self.engine = QComboBox()
        self.engine.addItems(list(SEARCH_ENGINES) + [CUSTOM_ENGINE])
        self.engine.setCurrentText(s.get("search_engine"))
        self.custom = QLineEdit(s.get("custom_search"))
        self.custom.setPlaceholderText("https://site.com/ara?q=%s")
        self.custom.setEnabled(self.engine.currentText() == CUSTOM_ENGINE)
        self.engine.currentTextChanged.connect(lambda t: self.custom.setEnabled(t == CUSTOM_ENGINE))
        self.zoom = QComboBox()
        for pct in (75, 80, 90, 100, 110, 125, 150, 175, 200):
            self.zoom.addItem("%d%%" % pct, pct)
        self.zoom.setCurrentIndex(max(0, self.zoom.findData(s.get("default_zoom"))))
        f.addRow("Açılışta", self.startup)
        f.addRow("Ana sayfa", self.home)
        f.addRow("Arama motoru", self.engine)
        f.addRow("Özel arama adresi (%s = sorgu)", self.custom)
        f.addRow("Varsayılan yakınlaştırma", self.zoom)
        b_import = QPushButton("Başka tarayıcıdan içe aktar…")
        b_import.clicked.connect(lambda: self.ctrl.show_import())
        f.addRow(b_import)
        tabs.addTab(general, "Genel")

        look = QWidget()
        f2 = QFormLayout(look)
        self.theme = QComboBox()
        for label, data in (("Sistem", "system"), ("Açık", "light"), ("Koyu", "dark")):
            self.theme.addItem(label, data)
        self.theme.setCurrentIndex(max(0, self.theme.findData(s.get("theme"))))
        self.bm_bar = QCheckBox("Yer imleri çubuğunu göster")
        self.bm_bar.setChecked(s.get("show_bookmarks_bar"))
        self.dark_web = QCheckBox("Web sayfalarını zorla koyu yap (deneysel)")
        self.dark_web.setChecked(s.get("force_dark_web"))
        self.smooth = QCheckBox("Yumuşak kaydırma")
        self.smooth.setChecked(s.get("smooth_scroll"))
        f2.addRow("Tema", self.theme)
        f2.addRow(self.bm_bar)
        f2.addRow(self.dark_web)
        f2.addRow(self.smooth)
        tabs.addTab(look, "Görünüm")

        priv = QWidget()
        f3 = QFormLayout(priv)
        self.adblock = QCheckBox("Reklam ve izleyicileri engelle")
        self.adblock.setChecked(s.get("adblock"))
        self.dnt = QCheckBox("“Takip edilmeyi reddet” (DNT/GPC) sinyali gönder")
        self.dnt.setChecked(s.get("dnt"))
        self.js = QCheckBox("JavaScript'i etkinleştir")
        self.js.setChecked(s.get("javascript"))
        b_reset = QPushButton("Site izinlerini ve yakınlaştırmaları sıfırla")
        b_reset.clicked.connect(self._reset_sites)
        b_clear = QPushButton("Tarama verilerini temizle…")
        b_clear.clicked.connect(lambda: ClearDataDialog(self.ctrl, self).exec())
        f3.addRow(self.adblock)
        f3.addRow(self.dnt)
        f3.addRow(self.js)
        f3.addRow(b_reset)
        f3.addRow(b_clear)
        tabs.addTab(priv, "Gizlilik")

        pw = QWidget()
        f5 = QFormLayout(pw)
        self.pw_enabled = QCheckBox("Parola yöneticisini etkinleştir")
        self.pw_enabled.setChecked(bool(s.get("password_manager_enabled")))
        self.pw_autofill = QCheckBox("Kayıtlı parolaları giriş formlarına otomatik doldur")
        self.pw_autofill.setChecked(bool(s.get("password_autofill")))
        b_vault = QPushButton("Parola kasasını yönet…")
        b_vault.clicked.connect(lambda: self.ctrl.show_passwords())
        f5.addRow(self.pw_enabled)
        f5.addRow(self.pw_autofill)
        f5.addRow(b_vault)
        tabs.addTab(pw, "Parolalar")

        dl = QWidget()
        f4 = QFormLayout(dl)
        self.dl_dir = QLineEdit(s.get("download_dir") or ctrl.download_dir())
        b_browse = QPushButton("Gözat…")
        b_browse.clicked.connect(self._browse)
        row = QHBoxLayout()
        row.addWidget(self.dl_dir, 1)
        row.addWidget(b_browse)
        self.dl_ask = QCheckBox("Her indirmede nereye kaydedileceğini sor")
        self.dl_ask.setChecked(s.get("download_ask"))
        self.pdf = QCheckBox("Yerleşik PDF görüntüleyiciyi kullan")
        self.pdf.setChecked(s.get("pdf_viewer"))
        f4.addRow("İndirme klasörü", row)
        f4.addRow(self.dl_ask)
        f4.addRow(self.pdf)
        tabs.addTab(dl, "İndirmeler")

        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        box.accepted.connect(self._save)
        box.rejected.connect(self.reject)
        root.addWidget(box)

    def _browse(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "İndirme klasörü", self.dl_dir.text())
        if path:
            self.dl_dir.setText(path)

    def _reset_sites(self) -> None:
        self.ctrl.settings.set("permissions", {}, save=False)
        self.ctrl.settings.set("site_zoom", {})
        QMessageBox.information(self, "Sıfırlandı", "Site izinleri ve yakınlaştırma düzeyleri sıfırlandı.")

    def _save(self) -> None:
        s = self.ctrl.settings
        if self.engine.currentText() == CUSTOM_ENGINE and "%s" not in self.custom.text():
            QMessageBox.warning(self, "Arama adresi", "Özel arama adresi sorgunun yerine geçecek “%s” içermeli.")
            return
        home = self.home.text().strip()
        if home:
            url = user_input_to_url(home, self.ctrl.search_template())
            home = url.toString() if url.isValid() else s.get("home_page")
        else:
            home = NEWTAB_URL
        s.set("startup", self.startup.currentData(), save=False)
        s.set("home_page", home, save=False)
        s.set("search_engine", self.engine.currentText(), save=False)
        s.set("custom_search", self.custom.text().strip(), save=False)
        s.set("default_zoom", int(self.zoom.currentData()), save=False)
        s.set("theme", self.theme.currentData(), save=False)
        s.set("show_bookmarks_bar", self.bm_bar.isChecked(), save=False)
        s.set("force_dark_web", self.dark_web.isChecked(), save=False)
        s.set("smooth_scroll", self.smooth.isChecked(), save=False)
        s.set("adblock", self.adblock.isChecked(), save=False)
        s.set("dnt", self.dnt.isChecked(), save=False)
        s.set("javascript", self.js.isChecked(), save=False)
        s.set("download_dir", self.dl_dir.text().strip(), save=False)
        s.set("download_ask", self.dl_ask.isChecked(), save=False)
        s.set("pdf_viewer", self.pdf.isChecked(), save=False)
        s.set("password_manager_enabled", self.pw_enabled.isChecked(), save=False)
        s.set("password_autofill", self.pw_autofill.isChecked(), save=False)
        s.save()
        self.ctrl.apply_settings()
        self.accept()


class ClearDataDialog(QDialog):
    def __init__(self, ctrl: "Controller", parent=None):
        super().__init__(parent)
        self.ctrl = ctrl
        self.setWindowTitle("Tarama verilerini temizle")
        lay = QVBoxLayout(self)
        self.c_hist = QCheckBox("Tarama geçmişi")
        self.c_cookies = QCheckBox("Çerezler ve site verileri (tamamlanması için yeniden başlatma gerekir)")
        self.c_cache = QCheckBox("Önbelleğe alınmış dosyalar")
        self.c_dl = QCheckBox("İndirme listesi")
        self.c_perm = QCheckBox("Site izinleri ve yakınlaştırma düzeyleri")
        self.c_pw = QCheckBox("Kayıtlı parolalar")
        for cb in (self.c_hist, self.c_cookies, self.c_cache, self.c_dl, self.c_perm, self.c_pw):
            cb.setChecked(True)
            lay.addWidget(cb)
        note = QLabel("İndirilen dosyalar silinmez. İşlem geri alınamaz.")
        note.setWordWrap(True)
        lay.addWidget(note)
        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        box.button(QDialogButtonBox.StandardButton.Ok).setText("Temizle")
        box.button(QDialogButtonBox.StandardButton.Cancel).setText("Vazgeç")
        box.accepted.connect(self._apply)
        box.rejected.connect(self.reject)
        lay.addWidget(box)

    def _apply(self) -> None:
        self.ctrl.clear_data(
            history=self.c_hist.isChecked(),
            cookies=self.c_cookies.isChecked(),
            cache=self.c_cache.isChecked(),
            downloads=self.c_dl.isChecked(),
            sites=self.c_perm.isChecked(),
            passwords=self.c_pw.isChecked(),
        )
        self.accept()


class TabSearchDialog(QDialog):
    def __init__(self, win: "BrowserWindow"):
        super().__init__(win)
        self.win = win
        self.setWindowTitle("Sekmelerde ara")
        self.resize(560, 440)
        lay = QVBoxLayout(self)
        self.edit = QLineEdit()
        self.edit.setPlaceholderText("Sekme başlığı veya adres yazın…")
        self.list = QListWidget()
        lay.addWidget(self.edit)
        lay.addWidget(self.list, 1)
        self.edit.textChanged.connect(self._populate)
        self.edit.returnPressed.connect(self._activate)
        self.list.itemActivated.connect(lambda _i: self._activate())
        self._populate()

    def _populate(self, *_args) -> None:
        q = self.edit.text().strip().lower()
        self.list.clear()
        for i, tab in enumerate(self.win.tabs):
            title, url = tab.display_title(), tab.url_string()
            if q and q not in title.lower() and q not in url.lower():
                continue
            item = QListWidgetItem("%s%s\n%s" % ("📌 " if tab.pinned else "", elide(title, 70), elide(url, 90)))
            item.setData(Qt.ItemDataRole.UserRole, i)
            self.list.addItem(item)
        if self.list.count():
            self.list.setCurrentRow(0)

    def keyPressEvent(self, event):  # noqa: N802
        if event.key() in (Qt.Key.Key_Down, Qt.Key.Key_Up):
            step = 1 if event.key() == Qt.Key.Key_Down else -1
            row = max(0, min(self.list.count() - 1, self.list.currentRow() + step))
            self.list.setCurrentRow(row)
            return
        super().keyPressEvent(event)

    def _activate(self) -> None:
        item = self.list.currentItem()
        if item is not None:
            self.win.activate_tab_index(item.data(Qt.ItemDataRole.UserRole))
            self.accept()


# --------------------------------------------------------------------------- #
#  Diğer tarayıcılardan içe aktarma
# --------------------------------------------------------------------------- #
WEBKIT_EPOCH_DELTA = 11644473600
IMPORT_HISTORY_LIMIT = 20000


def _clean_ts(value) -> float:
    now = time.time()
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return now
    return ts if 0 < ts <= now + 86400 else now


def _webkit_ts(value) -> float:
    try:
        return _clean_ts(int(value) / 1e6 - WEBKIT_EPOCH_DELTA)
    except (TypeError, ValueError):
        return time.time()


def _unix_us_ts(value) -> float:
    try:
        return _clean_ts(int(value) / 1e6)
    except (TypeError, ValueError):
        return time.time()


def detect_browser_sources() -> list:
    home = Path.home()
    env = os.environ
    chromium, direct, firefox = [], [], []
    if sys.platform.startswith("win"):
        local = Path(env.get("LOCALAPPDATA", str(home / "AppData" / "Local")))
        roaming = Path(env.get("APPDATA", str(home / "AppData" / "Roaming")))
        chromium = [("Google Chrome", local / "Google/Chrome/User Data"),
                    ("Microsoft Edge", local / "Microsoft/Edge/User Data"),
                    ("Brave", local / "BraveSoftware/Brave-Browser/User Data"),
                    ("Vivaldi", local / "Vivaldi/User Data"),
                    ("Chromium", local / "Chromium/User Data")]
        direct = [("Opera", roaming / "Opera Software/Opera Stable"),
                  ("Opera GX", roaming / "Opera Software/Opera GX Stable")]
        firefox = [("Firefox", roaming / "Mozilla/Firefox/Profiles")]
    elif sys.platform == "darwin":
        support = home / "Library" / "Application Support"
        chromium = [("Google Chrome", support / "Google/Chrome"),
                    ("Microsoft Edge", support / "Microsoft Edge"),
                    ("Brave", support / "BraveSoftware/Brave-Browser"),
                    ("Vivaldi", support / "Vivaldi"),
                    ("Chromium", support / "Chromium")]
        direct = [("Opera", support / "com.operasoftware.Opera")]
        firefox = [("Firefox", support / "Firefox/Profiles")]
    else:
        cfg = Path(env.get("XDG_CONFIG_HOME", str(home / ".config")))
        chromium = [("Google Chrome", cfg / "google-chrome"),
                    ("Chromium", cfg / "chromium"),
                    ("Chromium (Snap)", home / "snap/chromium/common/chromium"),
                    ("Microsoft Edge", cfg / "microsoft-edge"),
                    ("Brave", cfg / "BraveSoftware/Brave-Browser"),
                    ("Vivaldi", cfg / "vivaldi"),
                    ("Google Chrome (Flatpak)", home / ".var/app/com.google.Chrome/config/google-chrome")]
        direct = [("Opera", cfg / "opera")]
        firefox = [("Firefox", home / ".mozilla/firefox"),
                   ("Firefox (Snap)", home / "snap/firefox/common/.mozilla/firefox"),
                   ("Firefox (Flatpak)", home / ".var/app/org.mozilla.firefox/.mozilla/firefox")]

    found: list = []

    def has_chromium_data(d: Path) -> bool:
        return (d / "Bookmarks").is_file() or (d / "History").is_file()

    for name, base in chromium:
        try:
            if not base.is_dir():
                continue
            names = {}
            try:
                state = json.loads((base / "Local State").read_text("utf-8"))
                for key, info in (state.get("profile", {}).get("info_cache", {}) or {}).items():
                    names[key] = info.get("name", key)
            except (OSError, ValueError, AttributeError):
                pass
            for d in sorted(base.iterdir()):
                if d.is_dir() and (d.name == "Default" or d.name.startswith("Profile ")) and has_chromium_data(d):
                    found.append(("%s — %s" % (name, names.get(d.name, d.name)), "chromium", d))
        except OSError:
            continue
    for name, base in direct:
        try:
            if base.is_dir() and has_chromium_data(base):
                found.append((name, "chromium", base))
        except OSError:
            continue
    for name, base in firefox:
        try:
            if not base.is_dir():
                continue
            for d in sorted(base.iterdir()):
                if d.is_dir() and (d / "places.sqlite").is_file():
                    label = d.name.split(".", 1)[1] if "." in d.name else d.name
                    found.append(("%s — %s" % (name, label), "firefox", d))
        except OSError:
            continue
    return found


def _copy_db(src: Path, tmp: Path) -> Path:
    dst = tmp / src.name
    shutil.copy2(src, dst)
    wal = src.with_name(src.name + "-wal")
    if wal.is_file():
        try:
            shutil.copy2(wal, tmp / wal.name)
        except OSError:
            pass
    return dst


def read_chromium(profile: Path, want_bm: bool, want_hist: bool, tmp: Path):
    bookmarks: list = []
    history: list = []
    if want_bm and (profile / "Bookmarks").is_file():
        data = json.loads((profile / "Bookmarks").read_text("utf-8"))

        def walk(node) -> None:
            if not isinstance(node, dict):
                return
            if node.get("type") == "url" and is_web_url(str(node.get("url", ""))):
                url = node["url"]
                bookmarks.append((url, node.get("name") or url, _webkit_ts(node.get("date_added"))))
            for child in node.get("children") or []:
                walk(child)

        for root in (data.get("roots") or {}).values():
            walk(root)
    if want_hist and (profile / "History").is_file():
        conn = sqlite3.connect(str(_copy_db(profile / "History", tmp)))
        try:
            try:
                cur = conn.execute("SELECT url, title, visit_count, last_visit_time FROM urls "
                                   "WHERE hidden=0 ORDER BY last_visit_time DESC LIMIT ?",
                                   (IMPORT_HISTORY_LIMIT,))
            except sqlite3.OperationalError:
                cur = conn.execute("SELECT url, title, visit_count, last_visit_time FROM urls "
                                   "ORDER BY last_visit_time DESC LIMIT ?", (IMPORT_HISTORY_LIMIT,))
            for url, title, count, last in cur:
                if url and is_web_url(url):
                    history.append((url, title or "", max(1, int(count or 1)), _webkit_ts(last)))
        finally:
            conn.close()
    return bookmarks, history


def read_firefox(profile: Path, want_bm: bool, want_hist: bool, tmp: Path):
    bookmarks: list = []
    history: list = []
    conn = sqlite3.connect(str(_copy_db(profile / "places.sqlite", tmp)))
    try:
        if want_bm:
            for url, title, added in conn.execute(
                    "SELECT p.url, COALESCE(NULLIF(b.title,''), p.title, p.url), b.dateAdded "
                    "FROM moz_bookmarks b JOIN moz_places p ON b.fk = p.id "
                    "WHERE b.type = 1 AND p.url LIKE 'http%'"):
                if url and is_web_url(url):
                    bookmarks.append((url, title or url, _unix_us_ts(added)))
        if want_hist:
            for url, title, count, last in conn.execute(
                    "SELECT url, title, visit_count, last_visit_date FROM moz_places "
                    "WHERE visit_count > 0 AND last_visit_date IS NOT NULL AND url LIKE 'http%' "
                    "ORDER BY last_visit_date DESC LIMIT ?", (IMPORT_HISTORY_LIMIT,)):
                if url and is_web_url(url):
                    history.append((url, title or "", max(1, int(count or 1)), _unix_us_ts(last)))
    finally:
        conn.close()
    return bookmarks, history


class ImportDialog(QDialog):
    def __init__(self, ctrl: "Controller", parent=None):
        super().__init__(parent)
        self.ctrl = ctrl
        self.setWindowTitle("Başka bir tarayıcıdan içe aktar")
        self.setMinimumWidth(540)
        lay = QVBoxLayout(self)
        self.sources = detect_browser_sources()
        intro = QLabel("Aktarılacak tarayıcıyı ve profili seçin:" if self.sources else
                       "Desteklenen bir tarayıcı bulunamadı (Chrome, Edge, Brave, Opera, Vivaldi, Firefox). "
                       "Yer imlerinizi HTML dosyası olarak dışa aktardıysanız aşağıdan içe aktarabilirsiniz.")
        intro.setWordWrap(True)
        lay.addWidget(intro)
        self.combo = QComboBox()
        for label, kind, path in self.sources:
            self.combo.addItem(label, (kind, path))
        lay.addWidget(self.combo)
        self.c_bm = QCheckBox("Yer imleri")
        self.c_hist = QCheckBox("Geçmiş (en son %d kayıt)" % IMPORT_HISTORY_LIMIT)
        self.c_bm.setChecked(True)
        self.c_hist.setChecked(True)
        lay.addWidget(self.c_bm)
        lay.addWidget(self.c_hist)
        note = QLabel("Not: Parolalar ve çerezler tarayıcılar tarafından şifreli saklandığı için "
                      "aktarılmaz. Kaynak tarayıcı açıksa dosyalar kilitli olabilir; sorun olursa "
                      "onu kapatıp tekrar deneyin. Mevcut verileriniz silinmez, aynı adresler birleştirilir.")
        note.setWordWrap(True)
        lay.addWidget(note)
        row = QHBoxLayout()
        b_html = QPushButton("HTML dosyasından yer imi aktar…")
        b_html.clicked.connect(self._import_html)
        row.addWidget(b_html)
        row.addStretch(1)
        lay.addLayout(row)
        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        box.button(QDialogButtonBox.StandardButton.Ok).setText("İçe aktar")
        box.button(QDialogButtonBox.StandardButton.Cancel).setText("Kapat")
        box.button(QDialogButtonBox.StandardButton.Ok).setEnabled(bool(self.sources))
        box.accepted.connect(self._run)
        box.rejected.connect(self.reject)
        lay.addWidget(box)

    def _run(self) -> None:
        data = self.combo.currentData()
        if data is None:
            return
        if not (self.c_bm.isChecked() or self.c_hist.isChecked()):
            QMessageBox.information(self, "İçe aktar", "Aktarılacak en az bir öğe seçin.")
            return
        kind, path = data
        error = None
        bookmarks, history = [], []
        tmp = Path(tempfile.mkdtemp(prefix="yinegelos-import-"))
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            reader = read_firefox if kind == "firefox" else read_chromium
            bookmarks, history = reader(path, self.c_bm.isChecked(), self.c_hist.isChecked(), tmp)
        except PermissionError:
            error = "Dosyalar kullanımda. Kaynak tarayıcıyı tamamen kapatıp tekrar deneyin."
        except (OSError, sqlite3.Error, ValueError) as exc:
            error = "İçe aktarma başarısız oldu: %s" % exc
        finally:
            QApplication.restoreOverrideCursor()
            shutil.rmtree(tmp, ignore_errors=True)
        if error:
            QMessageBox.warning(self, "İçe aktar", error)
            return
        n_bm = self.ctrl.db.import_bookmark_rows(bookmarks)
        n_hist = self.ctrl.db.import_history_rows(history)
        self._refresh_views()
        QMessageBox.information(self, "İçe aktarma tamamlandı",
                                "%d yer imi ve %d geçmiş kaydı eklendi." % (n_bm, n_hist))
        self.accept()

    def _import_html(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Yer imi dosyası seç", "",
                                              "HTML yer imi dosyası (*.html *.htm);;Tüm dosyalar (*)")
        if not path:
            return
        try:
            text = Path(path).read_text("utf-8", errors="replace")
        except OSError as exc:
            QMessageBox.warning(self, "Hata", "Dosya okunamadı: %s" % exc)
            return
        count = self.ctrl.db.import_bookmarks_html(text)
        self._refresh_views()
        QMessageBox.information(self, "İçe aktarma tamamlandı", "%d yer imi eklendi." % count)

    def _refresh_views(self) -> None:
        self.ctrl.bookmarks_changed()
        self.ctrl.request_suggestions_refresh()
        if self.ctrl.history_dialog is not None and self.ctrl.history_dialog.isVisible():
            self.ctrl.history_dialog.reload()


# --------------------------------------------------------------------------- #
#  Ana pencere
# --------------------------------------------------------------------------- #
class BrowserWindow(QMainWindow):
    def __init__(self, ctrl: "Controller", private: bool, profile: QWebEngineProfile):
        super().__init__()
        self.ctrl = ctrl
        self.private = private
        self.profile = profile
        self._tabs: list[BrowserTab] = []
        self._current: BrowserTab | None = None
        self.closed_tabs: list[tuple] = []
        self._closing = False
        self._restoring = False
        self._prog_move = False
        self._fs_tab: BrowserTab | None = None
        self._fs_prev = None
        self._pre_fs_max = False
        self._find_tab: BrowserTab | None = None
        self._addr_key = None
        self._printer = None

        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle(APP_FULL)
        self.setMinimumSize(640, 420)
        self.resize(1280, 820)
        self._build_actions()
        self._build_ui()
        self._build_menu()
        self.apply_theme()
        self.refresh_bookmarks_bar()

    @property
    def tabs(self) -> list:
        return list(self._tabs)

    def tab_count(self) -> int:
        return len(self._tabs)

    def current_tab(self) -> "BrowserTab | None":
        return self._current

    def icon(self, name: str, key: str = "text", size: int = 20, fill: bool = False) -> QIcon:
        return svg_icon(name, self.ctrl.colors[key], size, fill)

    def msg(self, text: str, ms: int = 4000) -> None:
        self.statusBar().showMessage(text, ms)

    def _act(self, text: str, slot, shortcut=None) -> QAction:
        action = QAction(text, self)
        if shortcut:
            seqs = shortcut if isinstance(shortcut, (list, tuple)) else [shortcut]
            action.setShortcuts([QKeySequence(s) for s in seqs])
            action.setShortcutContext(Qt.ShortcutContext.WindowShortcut)
        action.triggered.connect(lambda _checked=False: slot())
        self.addAction(action)
        return action

    def _build_actions(self) -> None:
        a = self._act
        self.act_new_tab = a("Yeni sekme", lambda: self.add_tab(), "Ctrl+T")
        self.act_new_window = a("Yeni pencere", lambda: self.ctrl.new_window(), "Ctrl+N")
        self.act_new_private = a("Yeni gizli pencere", lambda: self.ctrl.new_window(private=True),
                                 "Ctrl+Shift+N")
        self.act_close_tab = a("Sekmeyi kapat", self.close_current_tab, ["Ctrl+W", "Ctrl+F4"])
        self.act_reopen = a("Kapatılan sekmeyi yeniden aç", self.reopen_closed_tab, "Ctrl+Shift+T")
        self.act_open_file = a("Dosya aç…", self.open_file, "Ctrl+O")
        self.act_save_page = a("Sayfayı kaydet…", self.save_page, "Ctrl+S")
        self.act_print = a("Yazdır…", self.print_page, "Ctrl+P")
        self.act_pdf = a("PDF olarak kaydet…", self.save_pdf)
        self.act_find = a("Sayfada bul", self.open_find, "Ctrl+F")
        self.act_find_next = a("Sonrakini bul", lambda: self.run_find(False), ["F3", "Ctrl+G"])
        self.act_find_prev = a("Öncekini bul", lambda: self.run_find(True), ["Shift+F3", "Ctrl+Shift+G"])
        self.act_zoom_in = a("Yakınlaştır", lambda: self.zoom_step(1), ["Ctrl++", "Ctrl+="])
        self.act_zoom_out = a("Uzaklaştır", lambda: self.zoom_step(-1), "Ctrl+-")
        self.act_zoom_reset = a("Yakınlaştırmayı sıfırla", self.reset_zoom, "Ctrl+0")
        self.act_back = a("Geri", self.go_back, "Alt+Left")
        self.act_forward = a("İleri", self.go_forward, "Alt+Right")
        self.act_reload = a("Yenile", self.reload, ["F5", "Ctrl+R"])
        self.act_hard_reload = a("Önbelleği atlayarak yenile", self.hard_reload, ["Ctrl+F5", "Ctrl+Shift+R"])
        self.act_reload_stop = a("Yenile", self.reload_or_stop)
        self.act_home = a("Ana sayfa", self.go_home, "Alt+Home")
        self.act_focus_addr = a("Adres çubuğuna odaklan", self.focus_address, ["Ctrl+L", "Alt+D", "F6"])
        self.act_bookmark = a("Bu sayfayı yer imlerine ekle", self.toggle_bookmark, "Ctrl+D")
        self.act_bookmarks = a("Yer imlerini yönet", self.ctrl.show_bookmarks, "Ctrl+Shift+O")
        self.act_bm_bar = QAction("Yer imleri çubuğunu göster", self)
        self.act_bm_bar.setCheckable(True)
        self.act_bm_bar.setChecked(bool(self.ctrl.settings.get("show_bookmarks_bar")))
        self.act_bm_bar.setShortcut(QKeySequence("Ctrl+Shift+B"))
        self.act_bm_bar.toggled.connect(self.set_bookmarks_bar_visible)
        self.addAction(self.act_bm_bar)
        self.act_history = a("Geçmiş", self.ctrl.show_history, "Ctrl+H")
        self.act_downloads = a("İndirilenler", self.ctrl.show_downloads, "Ctrl+J")
        self.act_clear = a("Tarama verilerini temizle…", self.clear_data_dialog, "Ctrl+Shift+Del")
        self.act_import = a("Başka tarayıcıdan içe aktar…", self.ctrl.show_import)
        self.act_source = a("Sayfa kaynağını görüntüle", self.view_source, "Ctrl+U")
        self.act_devtools = a("Geliştirici araçları", self.toggle_devtools, ["F12", "Ctrl+Shift+I"])
        self.act_reader = a("Okuma modu", self.toggle_reader, "Ctrl+Alt+R")
        self.act_translate = a("Sayfayı çevir", self.translate_page)
        self.act_copy_url = a("Adresi kopyala", self.copy_url, "Ctrl+Shift+C")
        self.act_fullscreen = a("Tam ekran", self.toggle_fullscreen, "F11")
        self.act_settings = a("Ayarlar", self.ctrl.show_settings, "Ctrl+,")
        self.act_tab_search = a("Sekmelerde ara…", self.open_tab_search, "Ctrl+Shift+A")
        self.act_about = a("%s hakkında" % APP_NAME, self.show_about)
        self.act_quit = a("Çık", self.ctrl.quit_app, "Ctrl+Q")
        self.act_passwords = a("Parola Yöneticisi", self.ctrl.show_passwords, "Ctrl+Shift+P")

        def bind(seq: str, fn) -> None:
            sc = QShortcut(QKeySequence(seq), self)
            sc.activated.connect(fn)

        bind("Ctrl+Tab", lambda: self.cycle_tab(1))
        bind("Ctrl+Shift+Tab", lambda: self.cycle_tab(-1))
        bind("Ctrl+PgDown", lambda: self.cycle_tab(1))
        bind("Ctrl+PgUp", lambda: self.cycle_tab(-1))
        for n in range(1, 9):
            bind("Ctrl+%d" % n, lambda n=n: self.activate_tab_index(n - 1))
        bind("Ctrl+9", lambda: self.activate_tab_index(len(self._tabs) - 1))

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.tab_strip = QWidget()
        self.tab_strip.setObjectName("tabStrip")
        strip = QHBoxLayout(self.tab_strip)
        strip.setContentsMargins(8, 0, 8, 0)
        strip.setSpacing(2)
        self.tab_bar = TabBar()
        self.btn_newtab = QToolButton()
        self.btn_newtab.setToolTip("Yeni sekme (Ctrl+T)")
        self.btn_tablist = QToolButton()
        self.btn_tablist.setToolTip("Sekmelerde ara (Ctrl+Shift+A)")
        strip.addWidget(self.tab_bar)
        strip.addWidget(self.btn_newtab)
        strip.addStretch(1)
        strip.addWidget(self.btn_tablist)
        root.addWidget(self.tab_strip)

        self.toolbar = QToolBar()
        self.toolbar.setMovable(False)
        self.toolbar.setFloatable(False)
        self.toolbar.setIconSize(QSize(20, 20))
        self.toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonIconOnly)
        self.toolbar.setContextMenuPolicy(Qt.ContextMenuPolicy.PreventContextMenu)
        for act, tip in ((self.act_back, "Geri (Alt+←) — sağ tık: geçmiş"),
                         (self.act_forward, "İleri (Alt+→) — sağ tık: geçmiş"),
                         (self.act_reload_stop, "Yenile (F5)"),
                         (self.act_home, "Ana sayfa (Alt+Home)")):
            act.setToolTip(tip)
            self.toolbar.addAction(act)
        self.address = AddressBar()
        self.address.setPlaceholderText("Ara veya adres gir")
        self.address.setMinimumWidth(240)
        self.address.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.address.setClearButtonEnabled(False)
        self.sec_action = self.address.addAction(QIcon(), QLineEdit.ActionPosition.LeadingPosition)
        self.star_action = self.address.addAction(QIcon(), QLineEdit.ActionPosition.TrailingPosition)
        self.star_action.setToolTip("Bu sayfayı yer imlerine ekle (Ctrl+D)")
        self.star_action.triggered.connect(lambda _c=False: self.toggle_bookmark())
        self.completer = QCompleter(self.ctrl.suggestions, self)
        self.completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.completer.setFilterMode(Qt.MatchFlag.MatchContains)
        self.completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        self.completer.setMaxVisibleItems(8)
        self.address.setCompleter(self.completer)
        self.completer.activated[str].connect(self._on_completion)
        self.address.returnPressed.connect(lambda: self.on_address_entered(False))
        self.address.alt_enter.connect(lambda: self.on_address_entered(True))
        self.address.escaped.connect(self.revert_address)
        self.toolbar.addWidget(self.address)
        self.toolbar.addAction(self.act_downloads)
        if self.private:
            badge = QLabel("Gizli")
            badge.setObjectName("privateBadge")
            self.toolbar.addWidget(badge)
        self.btn_menu = QToolButton()
        self.btn_menu.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.btn_menu.setToolTip("Menü")
        self.toolbar.addWidget(self.btn_menu)
        root.addWidget(self.toolbar)

        for act, back in ((self.act_back, True), (self.act_forward, False)):
            btn = self.toolbar.widgetForAction(act)
            if btn is not None:
                btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
                btn.customContextMenuRequested.connect(
                    lambda pos, b=btn, bk=back: self.show_nav_history_menu(bk, b, pos))

        self.progress = QProgressBar()
        self.progress.setObjectName("progress")
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 100)
        self.progress.setFixedHeight(2)
        root.addWidget(self.progress)

        self.bookmarks_bar = QToolBar()
        self.bookmarks_bar.setObjectName("bookmarksBar")
        self.bookmarks_bar.setMovable(False)
        self.bookmarks_bar.setIconSize(QSize(14, 14))
        self.bookmarks_bar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.bookmarks_bar.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.bookmarks_bar.customContextMenuRequested.connect(self.bookmarks_bar_menu)
        self.bookmarks_bar.setVisible(bool(self.ctrl.settings.get("show_bookmarks_bar")))
        root.addWidget(self.bookmarks_bar)

        self.stack = QStackedWidget()
        root.addWidget(self.stack, 1)

        self.find_bar = FindBar()
        self.find_bar.hide()
        self.find_bar.search.connect(self.run_find)
        self.find_bar.closed.connect(self.close_find)
        root.addWidget(self.find_bar)

        sb = self.statusBar()
        sb.setSizeGripEnabled(False)
        self.zoom_label = QLabel("")
        self.shield_label = QLabel("")
        sb.addPermanentWidget(self.shield_label)
        sb.addPermanentWidget(self.zoom_label)
        self._shield_timer = QTimer(self)
        self._shield_timer.setInterval(1000)
        self._shield_timer.timeout.connect(self._update_shield)
        self._shield_timer.start()

        self.tab_bar.currentChanged.connect(self.on_current_changed)
        self.tab_bar.tabCloseRequested.connect(self._on_tab_close_requested)
        self.tab_bar.tabMoved.connect(self.on_tab_moved)
        self.tab_bar.new_tab_requested.connect(lambda: self.add_tab())
        self.tab_bar.context_requested.connect(self.show_tab_menu)
        self.btn_newtab.clicked.connect(lambda: self.add_tab())
        self.btn_tablist.clicked.connect(self.open_tab_search)

    def _build_menu(self) -> None:
        m = QMenu(self)
        self.menu = m
        m.addAction(self.act_new_tab)
        m.addAction(self.act_new_window)
        m.addAction(self.act_new_private)
        m.addSeparator()
        self.bm_menu = QMenu("Yer imleri", m)
        self.bm_menu.aboutToShow.connect(self._fill_bookmarks_menu)
        m.addMenu(self.bm_menu)
        m.addAction(self.act_history)
        m.addAction(self.act_downloads)
        m.addAction(self.act_passwords)
        m.addSeparator()
        zoom = QMenu("Yakınlaştırma", m)
        zoom.addAction(self.act_zoom_in)
        zoom.addAction(self.act_zoom_out)
        zoom.addAction(self.act_zoom_reset)
        m.addMenu(zoom)
        m.addAction(self.act_find)
        m.addAction(self.act_print)
        m.addAction(self.act_pdf)
        m.addAction(self.act_save_page)
        m.addAction(self.act_open_file)
        tools = QMenu("Diğer araçlar", m)
        for act in (self.act_reader, self.act_translate, self.act_copy_url, self.act_source,
                    self.act_devtools, self.act_hard_reload, self.act_tab_search, self.act_reopen):
            tools.addAction(act)
        m.addMenu(tools)
        m.addAction(self.act_fullscreen)
        m.addSeparator()
        m.addAction(self.act_import)
        m.addAction(self.act_clear)
        m.addAction(self.act_settings)
        m.addAction(self.act_about)
        m.addSeparator()
        m.addAction(self.act_quit)
        self.btn_menu.setMenu(m)

    def apply_icons(self) -> None:
        c = self.ctrl.colors
        t = c["text"]
        self.act_back.setIcon(svg_icon("arrow-left", t))
        self.act_forward.setIcon(svg_icon("arrow-right", t))
        self.act_reload_stop.setIcon(svg_icon("rotate-cw", t))
        self.act_home.setIcon(svg_icon("home", t))
        self.act_downloads.setIcon(svg_icon("download", t))
        self.act_passwords.setIcon(svg_icon("key", t))
        self.btn_menu.setIcon(svg_icon("menu", t))
        self.btn_newtab.setIcon(svg_icon("plus", t, 18))
        self.btn_tablist.setIcon(svg_icon("chevron-down", t, 18))
        self.find_bar.set_icons(t)

    def apply_theme(self) -> None:
        self.apply_icons()
        c = self.ctrl.colors
        for tab in self._tabs:
            tab.page.setBackgroundColor(QColor(c["page_bg"]))
            self.update_tab_ui(tab)
            if tab.is_newtab() and not tab.pending_url:
                tab.view.reload()
        self.refresh_bookmarks_bar()
        if self._current is not None:
            self.refresh_chrome(self._current, force=True)

    def on_settings_changed(self) -> None:
        visible = bool(self.ctrl.settings.get("show_bookmarks_bar"))
        self.act_bm_bar.blockSignals(True)
        self.act_bm_bar.setChecked(visible)
        self.act_bm_bar.blockSignals(False)
        if self._fs_tab is None:
            self.bookmarks_bar.setVisible(visible)
        for tab in self._tabs:
            self.ctrl.apply_zoom_to_tab(tab)

    def _update_shield(self) -> None:
        n = self.ctrl.blocked_count
        self.shield_label.setText("Engellenen: %d  " % n if n else "")

    def add_tab(self, url=None, activate: bool = True, index: int | None = None,
                load: bool = True, pinned: bool = False, lazy: bool = False,
                title: str = "") -> "BrowserTab | None":
        if self._closing:
            return None
        if url is None and load:
            url = NEWTAB_URL
        qurl = None
        if url:
            qurl = url if isinstance(url, QUrl) else QUrl(url)
        tab = BrowserTab(self)
        tab.pinned = pinned
        n_pinned = sum(1 for t in self._tabs if t.pinned)
        if index is None:
            index = len(self._tabs)
        index = min(index, n_pinned) if pinned else max(index, n_pinned)
        index = max(0, min(index, len(self._tabs)))
        if lazy and qurl is not None:
            tab.pending_url = qurl.toString()
            tab.pending_title = title
        self._tabs.insert(index, tab)
        self.stack.addWidget(tab)
        self.tab_bar.insertTab(index, self.icon("globe", "muted"), "")
        self.tab_bar.setTabData(index, "pinned" if pinned else None)
        self._update_close_button(tab)
        self.update_tab_ui(tab)
        if activate:
            self.tab_bar.setCurrentIndex(index)
        if qurl is not None and not lazy:
            tab.load(qurl)
        if activate and qurl is not None and qurl.toString().startswith(NEWTAB_URL):
            self.focus_address()
        return tab

    def _update_close_button(self, tab: BrowserTab) -> None:
        try:
            i = self._tabs.index(tab)
            btn = self.tab_bar.tabButton(i, QTabBar.ButtonPosition.RightSide)
            if btn is not None:
                btn.setVisible(not tab.pinned)
        except ValueError:
            pass

    def create_page_for_window(self, opener: BrowserTab, wtype):
        W = QWebEnginePage.WebWindowType
        if wtype == W.WebBrowserWindow:
            win = self.ctrl.new_window(private=self.private, empty=True)
            tab = win.add_tab(load=False)
        elif wtype == W.WebBrowserBackgroundTab:
            tab = self.add_tab(load=False, activate=False, index=self._tabs.index(opener) + 1)
        else:
            tab = self.add_tab(load=False, index=self._tabs.index(opener) + 1)
        return tab.page if tab is not None else None

    def close_current_tab(self) -> None:
        if self._current is not None:
            self.close_tab(self._current)

    def _on_tab_close_requested(self, index: int) -> None:
        if 0 <= index < len(self._tabs):
            self.close_tab(self._tabs[index])

    def close_tab(self, tab: BrowserTab, remember: bool = True) -> None:
        if self._closing or tab not in self._tabs:
            return
        if len(self._tabs) == 1:
            self.close()
            return
        idx = self._tabs.index(tab)
        if remember and not self.private:
            url = tab.url_string()
            if url and not url.startswith(NEWTAB_URL) and url != "about:blank":
                self.closed_tabs.append((url, tab.display_title(), tab.pinned, idx))
                del self.closed_tabs[:-25]
        if self._fs_tab is tab:
            self.set_html_fullscreen(tab, False)
        if self._find_tab is tab:
            self._find_tab = None
            self.find_bar.hide()
        if tab is self._current:
            self._current = None
        self._tabs.pop(idx)
        self.stack.removeWidget(tab)
        self.tab_bar.removeTab(idx)
        tab.dispose()

    def close_others(self, keep: BrowserTab) -> None:
        self.activate_tab_index(self._tabs.index(keep))
        for t in list(self._tabs):
            if t is not keep and not t.pinned:
                self.close_tab(t)

    def close_right(self, tab: BrowserTab) -> None:
        idx = self._tabs.index(tab)
        for t in list(self._tabs[idx + 1:]):
            self.close_tab(t)

    def reopen_closed_tab(self) -> None:
        if not self.closed_tabs:
            self.msg("Yeniden açılacak sekme yok.")
            return
        url, _title, pinned, idx = self.closed_tabs.pop()
        self.add_tab(url, index=idx, pinned=pinned)

    def duplicate_tab(self, tab: BrowserTab) -> None:
        self.add_tab(tab.url_string(), index=self._tabs.index(tab) + 1)

    def toggle_pin(self, tab: BrowserTab) -> None:
        tab.pinned = not tab.pinned
        i = self._tabs.index(tab)
        self.tab_bar.setTabData(i, "pinned" if tab.pinned else None)
        self._normalize_pins()
        self._update_close_button(tab)
        self.update_tab_ui(tab)

    def toggle_mute(self, tab: BrowserTab) -> None:
        tab.page.setAudioMuted(not tab.page.isAudioMuted())
        self.update_tab_ui(tab)

    def reload_tab(self, tab: BrowserTab) -> None:
        if tab.pending_url:
            tab.ensure_loaded()
        else:
            tab.view.reload()

    def cycle_tab(self, step: int) -> None:
        n = len(self._tabs)
        if n > 1:
            self.tab_bar.setCurrentIndex((self.tab_bar.currentIndex() + step) % n)

    def activate_tab_index(self, i: int) -> None:
        if 0 <= i < len(self._tabs):
            self.tab_bar.setCurrentIndex(i)

    def on_tab_moved(self, src: int, dst: int) -> None:
        if self._prog_move:
            return
        if 0 <= src < len(self._tabs) and 0 <= dst < len(self._tabs):
            self._tabs.insert(dst, self._tabs.pop(src))
        if any(t.pinned for t in self._tabs):
            QTimer.singleShot(0, self._normalize_pins)

    def _normalize_pins(self) -> None:
        desired = [t for t in self._tabs if t.pinned] + [t for t in self._tabs if not t.pinned]
        self._prog_move = True
        try:
            for target, tab in enumerate(desired):
                cur = self._tabs.index(tab)
                if cur != target:
                    self.tab_bar.moveTab(cur, target)
                    self._tabs.insert(target, self._tabs.pop(cur))
        finally:
            self._prog_move = False

    def on_current_changed(self, index: int) -> None:
        if self._closing or self._restoring or index < 0 or index >= len(self._tabs):
            return
        tab = self._tabs[index]
        prev = self._current
        if prev is tab:
            self.refresh_chrome(tab)
            return
        self._current = tab
        if prev is not None:
            if self._find_tab is prev:
                self.close_find()
            if self._fs_tab is prev:
                try:
                    prev.page.triggerAction(QWebEnginePage.WebAction.ExitFullScreen)
                except Exception:
                    pass
                self.set_html_fullscreen(prev, False)
        self.stack.setCurrentWidget(tab)
        tab.ensure_loaded()
        self.refresh_chrome(tab, force=True)
        if tab.is_newtab():
            self.focus_address()
        else:
            tab.view.setFocus()

    def restore_tabs(self, items: list, current: int) -> None:
        self._restoring = True
        try:
            for it in items:
                self.add_tab(it["url"], activate=False, lazy=True, pinned=bool(it.get("pinned")),
                             title=str(it.get("title", "")))
        finally:
            self._restoring = False
        if not self._tabs:
            self.add_tab()
            return
        current = max(0, min(current, len(self._tabs) - 1))
        self._current = None
        self.tab_bar.setCurrentIndex(current)
        self.on_current_changed(current)

    def session_state(self) -> dict:
        tabs, cur = [], 0
        for t in self._tabs:
            url = t.url_string()
            if not url or url == "about:blank":
                continue
            if t is self._current:
                cur = len(tabs)
            tabs.append({"url": url, "title": t.display_title(), "pinned": t.pinned})
        return {"tabs": tabs, "current": cur}

    def _tab_icon(self, tab: BrowserTab) -> QIcon:
        if tab.pending_url:
            return self.icon("globe", "muted")
        if tab.loading:
            return self.icon("loader", "accent")
        try:
            ic = tab.view.icon()
        except RuntimeError:
            ic = QIcon()
        return ic if not ic.isNull() else self.icon("globe", "muted")

    def update_tab_ui(self, tab: BrowserTab) -> None:
        try:
            i = self._tabs.index(tab)
        except ValueError:
            return
        title = tab.display_title()
        prefix = ""
        try:
            if tab.page.isAudioMuted():
                prefix = "🔇 "
            elif tab.page.recentlyAudible():
                prefix = "🔊 "
        except RuntimeError:
            pass
        self.tab_bar.setTabText(i, "" if tab.pinned else (prefix + title).replace("&", "&&"))
        self.tab_bar.setTabToolTip(i, "<p style='white-space:pre'>%s\n%s</p>" % (
            html.escape(elide(title, 100)), html.escape(elide(tab.url_string(), 120))))
        self.tab_bar.setTabIcon(i, self._tab_icon(tab))

    def tab_updated(self, tab: BrowserTab, **_flags) -> None:
        if self._closing or tab not in self._tabs:
            return
        self.update_tab_ui(tab)
        if tab is self._current:
            self.update_address(tab)
            self.update_nav(tab)
            self.update_title()

    def refresh_chrome(self, tab: BrowserTab, force: bool = False) -> None:
        if tab is not self._current:
            return
        self.update_address(tab, force=force)
        self.update_nav(tab)
        self.update_title()
        self.update_zoom_label(tab)

    def update_title(self) -> None:
        tab = self._current
        if tab is None:
            self.setWindowTitle(APP_FULL)
            return
        suffix = " — %s%s" % (APP_NAME, " (Gizli)" if self.private else "")
        self.setWindowTitle(elide(tab.display_title(), 120) + suffix)

    def update_nav(self, tab: BrowserTab) -> None:
        if tab is not self._current:
            return
        try:
            hist = tab.view.history()
            self.act_back.setEnabled(hist.canGoBack())
            self.act_forward.setEnabled(hist.canGoForward())
        except RuntimeError:
            return
        loading = tab.loading
        self.act_reload_stop.setIcon(self.icon("x" if loading else "rotate-cw"))
        self.act_reload_stop.setToolTip("Durdur" if loading else "Yenile (F5)")
        self.progress.setValue(tab.progress if loading else 0)

    def update_address(self, tab: BrowserTab, force: bool = False) -> None:
        if tab is not self._current:
            return
        if self.address.hasFocus() and not force:
            return
        s = tab.url_string()
        text = "" if (not s or s.startswith(NEWTAB_URL) or s == "about:blank") else s
        key = (id(tab), s)
        if not force and key == self._addr_key:
            return
        self._addr_key = key
        if self.address.text() != text:
            self.address.setText(text)
            self.address.setCursorPosition(0)
        self.update_security(s)
        self.update_star(tab)

    def revert_address(self) -> None:
        if self._current is not None:
            self.update_address(self._current, force=True)
        self.address.clearFocus()
        if self._current is not None:
            self._current.view.setFocus()

    def update_security(self, url_str: str) -> None:
        scheme = QUrl(url_str).scheme()
        if scheme == "https":
            self.sec_action.setIcon(self.icon("lock", "ok", 16))
            self.sec_action.setToolTip("Bağlantı güvenli (HTTPS)")
        elif scheme == "http":
            self.sec_action.setIcon(self.icon("alert", "danger", 16))
            self.sec_action.setToolTip("Bağlantı güvenli değil (HTTP)")
        elif scheme == "file":
            self.sec_action.setIcon(self.icon("file", "muted", 16))
            self.sec_action.setToolTip("Yerel dosya")
        else:
            self.sec_action.setIcon(self.icon("search", "muted", 16))
            self.sec_action.setToolTip("")

    def update_star(self, tab: BrowserTab) -> None:
        url = tab.url_string()
        marked = is_web_url(url) and self.ctrl.db.is_bookmarked(url)
        self.star_action.setIcon(self.icon("star", "accent" if marked else "muted", 18, fill=marked))
        self.star_action.setToolTip("Yer imini kaldır (Ctrl+D)" if marked
                                    else "Bu sayfayı yer imlerine ekle (Ctrl+D)")

    def refresh_star(self) -> None:
        if self._current is not None:
            self.update_star(self._current)

    def focus_address(self) -> None:
        self.address.setFocus(Qt.FocusReason.ShortcutFocusReason)
        self.address.selectAll()

    def _on_completion(self, text: str) -> None:
        url = user_input_to_url(text, self.ctrl.search_template())
        if url.isValid() and not url.isEmpty():
            self.navigate(url)

    def on_address_entered(self, new_tab: bool) -> None:
        url = user_input_to_url(self.address.text(), self.ctrl.search_template())
        if not url.isValid() or url.isEmpty():
            return
        if new_tab:
            self.add_tab(url)
        else:
            self.navigate(url)

    def navigate(self, url: QUrl) -> None:
        tab = self._current or self.add_tab(load=False)
        if tab is None:
            return
        tab.load(url)
        tab.view.setFocus()

    def open_url(self, url: str, new_tab: bool = False) -> None:
        if new_tab or self._current is None:
            self.add_tab(url)
        else:
            self.navigate(QUrl(url))

    def go_back(self) -> None:
        if self._current:
            self._current.view.back()

    def go_forward(self) -> None:
        if self._current:
            self._current.view.forward()

    def reload(self) -> None:
        if self._current:
            self.reload_tab(self._current)

    def hard_reload(self) -> None:
        if self._current:
            self._current.ensure_loaded()
            self._current.page.triggerAction(QWebEnginePage.WebAction.ReloadAndBypassCache)

    def reload_or_stop(self) -> None:
        if self._current is None:
            return
        if self._current.loading:
            self._current.view.stop()
        else:
            self.reload()

    def go_home(self) -> None:
        home = self.ctrl.settings.get("home_page") or NEWTAB_URL
        url = user_input_to_url(home, self.ctrl.search_template())
        self.navigate(url if url.isValid() else QUrl(NEWTAB_URL))

    def show_nav_history_menu(self, back: bool, widget, pos) -> None:
        tab = self._current
        if tab is None:
            return
        hist = tab.view.history()
        items, cur = hist.items(), hist.currentItemIndex()
        entries = items[:cur][::-1][:12] if back else items[cur + 1:][:12]
        if not entries:
            return
        menu = QMenu(self)
        for it in entries:
            label = elide(it.title() or it.url().toString(), 60)
            add_menu_action(menu, label, lambda it=it: tab.view.history().goToItem(it))
        menu.exec(widget.mapToGlobal(pos))

    def toggle_bookmark(self) -> None:
        tab = self._current
        if tab is None:
            return
        url = tab.url_string()
        if not is_web_url(url):
            self.msg("Bu sayfa yer imlerine eklenemez.")
            return
        db = self.ctrl.db
        if db.is_bookmarked(url):
            db.remove_bookmark(url)
            self.msg("Yer imi kaldırıldı.")
        else:
            db.add_bookmark(url, tab.display_title())
            self.msg("Yer imi eklendi.")
        self.ctrl.bookmarks_changed()

    def set_bookmarks_bar_visible(self, visible: bool) -> None:
        self.ctrl.settings.set("show_bookmarks_bar", bool(visible))
        for w in self.ctrl.windows:
            w.on_settings_changed()

    def refresh_bookmarks_bar(self) -> None:
        bar = self.bookmarks_bar
        for act in list(bar.actions()):
            bar.removeAction(act)
            act.deleteLater()
        rows = self.ctrl.db.list_bookmarks(limit=60)
        icon = self.icon("globe", "muted", 14)
        if not rows:
            empty = bar.addAction("Yer imleri burada görünür — adres çubuğundaki ☆ simgesine tıklayın")
            empty.setEnabled(False)
            return
        for r in rows:
            url, title = r["url"], r["title"] or r["url"]
            act = bar.addAction(icon, elide(title, 22))
            act.setData(url)
            act.setToolTip("%s\n%s" % (title, url))
            act.triggered.connect(lambda _c=False, u=url: self.open_url(u))

    def bookmarks_bar_menu(self, pos) -> None:
        act = self.bookmarks_bar.actionAt(pos)
        menu = QMenu(self)
        if act is not None and act.data():
            url = act.data()
            add_menu_action(menu, "Yeni sekmede aç", lambda: self.add_tab(url))
            add_menu_action(menu, "Yeni gizli pencerede aç",
                            lambda: self.ctrl.new_window(private=True, urls=[url]))
            add_menu_action(menu, "Adresi kopyala", lambda: QApplication.clipboard().setText(url))
            menu.addSeparator()
            add_menu_action(menu, "Sil", lambda: (self.ctrl.db.remove_bookmark(url),
                                                  self.ctrl.bookmarks_changed()))
            menu.addSeparator()
        menu.addAction(self.act_bm_bar)
        menu.addAction(self.act_bookmarks)
        menu.exec(self.bookmarks_bar.mapToGlobal(pos))

    def _fill_bookmarks_menu(self) -> None:
        m = self.bm_menu
        m.clear()
        m.addAction(self.act_bookmark)
        m.addAction(self.act_bookmarks)
        m.addAction(self.act_bm_bar)
        rows = self.ctrl.db.list_bookmarks(limit=20)
        if rows:
            m.addSeparator()
        for r in rows:
            url = r["url"]
            add_menu_action(m, elide(r["title"] or url, 50), lambda u=url: self.open_url(u, True))

    def show_tab_menu(self, index: int, pos: QPoint) -> None:
        menu = QMenu(self)
        add_menu_action(menu, "Yeni sekme", lambda: self.add_tab())
        if 0 <= index < len(self._tabs):
            tab = self._tabs[index]
            n = len(self._tabs)
            add_menu_action(menu, "Yenile", lambda: self.reload_tab(tab))
            add_menu_action(menu, "Sekmeyi çoğalt", lambda: self.duplicate_tab(tab))
            add_menu_action(menu, "Sabitlemeyi kaldır" if tab.pinned else "Sekmeyi sabitle",
                            lambda: self.toggle_pin(tab))
            muted = tab.page.isAudioMuted()
            add_menu_action(menu, "Sesi aç" if muted else "Sekmeyi sessize al",
                            lambda: self.toggle_mute(tab))
            menu.addSeparator()
            add_menu_action(menu, "Sekmeyi kapat", lambda: self.close_tab(tab))
            add_menu_action(menu, "Diğer sekmeleri kapat", lambda: self.close_others(tab), enabled=n > 1)
            add_menu_action(menu, "Sağdaki sekmeleri kapat", lambda: self.close_right(tab),
                            enabled=index < n - 1)
        menu.addSeparator()
        add_menu_action(menu, "Kapatılan sekmeyi yeniden aç", self.reopen_closed_tab,
                        enabled=bool(self.closed_tabs))
        menu.exec(pos)

    def open_tab_search(self) -> None:
        TabSearchDialog(self).exec()

    def open_find(self) -> None:
        tab = self._current
        if tab is None:
            return
        if self._find_tab is not None and self._find_tab is not tab:
            self._clear_find_highlight(self._find_tab)
        self._find_tab = tab
        selected = ""
        try:
            selected = tab.page.selectedText().strip()
        except RuntimeError:
            pass
        if selected and "\n" not in selected and len(selected) < 120:
            self.find_bar.edit.blockSignals(True)
            self.find_bar.edit.setText(selected)
            self.find_bar.edit.blockSignals(False)
        self.find_bar.show()
        self.find_bar.focus_field()
        if self.find_bar.edit.text():
            self.run_find(False)

    def run_find(self, backward: bool = False) -> None:
        tab = self._current
        if tab is None or not self.find_bar.isVisible():
            return
        text = self.find_bar.edit.text()
        if not text:
            tab.page.findText("")
            self.find_bar.set_result(None, None)
            return
        flags = QWebEnginePage.FindFlag(0)
        if backward:
            flags |= QWebEnginePage.FindFlag.FindBackward
        if self.find_bar.case.isChecked():
            flags |= QWebEnginePage.FindFlag.FindCaseSensitively
        tab.page.findText(text, flags)

    def on_find_result(self, tab: BrowserTab, result) -> None:
        if tab is self._current and self.find_bar.isVisible() and self.find_bar.edit.text():
            self.find_bar.set_result(result.activeMatch(), result.numberOfMatches())

    def _clear_find_highlight(self, tab: BrowserTab) -> None:
        if tab in self._tabs:
            try:
                tab.page.findText("")
            except RuntimeError:
                pass

    def close_find(self) -> None:
        if self._find_tab is not None:
            self._clear_find_highlight(self._find_tab)
        self._find_tab = None
        self.find_bar.hide()
        self.find_bar.set_result(None, None)
        if self._current is not None:
            self._current.view.setFocus()

    def zoom_step(self, direction: int, tab: BrowserTab | None = None) -> None:
        tab = tab or self._current
        if tab is None:
            return
        cur = tab.view.zoomFactor()
        if direction > 0:
            new = next((z for z in ZOOM_STEPS if z > cur + 0.001), ZOOM_STEPS[-1])
        else:
            new = next((z for z in reversed(ZOOM_STEPS) if z < cur - 0.001), ZOOM_STEPS[0])
        self.set_zoom(tab, new)

    def set_zoom(self, tab: BrowserTab, factor: float) -> None:
        tab.view.setZoomFactor(factor)
        self.ctrl.set_zoom_for_host(tab.host(), factor, self.private)
        self.update_zoom_label(tab)
        self.msg("Yakınlaştırma: %%%d" % round(factor * 100), 1500)

    def reset_zoom(self) -> None:
        if self._current is not None:
            self.set_zoom(self._current, self.ctrl.default_zoom())

    def update_zoom_label(self, tab: BrowserTab) -> None:
        if tab is not self._current:
            return
        try:
            z = tab.view.zoomFactor()
        except RuntimeError:
            return
        self.zoom_label.setText("" if abs(z - 1.0) < 0.001 else "%%%d  " % round(z * 100))

    def toggle_fullscreen(self) -> None:
        if self._fs_tab is not None:
            self._fs_tab.page.triggerAction(QWebEnginePage.WebAction.ExitFullScreen)
            return
        if self.isFullScreen():
            self.showMaximized() if self._pre_fs_max else self.showNormal()
        else:
            self._pre_fs_max = self.isMaximized()
            self.showFullScreen()

    def set_html_fullscreen(self, tab: BrowserTab, on: bool) -> None:
        if on:
            if self._fs_tab is None:
                self._fs_prev = (self.isMaximized(), self.isFullScreen(), self.tab_strip.isVisible(),
                                 self.toolbar.isVisible(), self.bookmarks_bar.isVisible(),
                                 self.statusBar().isVisible(), self.progress.isVisible())
            self._fs_tab = tab
            for w in (self.tab_strip, self.toolbar, self.bookmarks_bar, self.progress,
                      self.statusBar(), self.find_bar):
                w.hide()
            self.showFullScreen()
        else:
            if self._fs_tab is None or self._fs_prev is None:
                return
            self._fs_tab = None
            was_max, was_fs, strip, tool, bm, status, prog = self._fs_prev
            self.tab_strip.setVisible(strip)
            self.toolbar.setVisible(tool)
            self.bookmarks_bar.setVisible(bm)
            self.statusBar().setVisible(status)
            self.progress.setVisible(prog)
            if not was_fs:
                self.showMaximized() if was_max else self.showNormal()

    def print_page(self, tab: BrowserTab | None = None) -> None:
        tab = tab if isinstance(tab, BrowserTab) else self._current
        if tab is None:
            return
        printer = QPrinter(QPrinter.PrinterMode.HighResolution)
        dlg = QPrintDialog(printer, self)
        if dlg.exec():
            self._printer = printer

            def done(ok: bool) -> None:
                self.msg("Yazdırma tamamlandı." if ok else "Yazdırma başarısız oldu.", 5000)
            tab.page.print(printer, done)

    def save_pdf(self) -> None:
        tab = self._current
        if tab is None:
            return
        name = safe_filename(tab.display_title(), "sayfa") + ".pdf"
        path, _ = QFileDialog.getSaveFileName(self, "PDF olarak kaydet",
                                              str(Path(self.ctrl.download_dir()) / name), "PDF (*.pdf)")
        if path:
            if not path.lower().endswith(".pdf"):
                path += ".pdf"
            tab.page.printToPdf(path)

    def save_page(self) -> None:
        tab = self._current
        if tab is None:
            return
        name = safe_filename(tab.display_title(), "sayfa")
        path, flt = QFileDialog.getSaveFileName(
            self, "Sayfayı kaydet", str(Path(self.ctrl.download_dir()) / (name + ".html")),
            "Web sayfası, tamamı (*.html);;Tek HTML dosyası (*.html);;MHTML arşivi (*.mhtml)")
        if not path:
            return
        F = QWebEngineDownloadRequest.SavePageFormat
        if path.lower().endswith(".mhtml") or "MHTML" in (flt or ""):
            fmt = F.MimeHtmlSaveFormat
        elif (flt or "").startswith("Tek"):
            fmt = F.SingleHtmlSaveFormat
        else:
            fmt = F.CompleteHtmlSaveFormat
        tab.page.save(path, fmt)

    def open_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Dosya aç", "",
            "Web ve belgeler (*.html *.htm *.xhtml *.mhtml *.pdf *.svg *.txt *.png *.jpg *.jpeg *.gif *.webp);;"
            "Tüm dosyalar (*)")
        if path:
            self.open_url(QUrl.fromLocalFile(path).toString(), new_tab=True)

    def view_source(self) -> None:
        tab = self._current
        if tab is None:
            return
        url = tab.url_string()
        if url.startswith(("http://", "https://", "file://")):
            self.add_tab("view-source:" + url, index=self._tabs.index(tab) + 1)
        else:
            self.msg("Bu sayfanın kaynağı görüntülenemez.")

    def toggle_devtools(self) -> None:
        if self._current is not None:
            self._current.toggle_devtools()

    def toggle_reader(self) -> None:
        tab = self._current
        if tab is None or not is_web_url(tab.url_string()):
            self.msg("Okuma modu yalnızca web sayfalarında kullanılabilir.")
            return
        js = READER_JS.replace("__DARK__", "true" if self.ctrl.dark else "false")

        def done(result) -> None:
            if result == "unavailable":
                self.msg("Bu sayfada okunabilir bir makale bulunamadı.", 5000)
        tab.page.runJavaScript(js, done)

    def translate_page(self) -> None:
        tab = self._current
        if tab is None or not is_web_url(tab.url_string()):
            self.msg("Yalnızca web sayfaları çevrilebilir.")
            return
        lang = QLocale.system().name().split("_")[0] or "tr"
        target = "https://translate.google.com/translate?sl=auto&tl=%s&u=%s" % (
            lang, quote(tab.url_string(), safe=""))
        self.add_tab(target, index=self._tabs.index(tab) + 1)

    def copy_url(self) -> None:
        if self._current is not None:
            QApplication.clipboard().setText(self._current.url_string())
            self.msg("Adres panoya kopyalandı.", 2500)

    def clear_data_dialog(self) -> None:
        ClearDataDialog(self.ctrl, self).exec()

    def show_about(self) -> None:
        try:
            from PyQt6.QtWebEngineCore import qWebEngineChromiumVersion
            chromium = qWebEngineChromiumVersion()
        except Exception:
            chromium = "?"
        QMessageBox.about(
            self, "%s hakkında" % APP_NAME,
            "<h3>%s %s</h3><p>PyQt6 ve Qt WebEngine tabanlı web tarayıcısı.</p>"
            "<p>Qt %s · PyQt %s · Chromium %s</p>"
            "<p>Kimlik: <code>YinegelOS/1.3</code> uygulama token'ı ile tanıtılıyor.</p>"
            "<p>Parola kasası anahtarı: <b>%s</b></p>"
            "<p>Veri klasörü:<br><code>%s</code></p>" % (
                APP_FULL, VERSION, QT_VERSION_STR, PYQT_VERSION_STR, chromium,
                "keyring (sistem deposu)" if _KEYRING_AVAILABLE else "dosya (keyring yok)",
                html.escape(str(self.ctrl.dir))))

    def changeEvent(self, event):  # noqa: N802
        if event.type() == QEvent.Type.ActivationChange and self.isActiveWindow():
            self.ctrl.last_active = self
        super().changeEvent(event)

    def closeEvent(self, event):  # noqa: N802
        if not self.ctrl.confirm_close(self):
            event.ignore()
            return
        self._closing = True
        self._shield_timer.stop()
        self.ctrl.window_closing(self)
        for tab in list(self._tabs):
            tab.dispose()
        self._tabs.clear()
        self._current = None
        event.accept()


# --------------------------------------------------------------------------- #
#  Uygulama denetleyicisi
# --------------------------------------------------------------------------- #
class Controller(QObject):
    def __init__(self, app: QApplication):
        super().__init__()
        self.app = app
        self.dir = app_data_dir()
        self.cache_dir = app_cache_dir()
        self.settings = AppSettings(self.dir / "settings.json")
        self.db = Database(self.dir / "yinegelos.db")
        self.windows: list[BrowserWindow] = []
        self.last_active: BrowserWindow | None = None
        self.quitting = False
        self.blocked_count = 0
        self.cert_exceptions: set = set()
        self.cert_pending: set = set()
        self.cert_rejected: dict = {}
        self.private_perms: dict = {}
        self.private_zoom: dict = {}
        self.private_profile: QWebEngineProfile | None = None
        self._private_windows = 0
        self._zombies: list = []
        self._reserved: set = set()
        self._geometry_used = False
        self._notifications: list = []
        self._tray: QSystemTrayIcon | None = None
        self.downloads_dialog: DownloadsDialog | None = None
        self.history_dialog: HistoryDialog | None = None
        self.bookmarks_dialog: BookmarksDialog | None = None
        self.password_dialog: PasswordVaultDialog | None = None
        self.suggestions = QStringListModel(self)
        self._suggest_timer = QTimer(self)
        self._suggest_timer.setSingleShot(True)
        self._suggest_timer.setInterval(1500)
        self._suggest_timer.timeout.connect(self.refresh_suggestions)

        # Parola kasası (keyring destekli)
        self.vault_path = self.dir / "passwords.enc"
        self._legacy_key_path = self.dir / "passwords.key"
        self._init_vault()

        self._sys_dark = app.palette().color(QPalette.ColorRole.Window).lightness() < 128
        self.dark = False
        self.colors = theme_colors(False)
        self.apply_theme()
        try:
            app.styleHints().colorSchemeChanged.connect(
                lambda *_a: QTimer.singleShot(0, self._on_system_scheme_changed))
        except Exception:
            pass

        self.profile = self._create_profile()
        self.refresh_suggestions()
        self._autosave = QTimer(self)
        self._autosave.setInterval(20000)
        self._autosave.timeout.connect(self.save_session)
        self._autosave.start()

    # === Kısayol yönetimi ===
    def add_shortcut(self, url: str) -> None:
        from urllib.parse import urlsplit
        try:
            host = urlsplit(url).hostname or url
        except ValueError:
            host = url
        title = host.replace("www.", "")
        shortcuts = self.settings.get("shortcuts") or []
        if any(s.get("url") == url for s in shortcuts):
            return
        shortcuts.append({"url": url, "title": title})
        self.settings.set("shortcuts", shortcuts)
        for w in list(self.windows):
            w.refresh_newtab_if_visible()

    def remove_shortcut(self, url: str) -> None:
        shortcuts = self.settings.get("shortcuts") or []
        shortcuts = [s for s in shortcuts if s.get("url") != url]
        self.settings.set("shortcuts", shortcuts)
        for w in list(self.windows):
            w.refresh_newtab_if_visible()

    # === keyring destekli parola kasası ===
    def _init_vault(self) -> None:
        key_b64: str | None = None
        if self._legacy_key_path.exists():
            try:
                legacy = self._legacy_key_path.read_bytes().strip()
                if legacy:
                    if _KEYRING_AVAILABLE:
                        keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, legacy.decode("ascii"))
                    key_b64 = legacy.decode("ascii")
                try:
                    self._legacy_key_path.unlink()
                except OSError:
                    pass
            except Exception as exc:
                log("Eski anahtar taşınamadı: %s" % exc)
        if key_b64 is None and _KEYRING_AVAILABLE:
            try:
                key_b64 = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
            except KeyringError as exc:
                log("keyring okunamadı: %s" % exc)
        if not key_b64:
            key = Fernet.generate_key()
            key_b64 = key.decode("ascii")
            if _KEYRING_AVAILABLE:
                try:
                    keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, key_b64)
                except KeyringError as exc:
                    log("keyring'e yazılamadı: %s" % exc)
                    self._legacy_key_path.write_bytes(key)
                    try:
                        os.chmod(self._legacy_key_path, 0o600)
                    except OSError:
                        pass
            else:
                self._legacy_key_path.write_bytes(key)
                try:
                    os.chmod(self._legacy_key_path, 0o600)
                except OSError:
                    pass
        try:
            self._fernet = Fernet(key_b64.encode("ascii"))
        except Exception as exc:
            log("Fernet anahtarı geçersiz: %s" % exc)
            key = Fernet.generate_key()
            self._fernet = Fernet(key)
            if _KEYRING_AVAILABLE:
                try:
                    keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, key.decode("ascii"))
                except KeyringError:
                    pass

    def _load_vault(self) -> dict:
        if not self.vault_path.exists():
            return {}
        try:
            decrypted = self._fernet.decrypt(self.vault_path.read_bytes())
            data = json.loads(decrypted.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except InvalidToken:
            log("Parola kasası çözülemedi.")
            return {}
        except Exception as exc:
            log("Parola kasası okunamadı: %s" % exc)
            return {}

    def _save_vault(self, vault: dict) -> None:
        try:
            encrypted = self._fernet.encrypt(
                json.dumps(vault, ensure_ascii=False).encode("utf-8"))
            tmp = self.vault_path.with_suffix(".tmp")
            tmp.write_bytes(encrypted)
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, self.vault_path)
        except Exception as exc:
            log("Parola kasası yazılamadı: %s" % exc)

    def store_password(self, host: str, username: str, password: str) -> None:
        host = (host or "").strip().lower()
        if not host or not username or not password:
            return
        vault = self._load_vault()
        entries = vault.setdefault(host, [])
        for e in entries:
            if e.get("username") == username:
                e["password"] = password
                e["created"] = time.time()
                self._save_vault(vault)
                return
        entries.append({"username": username, "password": password, "created": time.time()})
        self._save_vault(vault)

    def get_passwords(self, host: str) -> list:
        host = (host or "").strip().lower()
        return list(self._load_vault().get(host, []))

    def delete_password(self, host: str, index: int) -> None:
        vault = self._load_vault()
        if host in vault and 0 <= index < len(vault[host]):
            vault[host].pop(index)
            if not vault[host]:
                del vault[host]
            self._save_vault(vault)

    def clear_all_passwords(self) -> None:
        self._save_vault({})

    def is_dark(self) -> bool:
        theme = self.settings.get("theme")
        if theme == "dark":
            return True
        if theme == "light":
            return False
        try:
            hints = self.app.styleHints()
            if hasattr(hints, "unsetColorScheme"):
                hints.unsetColorScheme()
            scheme = hints.colorScheme()
            if scheme == Qt.ColorScheme.Dark:
                return True
            if scheme == Qt.ColorScheme.Light:
                return False
        except Exception:
            pass
        return self._sys_dark

    def _on_system_scheme_changed(self) -> None:
        if self.settings.get("theme") == "system":
            self.apply_theme()

    def apply_theme(self) -> None:
        self.dark = self.is_dark()
        c = self.colors = theme_colors(self.dark)
        icons_dir = self.cache_dir / "icons"
        icons_dir.mkdir(parents=True, exist_ok=True)
        close, close_hover = icons_dir / "close.png", icons_dir / "close_hover.png"
        svg_pixmap("x", c["muted"], 14).save(str(close), "PNG")
        svg_pixmap("x", c["text"], 14).save(str(close_hover), "PNG")
        self.app.setPalette(build_palette(c))
        self.app.setStyleSheet(build_qss(c, close.as_posix(), close_hover.as_posix()))
        try:
            hints = self.app.styleHints()
            if self.settings.get("theme") != "system" and hasattr(hints, "setColorScheme"):
                hints.setColorScheme(Qt.ColorScheme.Dark if self.dark else Qt.ColorScheme.Light)
        except Exception:
            pass
        for w in list(self.windows):
            w.apply_theme()

    def _wipe_storage(self, web_dir: Path) -> None:
        for name in ("Local Storage", "IndexedDB", "Service Worker", "Session Storage", "File System",
                     "Cache Storage", "databases", "Cookies", "Cookies-journal", "Network"):
            target = web_dir / name
            try:
                if target.is_dir():
                    shutil.rmtree(target, ignore_errors=True)
                elif target.exists():
                    target.unlink()
            except OSError:
                pass

    def _create_profile(self) -> QWebEngineProfile:
        web_dir = self.dir / "web"
        cache = self.cache_dir / "web"
        if self.settings.get("wipe_storage"):
            self._wipe_storage(web_dir)
            self.settings.set("wipe_storage", False)
        web_dir.mkdir(parents=True, exist_ok=True)
        cache.mkdir(parents=True, exist_ok=True)
        profile = QWebEngineProfile("yinegelos", self.app)
        profile.setPersistentStoragePath(str(web_dir))
        profile.setCachePath(str(cache))
        profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies)
        profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.DiskHttpCache)
        self.setup_profile(profile, private=False)
        self.apply_profile_settings(profile)
        return profile

    def get_private_profile(self) -> QWebEngineProfile:
        if self.private_profile is None:
            profile = QWebEngineProfile()
            self.setup_profile(profile, private=True)
            self.apply_profile_settings(profile)
            self.private_profile = profile
        return self.private_profile

    def setup_profile(self, profile: QWebEngineProfile, private: bool) -> None:
        # Gerçek UA: uygulama token'ı içerir, Google bunu kabul eder
        profile.setHttpUserAgent(APP_UA)
        lang = QLocale.system().name().replace("_", "-")
        base = lang.split("-")[0]
        accept = "%s,%s;q=0.9,en-US;q=0.8,en;q=0.7" % (lang, base) if base != "en" else "en-US,en;q=0.9"
        profile.setHttpAcceptLanguage(accept)
        # Client Hints: Chrome kimliğine zorlamıyoruz, varsayılan bırakıyoruz
        try:
            hints = profile.clientHints()
            # fullVersionList'i boşalt, böylece Sec-CH-UA başlıkları Chrome gibi görünmez
            hints.setAllClientHintsEnabled(True)
        except Exception:
            pass
        interceptor = RequestInterceptor(self, profile)
        profile.setUrlRequestInterceptor(interceptor)
        handler = YinegelSchemeHandler(self, private, profile)
        profile.installUrlSchemeHandler(QByteArray(SCHEME.encode()), handler)
        profile.downloadRequested.connect(self.on_download_requested)
        try:
            profile.setNotificationPresenter(self.present_notification)
        except Exception:
            pass

    def apply_profile_settings(self, profile: QWebEngineProfile) -> None:
        s = profile.settings()
        get = self.settings.get

        def attr(name: str, value) -> None:
            a = getattr(QWebEngineSettings.WebAttribute, name, None)
            if a is not None:
                s.setAttribute(a, bool(value))

        attr("JavascriptEnabled", get("javascript"))
        attr("ScrollAnimatorEnabled", get("smooth_scroll"))
        attr("PdfViewerEnabled", get("pdf_viewer"))
        attr("ForceDarkMode", get("force_dark_web"))
        attr("FullScreenSupportEnabled", True)
        attr("ScreenCaptureEnabled", True)
        attr("JavascriptCanOpenWindows", True)
        attr("JavascriptCanAccessClipboard", True)
        attr("LocalStorageEnabled", True)
        attr("ErrorPageEnabled", True)
        attr("DnsPrefetchEnabled", True)
        attr("AllowRunningInsecureContent", False)
        attr("PluginsEnabled", True)

    def _profiles(self) -> list:
        return [self.profile] + ([self.private_profile] if self.private_profile is not None else [])

    def _retire_private_profile(self) -> None:
        profile, self.private_profile = self.private_profile, None
        self.private_perms.clear()
        self.private_zoom.clear()
        if profile is not None:
            self._zombies.append(profile)
            QTimer.singleShot(1500, self._reap_profiles)

    def _reap_profiles(self) -> None:
        for p in self._zombies:
            try:
                p.deleteLater()
            except RuntimeError:
                pass
        self._zombies.clear()

    def search_template(self) -> str:
        name = self.settings.get("search_engine")
        tpl = self.settings.get("custom_search") if name == CUSTOM_ENGINE else SEARCH_ENGINES.get(name)
        return tpl if tpl and "%s" in tpl else SEARCH_ENGINES["DuckDuckGo"]

    def download_dir(self) -> str:
        d = self.settings.get("download_dir")
        if d and Path(d).is_dir():
            return d
        loc = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DownloadLocation)
        return loc or str(Path.home())

    def default_zoom(self) -> float:
        return max(0.25, min(5.0, self.settings.get("default_zoom") / 100.0))

    def zoom_for_host(self, host: str, private: bool) -> float:
        store = self.private_zoom if private else self.settings.get("site_zoom")
        try:
            return float(store.get(host, self.default_zoom()))
        except (TypeError, ValueError):
            return self.default_zoom()

    def set_zoom_for_host(self, host: str, factor: float, private: bool) -> None:
        if not host:
            return
        store = self.private_zoom if private else self.settings.get("site_zoom")
        if abs(factor - self.default_zoom()) < 0.001:
            store.pop(host, None)
        else:
            store[host] = round(factor, 3)
        if not private:
            self.settings.save()

    def apply_zoom_to_tab(self, tab: BrowserTab) -> None:
        try:
            tab.view.setZoomFactor(self.zoom_for_host(tab.host(), tab.private))
        except RuntimeError:
            pass

    def apply_settings(self) -> None:
        for p in self._profiles():
            self.apply_profile_settings(p)
        self.apply_theme()
        for w in list(self.windows):
            w.on_settings_changed()
        self.request_suggestions_refresh()

    def permission_store(self, private: bool) -> dict:
        return self.private_perms if private else self.settings.get("permissions")

    def remember_permission(self, private: bool, key: str, allow: bool) -> None:
        self.permission_store(private)[key] = "allow" if allow else "deny"
        if not private:
            self.settings.save()

    def record_visit(self, url: str, title: str) -> None:
        self.db.add_visit(url, title)
        self.request_suggestions_refresh()

    def request_suggestions_refresh(self) -> None:
        self._suggest_timer.start()

    def refresh_suggestions(self) -> None:
        seen, items = set(), []
        for r in self.db.list_bookmarks(limit=500):
            if r["url"] not in seen:
                seen.add(r["url"])
                items.append(r["url"])
        for r in self.db.search_history("", 1500):
            if r["url"] not in seen:
                seen.add(r["url"])
                items.append(r["url"])
        self.suggestions.setStringList(items)

    def bookmarks_changed(self) -> None:
        for w in list(self.windows):
            w.refresh_bookmarks_bar()
            w.refresh_star()
        if self.bookmarks_dialog is not None and self.bookmarks_dialog.isVisible():
            self.bookmarks_dialog.reload()
        self.request_suggestions_refresh()

    def clear_data(self, history: bool, cookies: bool, cache: bool, downloads: bool,
                   sites: bool, passwords: bool = False) -> None:
        if history:
            self.db.clear_history()
            for p in self._profiles():
                p.clearAllVisitedLinks()
        if cache:
            for p in self._profiles():
                p.clearHttpCache()
        if cookies:
            for p in self._profiles():
                p.cookieStore().deleteAllCookies()
            self.settings.set("wipe_storage", True)
        if downloads and self.downloads_dialog is not None:
            self.downloads_dialog.clear_finished()
        if sites:
            self.settings.set("permissions", {}, save=False)
            self.settings.set("site_zoom", {}, save=False)
        if passwords:
            self.clear_all_passwords()
        self.settings.save()
        self.request_suggestions_refresh()
        if self.history_dialog is not None and self.history_dialog.isVisible():
            self.history_dialog.reload()
        if self.password_dialog is not None and self.password_dialog.isVisible():
            self.password_dialog.reload()
        w = self.active_window()
        if w is not None:
            w.msg("Seçilen tarama verileri temizlendi.", 5000)

    def render_newtab(self, private: bool) -> str:
        c = self.colors
        tiles: list[str] = []

        def tile(url: str, title: str) -> str:
            try:
                host = urlsplit(url).hostname or ""
            except ValueError:
                host = ""
            label = (title or host or url).strip()
            letter = (host.replace("www.", "")[:1] or label[:1] or "?").upper()
            hue = sum(ord(ch) for ch in host) % 360
            return ('<a class="tile" href="%s"><span class="x" title="Kısayolu sil">×</span>'
                    '<span class="ico" style="background:hsl(%d,55%%,42%%)">%s</span>'
                    '<span class="t">%s</span></a>' % (
                        html.escape(url, quote=True), hue, html.escape(letter), html.escape(label[:40])))

        if private:
            heading = "Gizli pencere"
            sub = "Bu pencerede gezdikleriniz kaydedilmez."
            content = ('<p class="note">Gizli pencere kapandığında çerezler, site verileri ve geçmiş silinir. '
                       'İndirdiğiniz dosyalar ve yer imleri korunur.</p>')
        else:
            heading = "<span>Y</span>inegelOS"
            sub = "Kısayollarınız"
            shortcuts = self.settings.get("shortcuts") or []
            if shortcuts:
                for s in shortcuts:
                    tiles.append(tile(s["url"], s.get("title", s["url"])))
                content = '<div class="shortcuts-title">Kısayollar</div><div class="grid">%s</div>' % "".join(tiles)
            else:
                content = ('<div class="empty-hint">Henüz kısayol yok. Aşağıdaki butona tıklayarak '
                           'ilk kısayolunuzu ekleyin.</div>')
            # Kısayol ekleme butonu
            content += ('<div style="margin-top:16px;width:100%;max-width:720px;display:flex;justify-content:center;">'
                        '<button id="add-shortcut" class="add-tile" style="min-width:180px;">'
                        '<span class="plus">+</span><span>Kısayol ekle</span></button></div>')
        mapping = {
            "bg": c["page_bg"], "fg": c["text"], "muted": c["muted"], "card": c["card"],
            "border": c["border"], "accent": c["accent"], "heading": heading, "sub": sub,
            "tpl": json.dumps(self.search_template()).replace("</", "<\\/"), "content": content,
        }
        return re.sub(r"@(\w+)@", lambda m: mapping.get(m.group(1), m.group(0)), NEWTAB_TEMPLATE)

    def default_tab_url(self, private: bool) -> str:
        if not private and self.settings.get("startup") == "home":
            return self.settings.get("home_page") or NEWTAB_URL
        return NEWTAB_URL

    def new_window(self, private: bool = False, urls: list | None = None,
                   empty: bool = False) -> BrowserWindow:
        profile = self.get_private_profile() if private else self.profile
        win = BrowserWindow(self, private, profile)
        if private:
            self._private_windows += 1
        base = self.last_active if self.last_active in self.windows else None
        if base is not None and not base.isMaximized() and not base.isFullScreen():
            g = base.geometry()
            win.resize(g.size())
            win.move(g.x() + 30, g.y() + 30)
        elif base is None and not self._geometry_used and self.settings.get("geometry"):
            try:
                win.restoreGeometry(QByteArray.fromBase64(self.settings.get("geometry").encode("ascii")))
            except Exception:
                pass
        self._geometry_used = True
        self.windows.append(win)
        self.last_active = win
        win.show()
        if not empty:
            if urls:
                for u in urls:
                    win.add_tab(u)
            if not win.tab_count():
                win.add_tab(self.default_tab_url(private))
        return win

    def active_window(self) -> BrowserWindow | None:
        w = QApplication.activeWindow()
        if isinstance(w, BrowserWindow) and w in self.windows:
            return w
        if self.last_active in self.windows:
            return self.last_active
        return self.windows[-1] if self.windows else None

    def open_in_active(self, url: str, new_tab: bool = True) -> None:
        win = self.active_window() or self.new_window(empty=True)
        win.add_tab(url) if new_tab else win.open_url(url)
        self.raise_window(win)

    @staticmethod
    def raise_window(win: BrowserWindow) -> None:
        win.setWindowState(win.windowState() & ~Qt.WindowState.WindowMinimized)
        win.show()
        win.raise_()
        win.activateWindow()

    def save_geometry(self, win: BrowserWindow) -> None:
        try:
            self.settings.set("geometry", bytes(win.saveGeometry().toBase64()).decode("ascii"))
        except Exception:
            pass

    def confirm_close(self, win: BrowserWindow) -> bool:
        if self.quitting or any(w is not win for w in self.windows):
            return True
        n = self.downloads_dialog.active_count() if self.downloads_dialog else 0
        if n == 0:
            return True
        ans = QMessageBox.question(
            win, "Devam eden indirmeler",
            "%d indirme sürüyor. Tarayıcıyı kapatırsanız iptal edilecekler.\n\nKapatılsın mı?" % n,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        return ans == QMessageBox.StandardButton.Yes

    def window_closing(self, win: BrowserWindow) -> None:
        if not self.quitting and not win.private:
            others = [w for w in self.windows if w is not win and not w.private]
            self.save_session(others if others else [win])
            if not others:
                self.save_geometry(win)
        if win.private:
            self._private_windows -= 1
            if self._private_windows <= 0:
                self._private_windows = 0
                self._retire_private_profile()
        if win in self.windows:
            self.windows.remove(win)
        if self.last_active is win:
            self.last_active = None
        if not self.windows:
            self.close_aux_dialogs()

    def close_aux_dialogs(self) -> None:
        for d in (self.downloads_dialog, self.history_dialog, self.bookmarks_dialog,
                  self.password_dialog):
            if d is not None:
                d.close()

    def quit_app(self) -> None:
        n = self.downloads_dialog.active_count() if self.downloads_dialog else 0
        if n:
            ans = QMessageBox.question(
                self.active_window(), "Devam eden indirmeler",
                "%d indirme sürüyor. Çıkarsanız iptal edilecekler.\n\nÇıkılsın mı?" % n,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if ans != QMessageBox.StandardButton.Yes:
                return
        normal = [w for w in self.windows if not w.private]
        self.save_session(normal)
        if normal:
            self.save_geometry(self.active_window() if self.active_window() in normal else normal[0])
        self.quitting = True
        for w in list(self.windows):
            w.close()
        self.close_aux_dialogs()
        self.app.quit()

    def save_session(self, windows: list | None = None) -> None:
        if self.quitting:
            return
        wins = windows if windows is not None else [w for w in self.windows if not w.private]
        data = {"version": 1, "windows": [w.session_state() for w in wins if w.tab_count()]}
        data["windows"] = [w for w in data["windows"] if w["tabs"]]
        if data["windows"]:
            atomic_write_json(self.dir / "session.json", data)

    def restore_session(self) -> bool:
        path = self.dir / "session.json"
        try:
            data = json.loads(path.read_text("utf-8"))
            entries = data.get("windows", [])
        except (OSError, ValueError, AttributeError):
            return False
        restored = False
        for ws in entries:
            if not isinstance(ws, dict):
                continue
            items = [t for t in ws.get("tabs", [])
                     if isinstance(t, dict) and isinstance(t.get("url"), str) and t["url"]]
            if not items:
                continue
            win = self.new_window(empty=True)
            cur = ws.get("current", 0)
            win.restore_tabs(items, cur if isinstance(cur, int) else 0)
            restored = True
        return restored

    def start(self, args: list, private: bool) -> None:
        urls = [u for u in (self.arg_to_url(a) for a in args) if u]
        if private:
            self.new_window(private=True, urls=urls or None)
            return
        restored = self.settings.get("startup") == "restore" and self.restore_session()
        if urls:
            win = self.active_window() or self.new_window(empty=True)
            for u in urls:
                win.add_tab(u)
        elif not restored:
            self.new_window()

    def arg_to_url(self, arg: str) -> str:
        url = user_input_to_url(arg, self.search_template())
        return url.toString() if url.isValid() and not url.isEmpty() else ""

    def handle_external(self, lines: list) -> None:
        lines = [ln.strip() for ln in lines if ln.strip()]
        command = lines[0] if lines and lines[0] in ("OPEN", "PRIVATE") else "OPEN"
        args = lines[1:] if lines and lines[0] in ("OPEN", "PRIVATE") else lines
        urls = [u for u in (self.arg_to_url(a) for a in args) if u]
        if command == "PRIVATE":
            win = self.new_window(private=True, urls=urls or None)
        elif urls:
            win = self.active_window() or self.new_window(empty=True)
            for u in urls:
                win.add_tab(u)
        else:
            win = self.active_window() or self.new_window()
        self.raise_window(win)

    def show_downloads(self) -> None:
        if self.downloads_dialog is None:
            self.downloads_dialog = DownloadsDialog(self)
        self.downloads_dialog.present()

    def show_history(self) -> None:
        if self.history_dialog is None:
            self.history_dialog = HistoryDialog(self)
        self.history_dialog.present()

    def show_bookmarks(self) -> None:
        if self.bookmarks_dialog is None:
            self.bookmarks_dialog = BookmarksDialog(self)
        self.bookmarks_dialog.present()

    def show_passwords(self) -> None:
        if self.password_dialog is None:
            self.password_dialog = PasswordVaultDialog(self)
        self.password_dialog.present()

    def show_settings(self) -> None:
        SettingsDialog(self).exec()

    def show_import(self) -> None:
        ImportDialog(self, self.active_window()).exec()

    def release_download_path(self, path: Path) -> None:
        self._reserved.discard(str(path))

    def on_download_requested(self, request: QWebEngineDownloadRequest) -> None:
        try:
            if not request.isSavePageDownload():
                directory = Path(self.download_dir())
                directory.mkdir(parents=True, exist_ok=True)
                name = safe_filename(request.downloadFileName() or "")
                path = unique_path(directory, name, self._reserved)
                if self.settings.get("download_ask"):
                    chosen, _ = QFileDialog.getSaveFileName(self.active_window(), "İndirmeyi kaydet", str(path))
                    if not chosen:
                        request.cancel()
                        return
                    path = Path(chosen)
                self._reserved.add(str(path))
                request.setDownloadDirectory(str(path.parent))
                request.setDownloadFileName(path.name)
            request.accept()
            self.show_downloads()
            self.downloads_dialog.add_download(request)
        except Exception as exc:
            log("İndirme başlatılamadı: %s" % exc)
            try:
                request.cancel()
            except Exception:
                pass

    def present_notification(self, notification) -> None:
        try:
            if self._tray is None:
                self._tray = QSystemTrayIcon(self.app.windowIcon(), self.app)
                self._tray.messageClicked.connect(self._on_notification_clicked)
                self._tray.show()
            self._notifications.append(notification)
            del self._notifications[:-20]
            notification.show()
            self._tray.showMessage(notification.title(), notification.message(),
                                   QSystemTrayIcon.MessageIcon.Information, 6000)
        except Exception as exc:
            log("Bildirim gösterilemedi: %s" % exc)

    def _on_notification_clicked(self) -> None:
        if self._notifications:
            try:
                self._notifications[-1].click()
            except Exception:
                pass
        w = self.active_window()
        if w is not None:
            self.raise_window(w)

    def shutdown(self) -> None:
        try:
            self.settings.save()
        except Exception:
            pass
        flush = QEvent.Type.DeferredDelete.value
        QCoreApplication.sendPostedEvents(None, flush)
        self._reap_profiles()
        QCoreApplication.sendPostedEvents(None, flush)
        try:
            self.profile.deleteLater()
        except RuntimeError:
            pass
        QCoreApplication.sendPostedEvents(None, flush)
        self.db.close()


# --------------------------------------------------------------------------- #
#  Tek örnek
# --------------------------------------------------------------------------- #
class InstanceServer(QObject):
    def __init__(self, name: str, handler, parent=None):
        super().__init__(parent)
        self.name = name
        self.handler = handler
        self.server = QLocalServer(self)
        self.server.newConnection.connect(self._on_connection)

    def listen(self) -> bool:
        QLocalServer.removeServer(self.name)
        ok = self.server.listen(self.name)
        if not ok:
            log("Tek örnek sunucusu başlatılamadı: %s" % self.server.errorString())
        return ok

    def close(self) -> None:
        self.server.close()

    def _on_connection(self) -> None:
        while self.server.hasPendingConnections():
            sock = self.server.nextPendingConnection()
            if sock is None:
                return
            buf = bytearray()
            sock.readyRead.connect(lambda s=sock, b=buf: b.extend(bytes(s.readAll())))
            sock.disconnected.connect(lambda s=sock, b=buf: self._finish(s, b))

    def _finish(self, sock: QLocalSocket, buf: bytearray) -> None:
        buf.extend(bytes(sock.readAll()))
        sock.deleteLater()
        try:
            self.handler(buf.decode("utf-8", "replace").splitlines())
        except Exception as exc:
            log("Harici istek işlenemedi: %s" % exc)


def send_to_running_instance(name: str, payload: str) -> bool:
    sock = QLocalSocket()
    sock.connectToServer(name)
    if not sock.waitForConnected(400):
        return False
    sock.write(payload.encode("utf-8"))
    sock.flush()
    sock.waitForBytesWritten(1500)
    sock.disconnectFromServer()
    if sock.state() != QLocalSocket.LocalSocketState.UnconnectedState:
        sock.waitForDisconnected(800)
    return True


def register_scheme() -> None:
    scheme = QWebEngineUrlScheme(QByteArray(SCHEME.encode()))
    scheme.setSyntax(QWebEngineUrlScheme.Syntax.Host)
    scheme.setFlags(QWebEngineUrlScheme.Flag.SecureScheme)
    QWebEngineUrlScheme.registerScheme(scheme)


USAGE = """Kullanım: yinegelos_browser.py [seçenekler] [adres | dosya ...]

  --private, --incognito   Gizli pencerede başlat
  -h, --help               Bu yardımı göster
"""


def main() -> int:
    global _LOG_PATH
    args = sys.argv[1:]
    if "-h" in args or "--help" in args:
        print(USAGE)
        return 0
    private = any(a in ("--private", "--incognito") for a in args)
    raw_urls = [a for a in args if not a.startswith("-")]
    qt_args = [sys.argv[0]] + [a for a in args if a.startswith("-")
                                and a not in ("--private", "--incognito")]

    QCoreApplication.setOrganizationName(ORG_NAME)
    QCoreApplication.setApplicationName(APP_NAME)
    QCoreApplication.setApplicationVersion(VERSION)
    register_scheme()
    sys.excepthook = excepthook

    app = QApplication(qt_args)
    app.setApplicationDisplayName(APP_FULL)
    app.setWindowIcon(make_app_icon())
    app.setStyle("Fusion")

    try:
        _LOG_PATH = app_data_dir() / "yinegelos.log"
        if _LOG_PATH.exists() and _LOG_PATH.stat().st_size > 1_000_000:
            _LOG_PATH.write_text("", "utf-8")
    except OSError:
        _LOG_PATH = None

    user = os.environ.get("USERNAME") or os.environ.get("USER") or "user"
    key = "yinegelos-browser-%s" % re.sub(r"\W", "_", user)
    payload = ("PRIVATE" if private else "OPEN") + "\n" + "\n".join(normalize_cli_arg(a) for a in raw_urls)
    if send_to_running_instance(key, payload):
        return 0

    ctrl = Controller(app)
    server = InstanceServer(key, ctrl.handle_external, app)
    server.listen()

    signal.signal(signal.SIGINT, lambda *_a: app.quit())
    tick = QTimer()
    tick.timeout.connect(lambda: None)
    tick.start(500)

    ctrl.start([normalize_cli_arg(a) for a in raw_urls], private)
    code = app.exec()
    server.close()
    ctrl.shutdown()
    return code


if __name__ == "__main__":
    sys.exit(main())