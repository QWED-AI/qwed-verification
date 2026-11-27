"""
SystemGuard: Deterministic Shell & File Firewall.
Blocks dangerous commands and enforces sandboxing.
"""
import ntpath
import re
import os
import stat
import unicodedata
from typing import Callable, Dict, Any, List, Optional, Tuple, Union


# Paths longer than this, or with more named parts (as given, or made
# absolute), are refused before anything is read: resolving reads the file
# system once for every part.
MAX_PATH_CHARS = 4096
MAX_PATH_PARTS = 256

# Links followed for one path before it is refused (as POSIX SYMLOOP_MAX)
_MAX_LINKS = 40

_ON_WINDOWS = os.name == "nt"
_UNRESOLVED = "Could not resolve path."
_INVALID_PATH = "INVALID_PATH"
_SANDBOX_ESCAPE = "SANDBOX_ESCAPE"

# Windows forms that name devices or the NT object namespace, where the path
# as written and the path the check resolves can be different files
_WINDOWS_NAMESPACE_PREFIXES = ("\\\\?\\", "\\\\.\\", "\\??\\")

# Windows names that open a device in any folder, with any extension
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {prefix + digit for prefix in ("COM", "LPT")
       for digit in "0123456789" + chr(0xB9) + chr(0xB2) + chr(0xB3)}
)

# Bit of a Windows reparse tag that names another file or directory
# (symbolic links, junctions, mount points, container links)
_REPARSE_TAG_NAME_SURROGATE = 0x20000000


def _is_within(root: str, path: str) -> bool:
    """
    True when ``path`` is ``root`` or below it, compared part by part with
    case folded on Windows. Only a first filter, before the file system is
    read; the decision is ``_is_inside`` on resolved paths.
    """
    root_key = os.path.normcase(root)
    try:
        return os.path.commonpath([root_key, os.path.normcase(path)]) == root_key
    except ValueError:
        # Different drives on Windows, or one path absolute and one not.
        return False


def _is_inside(root: str, path: str) -> bool:
    """
    True when ``path`` is ``root`` or below it, both resolved, compared
    exactly, part by part: a directory may tell case apart. (On Windows,
    resolving spells existing parts as the disk does; elsewhere they stay as
    written.)
    """
    if path == root:
        return True
    prefix = root if root.endswith(os.sep) else root + os.sep
    return path.startswith(prefix)


def _slashed(path: str) -> str:
    """``path`` without its drive, with "/" separators."""
    return os.path.splitdrive(path)[1].replace(os.sep, "/")


def _same_path(a: str, b: str) -> bool:
    return os.path.normcase(a) == os.path.normcase(b)


def _lstat_or_none(path: str) -> Optional[os.stat_result]:
    """
    ``lstat`` of ``path``, or None when nothing is there. Any other error is
    raised: the part is there but cannot be read, so whether it is a link is
    not known. On Windows a junction can deny reading its attributes and
    still be followed when a path through it is opened.
    """
    try:
        return os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None


def _is_link_stat(status: os.stat_result) -> bool:
    """A symbolic link, or a Windows reparse point that names another file."""
    return stat.S_ISLNK(status.st_mode) or bool(
        getattr(status, "st_reparse_tag", 0) & _REPARSE_TAG_NAME_SURROGATE
    )


def _resolves_in_place(written: str, resolved: str) -> bool:
    """
    The last part of ``written`` is not a link or a junction: it is the same
    file as ``resolved``, by file identity (``lstat`` does not follow the last
    part). A short (8.3) name or another case of the same name passes; a link
    to a name that differs only in case does not, nor a link that resolving
    could not follow (a loop, a volume link). From here on the check uses
    the string ``resolved``: a link swapped in after this read does not change
    which directory is allowed, though it can change what a path below it
    names when the caller opens it.
    """
    try:
        written_stat = _lstat_or_none(written)
        resolved_stat = _lstat_or_none(resolved)
    except OSError:
        # There, but whether it is a link cannot be read.
        return False
    if written_stat is None and resolved_stat is None:
        # Nothing there yet: resolving followed no link at the last part
        # and kept its name.
        return os.path.basename(written) == os.path.basename(resolved)
    if written_stat is None or resolved_stat is None:
        return False
    if _is_link_stat(written_stat) or _is_link_stat(resolved_stat):
        return False
    return os.path.samestat(written_stat, resolved_stat)


def _is_filesystem_root(path: str) -> bool:
    return os.path.dirname(path) == path


def _part_count(path: str) -> int:
    separators = "[" + re.escape(os.sep + (os.altsep or "")) + "]"
    return sum(1 for part in re.split(separators, path) if part)


def _without_format_chars(text: str) -> str:
    """``text`` without invisible format characters (Unicode Cf), which some
    file systems leave out of names (HFS+ ignores U+200C, for one)."""
    return "".join(char for char in text if unicodedata.category(char) != "Cf")


def _without_long_path_prefix(target: str) -> str:
    """A Windows link target without its long-path prefix, as a plain path."""
    if target.startswith("\\\\?\\UNC\\"):
        return "\\\\" + target[8:]
    if target.startswith("\\\\?\\"):
        return target[4:]
    return target


def _link_target(link: str, written: str) -> str:
    """Where ``link``, whose target reads ``written``, points: an absolute path."""
    target = os.path.join(os.path.dirname(link), written)
    if _ON_WINDOWS:
        return os.path.normpath(_without_long_path_prefix(target))
    return target


def _target_depends_on_route(written: str) -> bool:
    """
    Windows reads a relative link target from the path that reached the
    link, not from where an earlier link on that path led. A target that
    climbs with "..", or has a drive and no root ("D:x") or a root and no
    drive ("\\x"), can then name another place than the walk follows. A
    full path, or a relative name without "..", cannot.
    """
    drive, rest = ntpath.splitdrive(written)
    rooted = rest.startswith(("\\", "/"))
    if drive or rooted:
        return not (drive and rooted)
    return os.pardir in re.split(r"[\\/]", rest)


def _walk_start(path: str) -> Tuple[str, List[str]]:
    """The root of absolute ``path`` and its named parts, last first."""
    drive, rest = os.path.splitdrive(path)
    return drive + os.sep, [part for part in rest.split(os.sep) if part][::-1]


def _is_link(path: str) -> bool:
    """Raises OSError when ``path`` is there but cannot be read."""
    status = _lstat_or_none(path)
    return status is not None and _is_link_stat(status)


def _follow_link(
    link: str, walkable: Callable[[str], bool], read_by_route: bool = False
) -> Union[str, Tuple[str, List[str]]]:
    """
    The walk's new start and parts after ``link``, or the risk to report.
    ``read_by_route``: Windows, with another link followed on the way to
    this one.
    """
    try:
        written = os.readlink(link)
        target = _link_target(link, written)
    except (OSError, ValueError):
        return _INVALID_PATH
    if read_by_route and _target_depends_on_route(written):
        return _INVALID_PATH
    root, parts = _walk_start(target)
    if not walkable(root):
        return _SANDBOX_ESCAPE
    return root, parts


def _links_stay_inside(path: str, walkable: Callable[[str], bool]) -> Optional[str]:
    """
    Follow absolute ``path`` part by part, as resolving it would, and read a
    part only when ``walkable`` allows it. Returns None when every part and
    link stays walkable, or the risk to report: "SANDBOX_ESCAPE" when a part
    or a link leads anywhere else (nothing there is read, so a link to a
    network share connects to nothing), "INVALID_PATH" when more than
    _MAX_LINKS links are followed, when a part or a link is there but
    cannot be read (resolving would take it for a plain directory), or on
    Windows when a link reached through another link has a target whose
    meaning depends on that route.
    """
    if _ON_WINDOWS:
        # Windows removes ".." before it reads links.
        path = os.path.normpath(path)
    current, pending = _walk_start(path)
    if not walkable(current):
        return _SANDBOX_ESCAPE
    links = 0
    while pending:
        name = pending.pop()
        if name in (os.curdir, os.pardir):
            # The parts so far are resolved, so ".." is the real parent.
            current = os.path.dirname(current) if name == os.pardir else current
            continue
        candidate = os.path.join(current, name)
        if not walkable(candidate):
            return _SANDBOX_ESCAPE
        try:
            is_link = _is_link(candidate)
        except OSError:
            return _INVALID_PATH
        if not is_link:
            current = candidate
            continue
        links += 1
        followed = _INVALID_PATH if links > _MAX_LINKS else _follow_link(
            candidate, walkable, _ON_WINDOWS and links > 1
        )
        if isinstance(followed, str):
            return followed
        current, more = followed
        pending.extend(more)
    return None


def _is_windows_special(path: str) -> bool:
    """
    A Windows device or NT namespace form, an alternate data stream
    ("file:stream"), or a reserved device name such as "CON" or "COM1.txt":
    what Windows opens for these is not the file the path seems to name. So
    is a name that ends with a dot or a space.
    """
    slashed = path.replace("/", "\\")
    if slashed.startswith(_WINDOWS_NAMESPACE_PREFIXES):
        return True
    rest = ntpath.splitdrive(slashed)[1]
    if ":" in rest:
        return True
    parts = [part for part in rest.split("\\") if part not in ("", ".", "..")]
    return any(
        # Windows drops a trailing dot or space: "key.pem." opens "key.pem".
        part.endswith((".", " "))
        or part.split(".")[0].rstrip(" ").upper() in _WINDOWS_RESERVED_NAMES
        for part in parts
    )


def _writable_by_all(path: str) -> bool:
    """
    Every user can write to ``path``, as to /tmp, so what is in it may be
    anyone's. False on Windows, where the mode bits do not say who may
    write, and when nothing is there. True when it cannot be read.
    """
    if _ON_WINDOWS:
        return False
    try:
        return bool(os.stat(path).st_mode & stat.S_IWOTH)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        return True


def _starts_at_home(path: str) -> bool:
    """
    "~", or a first part that starts with "~" followed by more parts: a shell
    or ``os.path.expanduser`` reads it as a home directory.
    """
    return path == "~" or re.match(r"~[^/\\]*[/\\]", path) is not None


class SystemGuard:
    """
    Deterministic guard for system-level operations: a blocklist for shell
    commands, and allowed directories for file paths.
    """
    
    # Default blocklist of dangerous commands
    DEFAULT_BLOCKED_COMMANDS = [
        "rm", "rmdir", "del",           # Deletion
        "chmod", "chown", "chattr",     # Permission changes
        "wget", "curl", "fetch",        # Network downloads
        "ssh", "scp", "rsync", "nc",    # Remote access
        "sudo", "su", "doas",           # Privilege escalation
        "mkfs", "fdisk", "dd",          # Disk operations
        "reboot", "shutdown", "halt",   # System control
        "kill", "pkill", "killall",     # Process control
        "eval", "exec",                 # Code execution
    ]
    
    # Forbidden path patterns (regex)
    DEFAULT_FORBIDDEN_PATHS = [
        r"\.\.",                        # Path traversal
        r"~/.ssh",                      # SSH keys
        r"(?:^|/)\.ssh(?:/|$)",         # SSH keys, at any depth
        r"/etc/passwd",                 # User database
        r"/etc/shadow",                 # Password hashes
        r"/root",                       # Root home
        r"/var/log",                    # System logs
        r"\.env",                       # Environment files
        r"\.git/config",                # Git credentials
        r"id_rsa",                      # SSH private keys
        r"\.pem$",                      # SSL certificates
    ]

    # Directories a file path may be in when the caller names none. Not
    # /tmp: every user of the machine can write there, so a file in it may
    # be someone else's.
    DEFAULT_ALLOWED_PATHS = ["./workspace", "."]
    
    def __init__(
        self,
        allowed_paths: Optional[List[str]] = None,
        blocked_commands: Optional[List[str]] = None,
        forbidden_path_patterns: Optional[List[str]] = None
    ):
        if isinstance(allowed_paths, (str, bytes, os.PathLike)):
            # A single string would be read one character at a time, and "/"
            # alone allows every path.
            raise TypeError("allowed_paths must be a list of directories, not a single path.")
        # None means the defaults; an empty list allows no directory.
        self._default_allowed_paths = allowed_paths is None
        self.allowed_paths = (
            list(self.DEFAULT_ALLOWED_PATHS) if allowed_paths is None
            else [self._allowed_dir(entry) for entry in allowed_paths]
        )
        self.blocked_commands = blocked_commands or self.DEFAULT_BLOCKED_COMMANDS
        self.forbidden_patterns = [
            re.compile(p, re.IGNORECASE) 
            for p in (forbidden_path_patterns or self.DEFAULT_FORBIDDEN_PATHS)
        ]
    
    @staticmethod
    def _allowed_dir(entry: Any) -> str:
        try:
            path = os.fspath(entry)
        except TypeError:
            raise TypeError("allowed_paths entries must be strings or path objects.") from None
        if not isinstance(path, str):
            raise TypeError("allowed_paths entries must be strings or path objects, not bytes.")
        if "\x00" in path:
            raise ValueError("allowed_paths entries must not contain a NUL character.")
        return path

    def verify_shell_command(self, command: str) -> Dict[str, Any]:
        """
        Statically analyze a shell command for dangerous patterns.
        
        Returns:
            {"verified": True/False, "risk": str, "message": str}
        """
        if not command or not command.strip():
            return {"verified": True, "message": "Empty command."}
        
        # Normalize command
        cmd_lower = command.lower().strip()
        
        # 1. Check for blocked base commands
        # Split by common shell operators to get base command
        tokens = re.split(r'[;\|\&\s]+', cmd_lower)
        base_commands = [t.split('/')[-1] for t in tokens if t]  # Handle full paths
        
        for base_cmd in base_commands:
            if base_cmd in self.blocked_commands:
                return {
                    "verified": False,
                    "risk": "BLOCKED_COMMAND",
                    "message": f"Command '{base_cmd}' is prohibited by security policy."
                }
        
        # 2. Check for pipe to shell (common RCE pattern: curl ... | bash)
        if re.search(r'\|\s*(bash|sh|zsh|ksh|python|perl|ruby|node)', cmd_lower):
            return {
                "verified": False,
                "risk": "PIPE_TO_SHELL",
                "message": "Piping to shell interpreter is prohibited (RCE risk)."
            }
        
        # 3. Check for path traversal / forbidden paths
        for pattern in self.forbidden_patterns:
            if pattern.search(command):
                return {
                    "verified": False,
                    "risk": "PATH_VIOLATION",
                    "message": f"Access to protected path pattern is denied."
                }
        
        # 4. Check for backticks or $() command substitution
        if '`' in command or '$(' in command:
            return {
                "verified": False,
                "risk": "COMMAND_SUBSTITUTION",
                "message": "Command substitution (backticks/$(...)  ) is prohibited."
            }
        
        return {"verified": True, "message": "Command passed security checks."}
    
    def verify_file_access(
        self, 
        filepath: Union[str, "os.PathLike[str]"],
        operation: str = "read"
    ) -> Dict[str, Any]:
        r"""
        Verify that a file path names a file inside an allowed directory.

        A path is allowed only when it is an allowed directory or below one,
        compared part by part, so "/tmp-exfil" is not inside "/tmp". This
        holds first for the path as written, before the file system is read,
        and then, exactly, for the path resolved as the file system shows it
        at the time of the call: links followed in order, "." and ".." parts
        and repeated separators removed (on Windows, existing parts spelt as
        on disk). Before resolving, the links on the way are read one by one,
        and a link that leads outside the allowed directories is refused
        without reading anything there: on Windows, a link to a network share
        would otherwise connect to its server. A part that is there but
        cannot be read (no permission, or a name the system refuses) is
        refused as INVALID_PATH: resolving would take it for a plain
        directory, and on Windows a junction can hide that it is one and
        still be followed. On Windows a link reached through another link
        is refused the same way when its target climbs with ".." or names
        a drive or a root alone: Windows reads such a target from the path
        that reached the link, which can lead elsewhere than the link's own
        folder.

        The forbidden patterns are matched against the path as written, and
        against the resolved path: anywhere in the part below its allowed
        directory, and from the start of the whole path when the match
        reaches below the allowed directory. A match within the allowed
        directory's own path does not count: the caller chose that
        directory.

        Refused before anything is read:
        - "~", or a first part starting with "~" followed by more parts: it
          names a home directory only if something expands it later, which
          this check cannot see;
        - a NUL character, bytes, more than MAX_PATH_CHARS characters or
          more than MAX_PATH_PARTS parts;
        - on Windows, device and NT namespace forms (\\?\, \\.\, \??\),
          alternate data streams ("file:stream"), reserved device names
          ("CON", "COM1.txt") and names that end with a dot or a space.

        Environment variables ("$HOME", "%USERPROFILE%") are not expanded: they
        are read as names. A caller that expands them after the check opens
        another path.

        An allowed directory that is itself a link or a junction is not
        used: whoever can replace it decides where it points. Name the
        directory it points to (on macOS, "/private/tmp" for "/tmp"). Nor
        is one inside another allowed directory with a link between them.
        Links in the parents of an allowed directory, outside every allowed
        directory, are followed: they are the caller's own setup.
        When the caller names no allowed directories, the defaults are
        "./workspace" and ".". The default "." is not used while the working
        directory is the root of a file system, and neither default is used
        while every user can write to it (the working directory in /tmp,
        say). That is not checked on Windows, where the mode bits do not
        say who may write. Name a shared directory to allow it.

        The answer holds for the file system at the time of the call. A link
        changed after the check can point elsewhere, and a hard link is the
        file it links to wherever that is. Open the ``resolved_path`` of an
        allowed result, not the path as given.

        Args:
            filepath: The path to check, a string or a path object.
            operation: "read" or "write" (for logging purposes).
        """
        if not filepath:
            return {"verified": False, "risk": "EMPTY_PATH", "message": "Empty file path."}
        try:
            # Once: a path object could give another string the next time.
            filepath = os.fspath(filepath)
        except (TypeError, ValueError):
            return self._invalid_path(_UNRESOLVED)
        refusal = self._refuse_as_written(filepath)
        if refusal is not None:
            return refusal

        # Inside an allowed directory as written, part by part, before the
        # file system is read: resolving a path reads it, and on Windows
        # reading a network path connects to its server.
        try:
            abs_path = os.path.abspath(filepath)
            # On Linux "link/.." is the parent of the link's target, so the
            # walk and the resolution start from the path as given, not from
            # its absolute form, where ".." has already been removed.
            given = abs_path if _ON_WINDOWS else (
                filepath if os.path.isabs(filepath) else os.path.join(os.getcwd(), filepath)
            )
        except (OSError, ValueError):
            return self._invalid_path(_UNRESOLVED)
        if max(_part_count(filepath), _part_count(abs_path)) > MAX_PATH_PARTS:
            return self._invalid_path("Path has too many parts.")
        roots = self._allowed_roots()
        if not any(_is_within(written, abs_path) or _is_within(resolved, abs_path)
                   for written, resolved in roots):
            return self._sandbox_escape(filepath)

        # The links on the way must lead inside before any is followed.
        forms = [form for root in roots for form in root]
        risk = _links_stay_inside(given, lambda part: any(
            _is_within(form, part) or _is_within(part, form) for form in forms
        ))
        if risk == _SANDBOX_ESCAPE:
            return self._sandbox_escape(filepath)
        if risk is not None:
            return self._invalid_path("Path has too many links, or a link or part that cannot be checked.")

        try:
            real_path = os.path.realpath(given)
        except (OSError, ValueError):
            return self._invalid_path(_UNRESOLVED)
        holding = [resolved for _, resolved in roots if _is_inside(resolved, real_path)]
        if not holding:
            return self._sandbox_escape(filepath)
        if any(self._forbidden_below(root, real_path) for root in holding):
            return self._forbidden_path()

        return {
            "verified": True,
            "message": f"File {operation} access permitted.",
            "resolved_path": real_path,
        }

    def _refuse_as_written(self, filepath: Any) -> Optional[Dict[str, Any]]:
        """A refusal for the path as written, or None when it may be resolved."""
        if not isinstance(filepath, str) or "\x00" in filepath:
            return self._invalid_path(_UNRESOLVED)
        if len(filepath) > MAX_PATH_CHARS:
            return self._invalid_path("Path is too long.")
        if _ON_WINDOWS and _is_windows_special(filepath):
            return self._invalid_path("Windows device, namespace and stream paths are refused.")
        if self._matches_forbidden(filepath):
            return self._forbidden_path()
        if _starts_at_home(filepath):
            return self._invalid_path(
                "A path that starts at '~' is refused: whether it names a home "
                "directory depends on expansion this check cannot see."
            )
        return None

    def _allowed_roots(self) -> List[Tuple[str, str]]:
        """
        Each usable allowed directory, as written (absolute) and resolved,
        taken now: the working directory may have changed since the guard
        was made.

        A directory whose last part is a link or a junction is not used:
        whoever can replace the link decides where it points. Nor is one
        inside another allowed directory with a link between the two, since
        whoever can write the outer directory can make that link. A default
        directory every user can write to is not used either.
        """
        entries = []
        for allowed_dir in self.allowed_paths:
            try:
                written = os.path.abspath(os.fspath(allowed_dir))
            except OSError:
                # A relative directory while the working directory is gone
                continue
            # Resolved as given: on Linux "link/.." is the parent of the
            # link's target. If that differs from the lexical form, the two
            # are different files and the directory is not used.
            resolved = os.path.realpath(allowed_dir)
            entries.append((written, resolved, _resolves_in_place(written, resolved)))
        return [
            (written, resolved)
            for written, resolved, in_place in entries
            if in_place
            and not self._default_at_filesystem_root(written, resolved)
            and not (self._default_allowed_paths and _writable_by_all(resolved))
            and self._nested_in_place(written, resolved, entries)
        ]

    def _default_at_filesystem_root(self, written: str, resolved: str) -> bool:
        # A default "." in a file system root would allow every path.
        return self._default_allowed_paths and (
            _is_filesystem_root(written) or _is_filesystem_root(resolved)
        )

    @staticmethod
    def _nested_in_place(written: str, resolved: str, entries: List[Tuple[str, str, bool]]) -> bool:
        """
        For every listed directory that holds ``written`` (used or not), it
        is not a link itself and ``resolved`` stays inside its resolution:
        a link between the two would take the inner directory elsewhere.
        """
        return all(
            outer_in_place and _is_inside(outer_resolved, resolved)
            for outer_written, outer_resolved, outer_in_place in entries
            if not _same_path(outer_written, written) and _is_within(outer_written, written)
        )

    def _forbidden_below(self, root: str, real_path: str) -> bool:
        """
        A forbidden pattern matches the resolved path below ``root``
        ("a/.env"), or matches the whole resolved path from its start and
        reaches below ``root`` ("/etc/passwd" with "/etc" allowed). A match
        within ``root``'s own path does not count: the caller chose it. Both
        are also read without invisible format characters.
        """
        readings = {(real_path, root), (_without_format_chars(real_path), _without_format_chars(root))}
        for path, base in readings:
            full = _slashed(path)
            head = len(_slashed(base).rstrip("/"))
            below = full[head:].lstrip("/")
            for pattern in self.forbidden_patterns:
                if below and pattern.search(below):
                    return True
                match = pattern.match(full)
                if match and match.end() > head:
                    return True
        return False

    @staticmethod
    def _sandbox_escape(filepath: str) -> Dict[str, Any]:
        return {
            "verified": False,
            "risk": _SANDBOX_ESCAPE,
            # repr: the path comes from the caller, and the message may be
            # printed to a terminal
            "message": f"Path {filepath!r} is outside allowed workspace."
        }

    def _matches_forbidden(self, path: str) -> bool:
        readings = {path, _without_format_chars(path)}
        return any(
            pattern.search(reading) for pattern in self.forbidden_patterns for reading in readings
        )

    @staticmethod
    def _forbidden_path() -> Dict[str, Any]:
        return {
            "verified": False,
            "risk": "FORBIDDEN_PATH",
            "message": "Access to path matching forbidden pattern is denied."
        }

    @staticmethod
    def _invalid_path(message: str) -> Dict[str, Any]:
        return {"verified": False, "risk": _INVALID_PATH, "message": message}
