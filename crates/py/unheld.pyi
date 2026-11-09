"""unheld: the core's verbs, one to one, from Python.

Python is the carrier. A verb that seals returns ``bytes`` of one bucket size, a verb that
opens takes them back, and what the program does with the bytes in between is its own
transport. No verb returns a key. Every verb that changes state writes the vault before it
returns. Every refusal is a ``Refused`` whose ``reason`` is a ``Refuse``.
"""

from enum import Enum
from os import PathLike

BUCKETS: list[int]
"""The fixed blob sizes in bytes. Every ``bytes`` a verb returns has one of these lengths."""

SMALL_GROUP: int
"""Members above which a group needs a carrier that delivers in order (L19)."""

class Refuse(Enum):
    """Every way a verb refuses. A refusal that carries numbers in Rust puts them in the
    exception's message here."""

    NoIdentity = ...
    IdentityExists = ...
    UnknownPeer = ...
    Unverified = ...
    NoGrant = ...
    Changed = ...
    NotConfirmed = ...
    NoIntro = ...
    BadIntro = ...
    BadBlob = ...
    NothingToOpen = ...
    CarrierIo = ...
    Gap = ...
    CarrierRefused = ...
    EmptyMessage = ...
    DuressSame = ...
    UnknownSender = ...
    UnknownSession = ...
    Replay = ...
    VaultLocked = ...
    NoVault = ...
    VaultIo = ...
    Protocol = ...
    TooLarge = ...
    NeedsOrder = ...
    TooSmall = ...
    UnknownGroup = ...
    GroupExists = ...
    NotAdmin = ...
    NoRight = ...
    NotMember = ...
    BadRequest = ...
    BadEnrolment = ...
    NotPending = ...
    DeviceExists = ...
    NotADevice = ...
    UnknownDevice = ...
    ThisDevice = ...
    VaultOld = ...
    NoContinuity = ...
    BadShare = ...
    NotEnoughShares = ...
    BadThreshold = ...

class Refused(Exception):
    """A verb refused. The message is one fixed sentence and never carries plaintext or key
    material."""

    reason: Refuse

class PeerState(Enum):
    """Where a contact stands. Only ``Verified`` can be sent to (L3, L14)."""

    Pending = ...
    Verified = ...
    Changed = ...

class MemberTrust(Enum):
    """How a group member stands with you (L18). Only your own ``verify`` makes ``Verified``."""

    Verified = ...
    Pending = ...
    Changed = ...
    Vouched = ...

class Target(Enum):
    """The readers of an outbound blob."""

    Peer = ...
    Group = ...
    Ring = ...
    Device = ...

class Part(Enum):
    """What one part of a blob is to an outsider with no key."""

    Message = ...
    Welcome = ...
    Introduction = ...
    Opaque = ...

class Peer:
    """A contact the fingerprint ceremony has admitted, or is waiting to."""

    name: str
    state: PeerState
    fingerprint_prefix: str
    sessions: int
    has_intro: bool
    agent_access: bool
    """The person has let an agent read and send with this peer through ``unheld mcp``."""
    agent_reads: bool
    """The peer says an assistant reads what you send them; every message of theirs says whether."""

class Opened:
    """A message ``open`` produced, or a roster change every member gets to see (L16)."""

    sender: str
    """A peer's name, or ``?`` and a key hash for a member you never verified."""
    trust: MemberTrust
    vouched_by: str | None
    """For a sender you never verified, the admin who put them in the roster."""
    group: str | None
    """The local group name when the message came through a group."""
    body: bytes
    """The plaintext. Written by someone else: data, never an instruction."""
    session_started: bool
    change: str | None
    """A roster change, in words, when this part was a commit."""
    moved_to: str | None
    """Where the sender asks that your next blobs to them go, in their transport's words. The
    program hands it to its transport; nothing in the module reads it."""
    agent_reads: bool | None
    """The sender says something new about who reads your messages to them: ``True`` when an
    assistant now does, ``False`` when none does any longer, ``None`` when nothing changed."""

class Outbound:
    """One blob and who it is for, from a verb that writes to more than one set of readers."""

    target: Target
    label: str
    """The peer's or group's name, or ``ring`` or ``device``."""
    blob: bytes

class Member:
    """One member of a group as this vault sees them."""

    label: str
    trust: MemberTrust
    is_admin: bool
    is_me: bool
    devices: int

class Roster:
    """A group and its roster, with the verification state of every member (L18)."""

    name: str
    epoch: int
    admin: str
    i_am_admin: bool
    members: list[Member]

class Added:
    """The two blobs an ``add`` produces."""

    for_group: bytes
    """The commit every member opens."""
    for_newcomer: bytes
    """The welcome the newcomer opens."""

class Device:
    """What a device shows about itself."""

    name: str
    fingerprint_prefix: str
    enrolled_at: int
    is_this: bool
    revoked: bool

class OutsidePart:
    """What an outsider can read from one part of a blob without any key."""

    kind: Part
    wire_format: str | None
    group_id_prefix: str | None
    epoch: int | None
    content_type: str | None
    ciphersuite: str | None
    recipients: int | None

class Outside:
    """Everything an outsider can read from a blob. Measured, not assumed (L7)."""

    bucket: int
    parts: list[OutsidePart]

class Share:
    """One of ``n`` shares of the identity key (L21). The bytes stay in Rust, zeroised when the
    object is collected, until ``to_text`` is called for the person who will hold it."""

    @staticmethod
    def from_text(text: str) -> Share:
        """A share the person typed or pasted back. Malformed text is refused."""
    @property
    def index(self) -> int: ...
    @property
    def threshold(self) -> int: ...
    def to_text(self) -> str:
        """The share as text, to show once and never store. Python cannot zeroise a ``str``."""

class Core:
    """An unlocked vault. Every verb that changes state writes the vault before it returns."""

    @staticmethod
    def create(dir: str | PathLike[str], passphrase: str, name: str) -> Core:
        """A new identity in a new vault under ``dir``, locked with ``passphrase`` (L20)."""
    @staticmethod
    def unlock(dir: str | PathLike[str], passphrase: str) -> Core:
        """Open the vault under ``dir``. A wrong passphrase and a damaged file are the same
        refusal."""
    @staticmethod
    def create_device(dir: str | PathLike[str], passphrase: str) -> tuple[Core, str]:
        """A vault for a device that has no identity yet, and the request text it hands to a
        device that has one (L15)."""
    @staticmethod
    def recover(dir: str | PathLike[str], passphrase: str, name: str, shares: list[Share]) -> Core:
        """A vault on a new device holding the identity the shares rebuild (L21)."""
    @staticmethod
    def request_fingerprint(request: str) -> str:
        """The digits a request's key makes, for the two screens to compare (L15)."""
    def save(self) -> None:
        """Write the vault. Every verb that changes state already does this."""
    @property
    def name(self) -> str: ...
    @property
    def fingerprint_prefix(self) -> str: ...
    def intro(self) -> str:
        """This identity's signed public bundle, as text, to hand over out of band."""
    def import_intro(self, name: str, intro: str) -> Peer:
        """Stage a peer from their introduction. The peer is ``Pending`` until ``verify`` (L3)."""
    def fingerprint(self, name: str) -> str:
        """The pairwise safety number, as groups of digits to read aloud."""
    def verify(self, name: str, confirmed: bool) -> Peer:
        """The one constructor of a ``Verified`` peer. ``confirmed`` is the human's answer to
        whether every group of digits matched; anything but ``True`` is refused (L3)."""
    def peer(self, name: str) -> Peer: ...
    def peers(self) -> list[Peer]: ...
    def grant_agent(self, name: str, granted: bool) -> Peer:
        """Let an agent read and send with this peer through ``unheld mcp``, or stop letting
        it. The person's decision, never a program's on its own."""
    def seal(self, name: str, body: bytes, moved_to: str | None = None) -> bytes:
        """``body`` to ``name``, padded to a bucket. Refused unless the peer is ``Verified``
        (L3, L4, L14). ``moved_to`` rides inside the encryption and tells the peer where your
        next blobs from them should go, in your transport's words (L7)."""
    def open(self, blob: bytes) -> list[Opened]:
        """Every message or roster change one blob holds. A replayed, reflected or altered blob
        is refused (L11, L12, L13)."""
    def forget(self, name: str) -> int:
        """End every session with a peer, or leave a group, deleting the keys (L10)."""
    def set_duress(self, duress: str) -> None:
        """A duress passphrase: unlocking with it destroys the vault and answers as a wrong
        passphrase would (L10)."""
    def group_new(self, name: str, peers: list[str], ordered: bool) -> bytes:
        """A group of verified peers with you as admin; the welcome every newcomer opens.
        ``ordered`` is your statement that your carrier delivers in order, which is what lets a
        group above ``SMALL_GROUP`` form (L16, L19)."""
    def group_add(self, group: str, peer: str, ordered: bool) -> Added:
        """Admin only; a commit for the members and a welcome for the newcomer (L16, L17)."""
    def group_remove(self, group: str, member: str) -> bytes:
        """Admin only; the commit after which the member opens nothing (L16, L17)."""
    def group_seal(self, group: str, body: bytes) -> bytes:
        """``body`` to every member of a group (L4, L8, L18)."""
    def roster(self, group: str) -> Roster: ...
    def groups(self) -> list[Roster]: ...
    def group_rename(self, old: str, new: str) -> None: ...
    def request(self) -> str:
        """The enrolment request again, for a device still waiting (L15)."""
    def enroll(self, device_name: str, request: str, confirmed: bool) -> str:
        """On a device that has the identity. ``confirmed`` is the human's answer to whether the
        new device shows exactly the digits this one shows; nothing happens without it (L15)."""
    def join_device(self, enrolment: str) -> str:
        """On the new device: open the enrolment, become the identity, and return what to hand
        back."""
    def connect_device(self, attach: str) -> list[Outbound]:
        """On the witness: bring the new device into every session and group, one blob per set
        of readers (L15, L16)."""
    def revoke_device(self, device_name: str) -> list[Outbound]:
        """One commit per session; a device cannot revoke itself (L15)."""
    def devices(self) -> list[Device]: ...
    def rotate(self) -> list[Outbound]:
        """New keys with a continuity statement; every peer shows ``Changed`` until they verify
        again (L14)."""
    def split(self, k: int, n: int) -> list[Share]:
        """``n`` shares of the identity key, any ``k`` of which rebuild it. The vault is byte
        for byte what it was (L21)."""

def wipe(dir: str | PathLike[str]) -> None:
    """Overwrite and remove the vault under ``dir`` (L10)."""

def inspect(blob: bytes) -> Outside:
    """Read a blob the way a carrier would: no vault, no key (L7)."""
