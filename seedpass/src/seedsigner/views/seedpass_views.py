"""
SeedPass views: derive deterministic passwords from a loaded seed.

Flow overview
-------------
    Home
      New seed        -> SeedSigner's photo-entropy flow
      Scan            -> SeedSigner's QR scan flow
      Seeds           -> in-memory seed list
      Settings        -> SeedSigner's settings
                          (the first three finalize a seed and land on
                           SeedOptionsView, which redirects here)

    SeedPassMenuView            per-seed menu
      SeedPassLabelEntryView    type the service name (e.g. "my bank")
      SeedPassRotationView      optional rotation counter
      -- or --
      SeedPassIndexEntryView    raw BIP-85 index (advanced)
      -- or --
      SeedBackupView            SeedSigner's own seed words / SeedQR export

    SeedPassReviewView          confirm before any secret is shown
    SeedPassFormatView          full 256-bit, or the 16-char short form
    SeedPassWarningView         dire warning
    SeedPassPasswordView        the base64 password
    SeedPassExportView          export as QR, or done

Nothing is written to disk at any point.
"""
import logging

from dataclasses import dataclass
from gettext import gettext as _

from seedsigner.gui.components import SeedSignerIconConstants
from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
from seedsigner.gui.screens.screen import (ButtonListScreen, ButtonOption,
    DireWarningScreen, QRDisplayScreen, WarningScreen)
from seedsigner.gui.screens import seedpass_screens
from seedsigner.gui.screens import seed_screens
from seedsigner.models.seed import Seed
from seedsigner.models.seedpass import (DEFAULT_FORMAT, DerivedPassword,
    PasswordFormat, SeedPassError, derive_password)
from seedsigner.models.seedpass_identity import (IdentityError, derive_identity,
    label_for_uri, parse_auth_request, sign_challenge, uri_for_label, validate_uri)
from seedsigner.models.fido2_session import ArmedSession, SessionError, parse_prepare_uri
from seedsigner.models import sido3
from seedsigner.models.settings import SettingsConstants
from seedsigner.views.view import BackStackView, Destination, MainMenuView, View

logger = logging.getLogger(__name__)


# Characters per on-screen group, chosen so each format lands on a small number
# of readable lines: 46 chars -> 5 groups of 10; 16 chars -> 2 groups of 8.
CHUNK_SIZE = {
    PasswordFormat.FULL: 10,
    PasswordFormat.SHORT: 8,
}
DEFAULT_CHUNK_SIZE = 10



@dataclass
class SeedPassMenuView(View):
    """
    Per-seed menu. This is where every "load a seed" path ends up, so it stands
    in for SeedSigner's SeedOptionsView on a password-only device.
    """
    BY_NAME = ButtonOption("New / lookup by name")
    BY_INDEX = ButtonOption("By BIP-85 index")
    PUBLIC_KEY = ButtonOption("Public key")
    BACKUP = ButtonOption("Backup seed", right_icon_name=SeedSignerIconConstants.CHEVRON_RIGHT)
    DISCARD = ButtonOption("Discard seed", button_label_color="red")

    seed: Seed = None

    def __post_init__(self):
        super().__post_init__()
        if self.seed is None:
            # No seed to work with; send the user back to pick or load one.
            from seedsigner.views.seed_views import SeedsMenuView
            self.set_redirect(Destination(SeedsMenuView))
            return

        if not self.seed.bip85_supported:
            self.set_redirect(Destination(
                SeedPassUnsupportedSeedView,
                view_args=dict(seed=self.seed),
            ))


    def run(self):
        button_data = [self.BY_NAME, self.BY_INDEX, self.PUBLIC_KEY, self.BACKUP, self.DISCARD]

        selected_menu_num = self.run_screen(
            seed_screens.SeedSelectSeedScreen,
            title=_("Passwords"),
            text=self.seed.get_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK)),
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            # Always exit to Home rather than back into a possibly-cleared stack
            return Destination(MainMenuView)

        if button_data[selected_menu_num] == self.BY_NAME:
            return Destination(SeedPassLabelEntryView, view_args=dict(seed=self.seed))

        elif button_data[selected_menu_num] == self.BY_INDEX:
            return Destination(SeedPassIndexEntryView, view_args=dict(seed=self.seed))

        elif button_data[selected_menu_num] == self.PUBLIC_KEY:
            return Destination(SeedPassIdentityEntryView, view_args=dict(seed=self.seed))

        elif button_data[selected_menu_num] == self.BACKUP:
            # SeedSigner's own backup flow: view the words, or transcribe a
            # SeedQR. Its "Done" routes back through SeedOptionsView, which
            # redirects here, so the loop closes cleanly.
            from seedsigner.views.seed_views import SeedBackupView
            return Destination(SeedBackupView, view_args=dict(seed=self.seed))

        elif button_data[selected_menu_num] == self.DISCARD:
            from seedsigner.views.seed_views import SeedDiscardView
            return Destination(SeedDiscardView, view_args=dict(seed=self.seed))



@dataclass
class SeedPassUnsupportedSeedView(View):
    """Electrum seeds have no BIP-32 root we can run BIP-85 against."""
    seed: Seed = None

    def run(self):
        self.run_screen(
            WarningScreen,
            title=_("Passwords"),
            status_headline=_("Unsupported Seed"),
            text=_("This seed type does not support BIP-85 derivation."),
            button_data=[ButtonOption("Back to Main Menu")],
            show_back_button=False,
        )
        return Destination(MainMenuView, clear_history=True)



@dataclass
class SeedPassLabelEntryView(View):
    """Type the service name that identifies this password."""
    seed: Seed = None

    def run(self):
        ret = self.run_screen(seedpass_screens.SeedPassLabelEntryScreen)

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        return Destination(
            SeedPassRotationView,
            view_args=dict(seed=self.seed, label=ret),
        )



@dataclass
class SeedPassRotationView(View):
    """
    Ask whether this is a first-time password or a rotation. Rotating changes
    the BIP-85 index, and therefore the password, without changing the name.
    """
    FIRST = ButtonOption("First password (#0)")
    ROTATE = ButtonOption("Rotate / re-issue")

    seed: Seed = None
    label: str = None

    def run(self):
        button_data = [self.FIRST, self.ROTATE]

        selected_menu_num = self.run_screen(
            seed_screens.SeedSelectSeedScreen,
            title=_("Rotation"),
            text=self.label,
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.FIRST:
            return Destination(
                SeedPassReviewView,
                view_args=dict(seed=self.seed, label=self.label, counter=0),
            )

        return Destination(
            SeedPassCounterEntryView,
            view_args=dict(seed=self.seed, label=self.label),
        )



@dataclass
class SeedPassCounterEntryView(View):
    seed: Seed = None
    label: str = None

    def run(self):
        ret = self.run_screen(seedpass_screens.SeedPassCounterEntryScreen)

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        return Destination(
            SeedPassReviewView,
            view_args=dict(seed=self.seed, label=self.label, counter=int(ret)),
        )



@dataclass
class SeedPassIndexEntryView(View):
    """Advanced: derive straight from a BIP-85 index, no service name."""
    seed: Seed = None

    def run(self):
        ret = self.run_screen(seedpass_screens.SeedPassIndexEntryScreen)

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        return Destination(
            SeedPassReviewView,
            view_args=dict(seed=self.seed, index=int(ret)),
        )



@dataclass
class SeedPassErrorView(View):
    """Shown when the entered label/index/counter can't be used."""
    message: str = None
    next_destination: Destination = None

    def run(self):
        self.run_screen(
            DireWarningScreen,
            title=_("Passwords"),
            status_icon_name=SeedSignerIconConstants.ERROR,
            status_headline=_("Invalid Input"),
            text=self.message,
            show_back_button=False,
            button_data=[ButtonOption("Try again")],
        )
        return self.next_destination or Destination(MainMenuView, clear_history=True)



@dataclass
class SeedPassReviewView(View):
    """
    Last stop before a secret is displayed: shows what will be derived, without
    revealing any of it.
    """
    REVEAL = ButtonOption("Reveal password")
    CHANGE_FORMAT = ButtonOption("Change format")

    seed: Seed = None
    label: str = None
    index: int = None
    counter: int = 0
    fmt: str = DEFAULT_FORMAT

    def __post_init__(self):
        super().__post_init__()
        self.derived: DerivedPassword = None
        try:
            self.derived = derive_password(
                seed_bytes=self.seed.seed_bytes,
                label=self.label,
                index=self.index,
                counter=self.counter,
                fmt=self.fmt,
            )
        except SeedPassError as e:
            self.set_redirect(Destination(
                SeedPassErrorView,
                view_args=dict(
                    message=str(e),
                    next_destination=Destination(SeedPassMenuView, view_args=dict(seed=self.seed)),
                ),
            ))


    def run(self):
        button_data = [self.REVEAL, self.CHANGE_FORMAT]

        selected_menu_num = self.run_screen(
            seedpass_screens.SeedPassReviewScreen,
            label=self.derived.label,
            index=self.derived.index,
            format_name=_(PasswordFormat.display_name(self.derived.fmt)),
            fingerprint=self.derived.fingerprint,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.CHANGE_FORMAT:
            return Destination(
                SeedPassFormatView,
                view_args=dict(
                    seed=self.seed,
                    label=self.label,
                    index=self.index,
                    counter=self.counter,
                ),
            )

        return Destination(
            SeedPassWarningView,
            view_args=dict(
                seed=self.seed,
                label=self.label,
                index=self.index,
                counter=self.counter,
                fmt=self.fmt,
            ),
        )



@dataclass
class SeedPassFormatView(View):
    """Pick the full password or the 16-char short form."""
    seed: Seed = None
    label: str = None
    index: int = None
    counter: int = 0

    def run(self):
        button_data = [
            ButtonOption(PasswordFormat.display_name(fmt)) for fmt in PasswordFormat.ALL
        ]

        selected_menu_num = self.run_screen(
            seedpass_screens.SeedPassFormatScreen,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        return Destination(
            SeedPassReviewView,
            view_args=dict(
                seed=self.seed,
                label=self.label,
                index=self.index,
                counter=self.counter,
                fmt=PasswordFormat.ALL[selected_menu_num],
            ),
        )



@dataclass
class SeedPassWarningView(View):
    """Dire warning before any password characters hit the screen."""
    seed: Seed = None
    label: str = None
    index: int = None
    counter: int = 0
    fmt: str = DEFAULT_FORMAT

    def run(self):
        destination = Destination(
            SeedPassPasswordView,
            view_args=dict(
                seed=self.seed,
                label=self.label,
                index=self.index,
                counter=self.counter,
                fmt=self.fmt,
            ),
            skip_current_view=True,
        )

        if self.settings.get_value(SettingsConstants.SETTING__DIRE_WARNINGS) == SettingsConstants.OPTION__DISABLED:
            return destination

        selected_menu_num = self.run_screen(
            DireWarningScreen,
            text=_("This password is only as private as the screen you show it on."),
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        return destination



@dataclass
class SeedPassPasswordView(View):
    """Displays the password as fixed-width groups on a single screen."""
    DONE = ButtonOption("Done")

    seed: Seed = None
    label: str = None
    index: int = None
    counter: int = 0
    fmt: str = DEFAULT_FORMAT

    def __post_init__(self):
        super().__post_init__()
        self.derived = derive_password(
            seed_bytes=self.seed.seed_bytes,
            label=self.label,
            index=self.index,
            counter=self.counter,
            fmt=self.fmt,
        )
        self.heading = self.derived.label or _("Index {}").format(self.derived.index)


    def run(self):
        selected_menu_num = self.run_screen(
            seedpass_screens.SeedPassPasswordScreen,
            heading=self.heading,
            chunks=self.derived.chunks(CHUNK_SIZE.get(self.fmt, DEFAULT_CHUNK_SIZE)),
            button_data=[self.DONE],
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        return Destination(
            SeedPassExportView,
            view_args=dict(
                seed=self.seed,
                label=self.label,
                index=self.index,
                counter=self.counter,
                fmt=self.fmt,
            ),
        )



@dataclass
class SeedPassExportView(View):
    """Offer the two QR payload types, or just finish."""
    EXPORT_SECRET = ButtonOption("Export password QR", SeedSignerIconConstants.QRCODE)
    EXPORT_REF = ButtonOption("Export name-only QR", SeedSignerIconConstants.QRCODE)
    DONE = ButtonOption("Done")

    seed: Seed = None
    label: str = None
    index: int = None
    counter: int = 0
    fmt: str = DEFAULT_FORMAT

    def run(self):
        button_data = [self.EXPORT_SECRET, self.EXPORT_REF, self.DONE]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Export"),
            is_bottom_list=True,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.DONE:
            # Wipe history so BACK can't walk into the revealed password
            return Destination(
                SeedPassMenuView,
                view_args=dict(seed=self.seed),
                clear_history=True,
            )

        include_secret = button_data[selected_menu_num] == self.EXPORT_SECRET

        return Destination(
            SeedPassExportQRView,
            view_args=dict(
                seed=self.seed,
                label=self.label,
                index=self.index,
                counter=self.counter,
                fmt=self.fmt,
                include_secret=include_secret,
            ),
        )



@dataclass
class SeedPassExportQRView(View):
    """Renders the `seedpass://` payload as a static QR."""
    seed: Seed = None
    label: str = None
    index: int = None
    counter: int = 0
    fmt: str = DEFAULT_FORMAT
    include_secret: bool = False

    def __post_init__(self):
        super().__post_init__()
        derived = derive_password(
            seed_bytes=self.seed.seed_bytes,
            label=self.label,
            index=self.index,
            counter=self.counter,
            fmt=self.fmt,
        )
        self.uri = derived.to_uri(include_secret=self.include_secret)


    def run(self):
        from seedsigner.models.encode_qr import GenericStaticQrEncoder

        self.run_screen(
            QRDisplayScreen,
            qr_encoder=GenericStaticQrEncoder(data=self.uri),
        )

        return Destination(
            SeedPassExportView,
            view_args=dict(
                seed=self.seed,
                label=self.label,
                index=self.index,
                counter=self.counter,
                fmt=self.fmt,
            ),
            skip_current_view=True,
        )



@dataclass
class SeedPassIdentityEntryView(View):
    """
    Name the identity by hand: a service name, or a full URI.

    Mostly this is for a service name, which is short and matches the password
    flow. Typing a full URI is possible but rarely necessary -- if the service
    sends an authentication QR, that already carries its URI and the public key
    can be exported straight from the approval screen without typing anything.
    Hand entry is for registering with a service that asks for a public key
    out-of-band.

    Either way there is one SLIP-0013 derivation underneath: a bare name becomes
    `seedpass://<name>`, and a real URI is used as-is, which is what makes it
    interoperable with other SLIP-0013 implementations.
    """
    seed: Seed = None

    def run(self):
        ret = self.run_screen(seedpass_screens.SeedPassIdentityEntryScreen)

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        return Destination(
            SeedPassIdentityView,
            view_args=dict(seed=self.seed, entered=ret),
        )



@dataclass
class SeedPassIdentityView(View):
    """Shows the derived public key and offers to export it."""
    EXPORT = ButtonOption("Export public key QR", SeedSignerIconConstants.QRCODE)
    ROTATE = ButtonOption("Rotate / re-issue")
    DONE = ButtonOption("Done")

    seed: Seed = None
    entered: str = None
    index: int = 0

    def __post_init__(self):
        super().__post_init__()
        self.identity = None
        try:
            # "://" is the only thing distinguishing a URI from a service name.
            if "://" in self.entered:
                self.identity = derive_identity(
                    self.seed.seed_bytes, uri=validate_uri(self.entered), index=self.index,
                )
            else:
                self.identity = derive_identity(
                    self.seed.seed_bytes, label=self.entered, index=self.index,
                )
        except IdentityError as e:
            self.set_redirect(Destination(
                SeedPassErrorView,
                view_args=dict(
                    message=str(e),
                    next_destination=Destination(SeedPassMenuView, view_args=dict(seed=self.seed)),
                ),
            ))


    def run(self):
        button_data = [self.EXPORT, self.ROTATE, self.DONE]

        selected_menu_num = self.run_screen(
            seedpass_screens.SeedPassIdentityScreen,
            identity_uri=self.identity.uri,
            index=self.identity.index,
            public_key=self.identity.public_key,
            fingerprint=self.identity.fingerprint,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.EXPORT:
            return Destination(
                SeedPassIdentityQRView,
                view_args=dict(seed=self.seed, entered=self.entered, index=self.index),
            )

        elif button_data[selected_menu_num] == self.ROTATE:
            return Destination(
                SeedPassIdentityView,
                view_args=dict(seed=self.seed, entered=self.entered, index=self.index + 1),
            )

        return Destination(
            SeedPassMenuView, view_args=dict(seed=self.seed), clear_history=True,
        )



@dataclass
class SeedPassIdentityQRView(View):
    """Renders the public key as a QR for a service to register."""
    seed: Seed = None
    entered: str = None
    index: int = 0

    def __post_init__(self):
        super().__post_init__()
        if "://" in self.entered:
            self.identity = derive_identity(self.seed.seed_bytes, uri=self.entered, index=self.index)
        else:
            self.identity = derive_identity(self.seed.seed_bytes, label=self.entered, index=self.index)


    def run(self):
        from seedsigner.models.encode_qr import GenericStaticQrEncoder

        self.run_screen(
            QRDisplayScreen,
            qr_encoder=GenericStaticQrEncoder(data=self.identity.to_uri()),
        )

        return Destination(
            SeedPassIdentityView,
            view_args=dict(seed=self.seed, entered=self.entered, index=self.index),
            skip_current_view=True,
        )



@dataclass
class SeedPassAuthRequestView(View):
    """
    Approve and sign a service's authentication request.

    Reached by scanning a `seedpass://v1/auth?...` QR. The URI and the visual
    challenge are shown before anything is signed: SLIP-0013 puts the visual
    challenge in the protocol precisely so a person can see what they are
    approving, and it is the only thing preventing a signature for a lookalike
    service.
    """
    APPROVE = ButtonOption("Sign in")
    PUBLIC_KEY = ButtonOption("Public key for this service")
    CANCEL = ButtonOption("Cancel")

    seed: Seed = None
    request: dict = None

    def __post_init__(self):
        super().__post_init__()
        if self.seed is None:
            self.set_redirect(Destination(SeedPassSelectSeedForAuthView, view_args=dict(request=self.request)))


    def run(self):
        # Registering by scanning: the request already names the service, so
        # there is no reason to make anyone re-type the URI on a joystick
        # keyboard just to get the public key for it.
        button_data = [self.APPROVE, self.PUBLIC_KEY, self.CANCEL]

        selected_menu_num = self.run_screen(
            seedpass_screens.SeedPassAuthRequestScreen,
            identity_uri=self.request["uri"],
            visual_challenge=self.request.get("visual"),
            fingerprint=self.seed.get_fingerprint(
                self.settings.get_value(SettingsConstants.SETTING__NETWORK)
            ),
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.CANCEL:
            return Destination(MainMenuView, clear_history=True)

        elif button_data[selected_menu_num] == self.PUBLIC_KEY:
            return Destination(
                SeedPassIdentityView,
                view_args=dict(
                    seed=self.seed,
                    entered=self.request["uri"],
                    index=self.request.get("index", 0),
                ),
            )

        # Deliberately not skip_current_view: the approval screen stays in
        # history so BACK from the QR returns to what was approved.
        return Destination(
            SeedPassAuthSignedQRView,
            view_args=dict(seed=self.seed, request=self.request),
        )



@dataclass
class SeedPassSelectSeedForAuthView(View):
    """Pick which loaded seed answers an authentication request."""
    request: dict = None

    def run(self):
        seeds = self.controller.storage.seeds
        if not seeds:
            return Destination(
                SeedPassErrorView,
                view_args=dict(message=_("Load a seed first"), next_destination=Destination(MainMenuView)),
            )

        button_data = [
            ButtonOption(
                seed.get_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK)),
                SeedSignerIconConstants.FINGERPRINT,
                icon_color="blue",
            )
            for seed in seeds
        ]

        selected_menu_num = self.run_screen(
            seed_screens.SeedSelectSeedScreen,
            title=_("Sign In"),
            text=self.request["uri"],
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        return Destination(
            SeedPassAuthRequestView,
            view_args=dict(seed=seeds[selected_menu_num], request=self.request),
            skip_current_view=True,
        )



@dataclass
class SeedPassAuthSignedQRView(View):
    """
    The signed response, as a QR.

    Carries the signature and the public key, so a service seeing this identity
    for the first time can register it and recognise it thereafter -- exactly
    the three-way branch SLIP-0013 describes.
    """
    seed: Seed = None
    request: dict = None

    def __post_init__(self):
        super().__post_init__()
        signature = sign_challenge(
            seed_bytes=self.seed.seed_bytes,
            uri=self.request["uri"],
            hidden=self.request.get("hidden", b""),
            visual=self.request.get("visual", ""),
            index=self.request.get("index", 0),
        )
        identity = derive_identity(
            self.seed.seed_bytes, uri=self.request["uri"], index=self.request.get("index", 0),
        )

        from urllib.parse import quote
        self.payload = (
            "seedpass://v1/authresp?"
            + f"id={quote(self.request['uri'], safe='')}"
            + f"&idx={self.request.get('index', 0)}"
            + f"&pk={identity.public_key}"
            + f"&sig={quote(signature, safe='')}"
        )


    def run(self):
        from seedsigner.models.encode_qr import GenericStaticQrEncoder

        self.run_screen(
            QRDisplayScreen,
            qr_encoder=GenericStaticQrEncoder(data=self.payload),
        )

        return Destination(MainMenuView, clear_history=True)



@dataclass
class SeedPassFido2PrepareView(View):
    """
    Arm a FIDO2 session for one relying party.

    Reached by scanning `seedpass://v1/fido2?rp=<rpid>`, which the companion app
    produces from the site's URL -- so the RP arrives by camera rather than
    being typed on a joystick keyboard.

    The seed stays loaded for the session; see fido2_session for why an earlier
    design that dropped it could not work. What arming buys is that the device
    will answer for this RP and no other, whatever the host asks for.
    """
    seed: Seed = None
    request: dict = None

    def __post_init__(self):
        super().__post_init__()
        if self.seed is None:
            from seedsigner.views.seed_views import SeedsMenuView
            self.set_redirect(Destination(SeedsMenuView))


    def run(self):
        rp_id = self.request["rp_id"]

        selected_menu_num = self.run_screen(
            seedpass_screens.SeedPassFido2ConfirmScreen,
            rp_id=rp_id,
            action=_("register") if self.request.get("nonce") is None else _("sign in"),
            button_data=[ButtonOption("Arm this site"), ButtonOption("Cancel")],
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON or selected_menu_num == 1:
            return Destination(MainMenuView, clear_history=True)

        try:
            session = ArmedSession(
                self.seed.seed_bytes, rp_id, nonce=self.request.get("nonce"),
            )
        except SessionError as e:
            return Destination(
                SeedPassErrorView,
                view_args=dict(message=str(e), next_destination=Destination(MainMenuView)),
            )

        return Destination(
            SeedPassFido2ArmedView,
            view_args=dict(seed=self.seed, session=session),
            skip_current_view=True,
        )



@dataclass
class SeedPassFido2ArmedView(View):
    """
    Serve CTAP2 over USB for the armed relying party.

    The USB loop runs here on the main thread rather than in a background
    worker. That keeps the confirmation prompt simple -- it is just another
    screen this view puts up -- and it means the back button still works between
    packets, so the session can be ended without unplugging anything.
    """
    seed: Seed = None
    session: ArmedSession = None
    transport: object = None

    def run(self):
        from seedsigner.models.fido2_authenticator import Authenticator
        from seedsigner.models import fido2_ctaphid as ctaphid
        from seedsigner.models.fido2_transport import HidTransport, TransportError

        transport = self.transport or HidTransport()
        authenticator = Authenticator(self.seed.seed_bytes, confirm=self._confirm)
        hid = ctaphid.CtapHid()

        try:
            transport.open()
        except TransportError as e:
            return Destination(
                SeedPassErrorView,
                view_args=dict(message=str(e), next_destination=Destination(MainMenuView)),
            )

        try:
            while True:
                # The armed screen doubles as the idle state: it returns as soon
                # as the user presses a button, which is how the session ends.
                if self._user_wants_out():
                    return Destination(MainMenuView, clear_history=True)

                packet = transport.read_packet()
                if packet is None:
                    continue

                message = hid.handle_packet(packet)
                transport.write_packets(hid.take_responses())

                if message is None:
                    continue

                channel, command, payload = message
                if command == ctaphid.CMD_CBOR:
                    response = authenticator.handle(payload)
                    transport.write_packets(
                        ctaphid.build_packets(channel, ctaphid.CMD_CBOR, response)
                    )
                elif command == ctaphid.CMD_PING:
                    # Echo, per the spec. Useful for a host to prove the link.
                    transport.write_packets(
                        ctaphid.build_packets(channel, ctaphid.CMD_PING, payload)
                    )
                elif command == ctaphid.CMD_CANCEL:
                    pass

        except TransportError:
            # The host went away, or the cable was pulled. Not an error worth a
            # screen; the session is simply over.
            return Destination(MainMenuView, clear_history=True)
        finally:
            transport.close()


    def _user_wants_out(self) -> bool:
        """
        Show the armed screen and check for a button press.

        Returns True when the user ends the session. The screen is re-rendered
        each pass, which also refreshes the request count.
        """
        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON as BACK

        result = self.run_screen(
            seedpass_screens.SeedPassFido2ArmedScreen,
            rp_id=self.session.rp_id,
            button_data=[ButtonOption("End session")],
        )
        return result is not None


    def _confirm(self, rp_id: str, action: str) -> bool:
        """
        User presence: the callback CTAP2 invokes before touching a key.

        Two gates, not one. The session must already be armed for this RP --
        which stops a host asking about a site the user never approved -- and
        then a human has to press the button. The first is automatic and the
        second is not.
        """
        if not self.session.matches(rp_id):
            return False

        selected_menu_num = self.run_screen(
            seedpass_screens.SeedPassFido2ConfirmScreen,
            rp_id=rp_id,
            action=action,
            button_data=[ButtonOption("Approve"), ButtonOption("Deny")],
        )

        return selected_menu_num == 0



@dataclass
class SeedPassSido3RequestView(View):
    """
    Sign a WebAuthn request relayed from the companion app.

    Reached by scanning a `sido3://` QR. The request carries the origin the
    browser reported, which the OS gave the companion app and which a web page
    cannot forge -- that is what makes this flow phishing-resistant where a
    plain QR login is not.

    The origin is checked against the RP ID again here. The browser already did
    it and the relay is supposed to pass both through untouched, but a bug in
    the relay must not be able to become a signature for the wrong site.
    """
    seed: Seed = None
    request: dict = None

    def __post_init__(self):
        super().__post_init__()
        if self.seed is None:
            self.set_redirect(Destination(
                SeedPassSido3SelectSeedView, view_args=dict(request=self.request),
            ))


    def run(self):
        request = self.request

        selected_menu_num = self.run_screen(
            seedpass_screens.SeedPassSido3ApproveScreen,
            origin=request["origin"],
            rp_id=request["rp_id"],
            operation=request["operation"],
            user_name=request.get("user_name"),
            fingerprint=self.seed.get_fingerprint(
                self.settings.get_value(SettingsConstants.SETTING__NETWORK)
            ),
            button_data=[ButtonOption("Approve"), ButtonOption("Deny")],
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON or selected_menu_num == 1:
            return Destination(MainMenuView, clear_history=True)

        try:
            payload = sido3.sign_request(self.seed.seed_bytes, request)
        except sido3.Sido3Error as e:
            return Destination(
                SeedPassErrorView,
                view_args=dict(message=str(e), next_destination=Destination(MainMenuView)),
            )

        return Destination(
            SeedPassSido3ResponseView,
            view_args=dict(payload=payload),
            skip_current_view=True,
        )



@dataclass
class SeedPassSido3SelectSeedView(View):
    """Pick which loaded seed answers a SIDO3 request."""
    request: dict = None

    def run(self):
        seeds = self.controller.storage.seeds
        if not seeds:
            return Destination(
                SeedPassErrorView,
                view_args=dict(
                    message=_("Load a seed first"),
                    next_destination=Destination(MainMenuView),
                ),
            )

        button_data = [
            ButtonOption(
                seed.get_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK)),
                SeedSignerIconConstants.FINGERPRINT,
                icon_color="blue",
            )
            for seed in seeds
        ]

        selected_menu_num = self.run_screen(
            seed_screens.SeedSelectSeedScreen,
            title=_("Sign In"),
            text=self.request["origin"],
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        return Destination(
            SeedPassSido3RequestView,
            view_args=dict(seed=seeds[selected_menu_num], request=self.request),
            skip_current_view=True,
        )



@dataclass
class SeedPassSido3ResponseView(View):
    """The signed response, for the companion app to scan and hand to Android."""
    payload: str = None

    def run(self):
        from seedsigner.models.encode_qr import GenericStaticQrEncoder

        self.run_screen(
            QRDisplayScreen,
            qr_encoder=GenericStaticQrEncoder(data=self.payload),
        )

        return Destination(MainMenuView, clear_history=True)
