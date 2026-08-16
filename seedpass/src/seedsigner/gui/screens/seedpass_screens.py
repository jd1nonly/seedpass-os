"""
Screens for the SeedPass password derivation flow.

Presentation only: no derivation logic lives here. Follows the same conventions
as `seed_screens.py` so it inherits SeedSigner's existing button handling,
scrolling and dire-warning edges.
"""
import logging

from dataclasses import dataclass, field
from gettext import gettext as _
from typing import List

from seedsigner.gui.components import (Fonts, IconTextLine, SeedSignerIconConstants,
    TextArea, GUIConstants)
from seedsigner.gui.keyboard import Keyboard

from .screen import ButtonListScreen, KeyboardScreen, WarningEdgesMixin

logger = logging.getLogger(__name__)


# Chars a user can type into a service label. Mirrors LABEL_ALLOWED_CHARS in
# models/seedpass.py minus the ones that are awkward on a 240x240 keyboard.
LABEL_KEYS_CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789.-"


@dataclass
class SeedPassLabelEntryScreen(KeyboardScreen):
    """Lowercase-only keyboard for typing a service label (e.g. "my bank")."""

    def __post_init__(self):
        # TRANSLATOR_NOTE: Prompt to type the name of the site/service
        self.title = _("Service Name")

        self.rows = 5
        self.cols = 9
        self.keys_charset = LABEL_KEYS_CHARSET
        self.show_save_button = True
        self.custom_additional_keys = [
            Keyboard.KEY_SPACE_2,
            Keyboard.KEY_BACKSPACE_2,
        ]

        super().__post_init__()



@dataclass
class SeedPassCounterEntryScreen(KeyboardScreen):
    """Numeric entry for the rotation counter."""

    def __post_init__(self):
        # TRANSLATOR_NOTE: How many times this password has been rotated/changed
        self.title = _("Rotation #")

        self.rows = 3
        self.cols = 5
        self.keys_charset = "0123456789"
        self.show_save_button = True
        self.custom_additional_keys = [Keyboard.KEY_BACKSPACE_5]

        super().__post_init__()



@dataclass
class SeedPassIndexEntryScreen(KeyboardScreen):
    """Numeric entry for a raw BIP-85 child index (advanced mode)."""

    def __post_init__(self):
        self.title = _("BIP-85 Index")

        self.rows = 3
        self.cols = 5
        self.keys_charset = "0123456789"
        self.show_save_button = True
        self.custom_additional_keys = [Keyboard.KEY_BACKSPACE_5]

        super().__post_init__()



@dataclass
class SeedPassReviewScreen(ButtonListScreen):
    """
    Confirms what is about to be derived *before* any secret hits the screen.
    """
    is_bottom_list: bool = True
    label: str = None
    index: int = 0
    format_name: str = None
    fingerprint: str = None

    def __post_init__(self):
        # TRANSLATOR_NOTE: Summary of the password about to be derived
        self.title = _("Password")
        super().__post_init__()

        if self.label:
            display_label = self.label
        else:
            # TRANSLATOR_NOTE: Shown when deriving by raw index instead of a name
            display_label = _("(by index)")

        self.components.append(IconTextLine(
            icon_name=SeedSignerIconConstants.PASSPHRASE,
            icon_color=GUIConstants.INFO_COLOR,
            label_text=_("Service"),
            value_text=display_label,
            screen_x=GUIConstants.COMPONENT_PADDING,
            screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING,
            auto_line_break=True,
        ))

        self.components.append(IconTextLine(
            icon_name=SeedSignerIconConstants.DERIVATION,
            icon_color=GUIConstants.INFO_COLOR,
            label_text=_("BIP-85 index"),
            value_text=f"{self.index}",
            screen_x=GUIConstants.COMPONENT_PADDING,
            screen_y=self.components[-1].screen_y + self.components[-1].height + int(1.5*GUIConstants.COMPONENT_PADDING),
        ))

        self.components.append(IconTextLine(
            icon_name=SeedSignerIconConstants.FINGERPRINT,
            icon_color=GUIConstants.INFO_COLOR,
            label_text=_("Format / seed"),
            value_text=f"{self.format_name}  {self.fingerprint}",
            screen_x=GUIConstants.COMPONENT_PADDING,
            screen_y=self.components[-1].screen_y + self.components[-1].height + int(1.5*GUIConstants.COMPONENT_PADDING),
        ))



@dataclass
class SeedPassIdentityEntryScreen(KeyboardScreen):
    """
    Keyboard for naming an identity.

    Allows ':' and '/' on top of the label charset, so a real URI such as
    `https://example.com` can be typed as well as a bare service name.
    """

    def __post_init__(self):
        # TRANSLATOR_NOTE: Prompt to type a service name or full URI
        self.title = _("Service or URI")

        self.rows = 5
        self.cols = 9
        self.keys_charset = LABEL_KEYS_CHARSET + ":/"
        self.show_save_button = True
        self.custom_additional_keys = [
            Keyboard.KEY_SPACE_2,
            Keyboard.KEY_BACKSPACE_2,
        ]

        super().__post_init__()



@dataclass
class SeedPassIdentityScreen(ButtonListScreen):
    """
    Shows a derived identity: what it is, and the public key a service stores.

    The URI is shown in full and deliberately not abbreviated -- it is the thing
    the signature is bound to, and the only defence against approving an
    identity for the wrong service.
    """
    is_bottom_list: bool = True
    identity_uri: str = None
    index: int = 0
    public_key: str = None
    fingerprint: str = None

    def __post_init__(self):
        self.title = _("Public Key")
        super().__post_init__()

        self.components.append(IconTextLine(
            icon_name=SeedSignerIconConstants.PASSPHRASE,
            icon_color=GUIConstants.INFO_COLOR,
            label_text=_("Identity"),
            value_text=self.identity_uri,
            screen_x=GUIConstants.COMPONENT_PADDING,
            screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING,
            auto_line_break=True,
        ))

        self.components.append(IconTextLine(
            icon_name=SeedSignerIconConstants.DERIVATION,
            icon_color=GUIConstants.INFO_COLOR,
            label_text=_("Rotation / seed"),
            value_text=f"{self.index}  {self.fingerprint}",
            screen_x=GUIConstants.COMPONENT_PADDING,
            screen_y=self.components[-1].screen_y + self.components[-1].height + int(1.5*GUIConstants.COMPONENT_PADDING),
        ))

        # The public key is not secret, so unlike a password it can be shown in
        # full without a dire warning.
        self.components.append(TextArea(
            text=self.public_key,
            font_name=GUIConstants.FIXED_WIDTH_FONT_NAME,
            font_size=GUIConstants.get_body_font_size() - 3,
            is_text_centered=True,
            screen_y=self.components[-1].screen_y + self.components[-1].height + int(1.5*GUIConstants.COMPONENT_PADDING),
        ))



@dataclass
class SeedPassAuthRequestScreen(ButtonListScreen):
    """
    Approval screen for a service's authentication request.

    SLIP-0013 splits the challenge in two on purpose: the hidden part is random
    bytes the user never sees, and the visual part is human-readable text meant
    to be shown here. Both are displayed as prominently as they can be, because
    a user checking the URI is the only thing standing between them and signing
    for a lookalike service.
    """
    is_bottom_list: bool = True
    identity_uri: str = None
    visual_challenge: str = None
    fingerprint: str = None

    def __post_init__(self):
        self.title = _("Sign In")
        super().__post_init__()

        self.components.append(IconTextLine(
            icon_name=SeedSignerIconConstants.PASSPHRASE,
            icon_color=GUIConstants.INFO_COLOR,
            label_text=_("Sign in to"),
            value_text=self.identity_uri,
            screen_x=GUIConstants.COMPONENT_PADDING,
            screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING,
            auto_line_break=True,
        ))

        if self.visual_challenge:
            self.components.append(IconTextLine(
                icon_name=SeedSignerIconConstants.CHECK,
                icon_color=GUIConstants.INFO_COLOR,
                label_text=_("Challenge"),
                value_text=self.visual_challenge,
                screen_x=GUIConstants.COMPONENT_PADDING,
                screen_y=self.components[-1].screen_y + self.components[-1].height + int(1.5*GUIConstants.COMPONENT_PADDING),
                auto_line_break=True,
            ))

        self.components.append(IconTextLine(
            icon_name=SeedSignerIconConstants.FINGERPRINT,
            icon_color=GUIConstants.INFO_COLOR,
            label_text=_("Signing with"),
            value_text=self.fingerprint,
            screen_x=GUIConstants.COMPONENT_PADDING,
            screen_y=self.components[-1].screen_y + self.components[-1].height + int(1.5*GUIConstants.COMPONENT_PADDING),
        ))



@dataclass
class SeedPassPasswordScreen(WarningEdgesMixin, ButtonListScreen):
    """
    Displays the derived password in fixed-width chunks.

    base64 has none of a mnemonic's self-correcting redundancy, so the layout
    leans hard on legibility: monospace, short groups, and an explicit warning
    that the groups are display-only.
    """
    chunks: List[str] = field(default_factory=list)
    heading: str = None
    is_bottom_list: bool = True
    status_color: str = GUIConstants.DIRE_WARNING_COLOR

    def __post_init__(self):
        self.title = self.heading or _("Password")
        super().__post_init__()

        # The full password is 46 chars; at a fixed large font its groups would
        # run off the bottom. Size the font to whichever constraint binds first,
        # vertical or horizontal.
        body_y = self.top_nav.height + GUIConstants.COMPONENT_PADDING
        body_height = self.buttons[0].screen_y - body_y
        footer_height = GUIConstants.get_body_font_size() + GUIConstants.COMPONENT_PADDING

        num_lines = max(len(self.chunks), 1)
        line_spacing = int(GUIConstants.COMPONENT_PADDING / 2)
        max_line_height = int((body_height - footer_height) / num_lines) - line_spacing

        widest_chunk = max((len(chunk) for chunk in self.chunks), default=1)
        available_width = self.canvas_width - 2 * GUIConstants.EDGE_PADDING

        font_size = GUIConstants.get_body_font_size() + 8
        min_font_size = GUIConstants.get_body_font_size() - 2
        while font_size > min_font_size:
            font = Fonts.get_font(GUIConstants.FIXED_WIDTH_FONT_NAME, font_size)
            left, top, right, bottom = font.getbbox("W" * widest_chunk, anchor="ls")
            if right <= available_width and (-1 * top) + bottom <= max_line_height:
                break
            font_size -= 1

        line_y = body_y
        for chunk in self.chunks:
            self.components.append(TextArea(
                text=chunk,
                font_name=GUIConstants.FIXED_WIDTH_FONT_NAME,
                font_size=font_size,
                is_text_centered=True,
                auto_line_break=False,
                screen_y=line_y,
            ))
            line_y = (
                self.components[-1].screen_y
                + self.components[-1].height
                + line_spacing
            )

        self.components.append(TextArea(
            # TRANSLATOR_NOTE: The password is one string; the on-screen grouping
            # is only to make it readable. Warn against typing spaces.
            text=_("No spaces. Case matters."),
            font_size=GUIConstants.get_body_font_size() - 2,
            font_color=GUIConstants.INFO_COLOR,
            is_text_centered=True,
            screen_y=line_y + int(GUIConstants.COMPONENT_PADDING / 2),
        ))



@dataclass
class SeedPassSido3ApproveScreen(WarningEdgesMixin, ButtonListScreen):
    """
    Approval for a SIDO3 signing request.

    The **origin** is the largest thing on screen, not the RP ID. The origin is
    what the browser reported and what the user can compare against their own
    address bar; the RP ID is derived from it and is the less informative of the
    two. Showing the wrong one would defeat the point of relaying the origin at
    all.
    """
    is_bottom_list: bool = True
    origin: str = None
    rp_id: str = None
    operation: str = None
    user_name: str = None
    fingerprint: str = None
    status_color: str = GUIConstants.ACCENT_COLOR

    def __post_init__(self):
        self.title = _("Register") if self.operation == "create" else _("Sign In")
        super().__post_init__()

        self.components.append(TextArea(
            # TRANSLATOR_NOTE: Label above the website address
            text=_("Website"),
            font_size=GUIConstants.get_body_font_size() - 3,
            is_text_centered=True,
            screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING,
        ))

        self.components.append(TextArea(
            text=self.origin,
            font_size=GUIConstants.get_body_font_size() + 3,
            is_text_centered=True,
            auto_line_break=True,
            screen_y=self.components[-1].screen_y + self.components[-1].height,
        ))

        if self.user_name:
            self.components.append(TextArea(
                text=self.user_name,
                font_size=GUIConstants.get_body_font_size() - 1,
                font_color=GUIConstants.INFO_COLOR,
                is_text_centered=True,
                screen_y=self.components[-1].screen_y + self.components[-1].height + GUIConstants.COMPONENT_PADDING,
            ))

        self.components.append(TextArea(
            text=_("Check this matches the site in your browser."),
            font_size=GUIConstants.get_body_font_size() - 3,
            font_color=GUIConstants.INFO_COLOR,
            is_text_centered=True,
            screen_y=self.components[-1].screen_y + self.components[-1].height + GUIConstants.COMPONENT_PADDING,
        ))



@dataclass
class SeedPassFido2ArmedScreen(ButtonListScreen):
    """
    Shown while the device is waiting on the USB cable.

    The relying party is the largest thing on screen because it is the only
    thing distinguishing a legitimate session from one armed for a lookalike
    domain, and the user approved it moments earlier.
    """
    is_bottom_list: bool = True
    rp_id: str = None
    request_count: int = 0

    def __post_init__(self):
        self.title = _("FIDO2")
        super().__post_init__()

        self.components.append(TextArea(
            text=self.rp_id,
            font_size=GUIConstants.get_body_font_size() + 4,
            is_text_centered=True,
            auto_line_break=True,
            screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING,
        ))

        self.components.append(TextArea(
            # TRANSLATOR_NOTE: Waiting for the computer to send a request
            text=_("Connect the USB cable to your computer."),
            font_size=GUIConstants.get_body_font_size() - 1,
            is_text_centered=True,
            screen_y=self.components[-1].screen_y + self.components[-1].height + GUIConstants.COMPONENT_PADDING,
        ))

        self.components.append(TextArea(
            # TRANSLATOR_NOTE: Reassures the user that other sites are refused
            text=_("Only this site will be answered."),
            font_size=GUIConstants.get_body_font_size() - 3,
            font_color=GUIConstants.INFO_COLOR,
            is_text_centered=True,
            screen_y=self.components[-1].screen_y + self.components[-1].height + GUIConstants.COMPONENT_PADDING,
        ))



@dataclass
class SeedPassFido2ConfirmScreen(WarningEdgesMixin, ButtonListScreen):
    """
    The user-presence prompt.

    Nothing is signed and no key is derived until this returns. It is the only
    step that makes a signature evidence of a human decision rather than of a
    cable being plugged in, so the site name is shown large and the action is
    spelled out.
    """
    is_bottom_list: bool = True
    rp_id: str = None
    action: str = None
    status_color: str = GUIConstants.ACCENT_COLOR

    def __post_init__(self):
        self.title = _("Approve?")
        super().__post_init__()

        self.components.append(TextArea(
            # TRANSLATOR_NOTE: Inserts "register" or "sign in"
            text=_("The computer asks to {}").format(self.action),
            font_size=GUIConstants.get_body_font_size() - 1,
            is_text_centered=True,
            screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING,
        ))

        self.components.append(TextArea(
            text=self.rp_id,
            font_size=GUIConstants.get_body_font_size() + 6,
            is_text_centered=True,
            auto_line_break=True,
            screen_y=self.components[-1].screen_y + self.components[-1].height + GUIConstants.COMPONENT_PADDING,
        ))

        self.components.append(TextArea(
            text=_("Approve only if this matches the site you are on."),
            font_size=GUIConstants.get_body_font_size() - 3,
            font_color=GUIConstants.INFO_COLOR,
            is_text_centered=True,
            screen_y=self.components[-1].screen_y + self.components[-1].height + GUIConstants.COMPONENT_PADDING,
        ))



@dataclass
class SeedPassFormatScreen(ButtonListScreen):
    """Choose the full 256-bit password or the 16-char short form."""
    is_bottom_list: bool = True

    def __post_init__(self):
        self.title = _("Format")
        super().__post_init__()

        self.components.append(TextArea(
            # TRANSLATOR_NOTE: The short format is for sites that cap password length
            text=_("Short is only for sites that reject long passwords. It is weaker: 82 bits vs 256."),
            screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING,
        ))
