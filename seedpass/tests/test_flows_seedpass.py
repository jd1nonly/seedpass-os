"""
Flow tests for the SeedPass views.

These run headlessly (hardware is mocked in `tests/base.py`) and verify the
View-to-View routing, not pixel output.

Run from the SeedSigner repo root:
    python -m pytest tests/test_flows_seedpass.py -v
"""
# Must import test base before the Controller
from base import FlowTest, FlowStep

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON, RET_CODE__POWER_BUTTON
from seedsigner.models.seed import ElectrumSeed, Seed
from seedsigner.models.seedpass import PasswordFormat, decode_password
from seedsigner.views.view import MainMenuView
from seedsigner.views import scan_views, seed_views, seedpass_views, tools_views


TEST_MNEMONIC_24 = ["abandon"] * 23 + ["art"]

# A valid Electrum segwit seed (BIP-85 unsupported)
ELECTRUM_MNEMONIC = (
    "regular reject rare profit once math fringe chase until ketchup century escape"
)


def load_seed_into_decoder(view: scan_views.ScanView):
    """Simulate scanning a standard SeedQR (23x "abandon" + "art")."""
    view.decoder.add_data("0000" * 23 + "0102")


class TestSeedPassFlows(FlowTest):

    def load_seed(self, mnemonic=None, seed_cls=Seed) -> Seed:
        seed = seed_cls(mnemonic=mnemonic or TEST_MNEMONIC_24)
        self.controller.storage.set_pending_seed(seed)
        self.controller.storage.finalize_pending_seed()
        return seed

    # ------------------------------------------------------------------ home menu

    def test_home_menu_entries(self):
        """New seed / Scan / Seeds / Settings, and nothing else."""
        captured = {}

        view = MainMenuView()
        # Home has no back button, so exit via the power button instead
        view.run_screen = lambda Screen_cls, **kwargs: (
            captured.update(kwargs) or RET_CODE__POWER_BUTTON
        )
        view.run()

        assert [b.button_label for b in captured["button_data"]] == [
            "New seed", "Scan", "Seeds", "Settings",
        ]

    def test_home_new_seed_opens_photo_entropy(self):
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.NEW_SEED),
            FlowStep(tools_views.ToolsImageEntropyLivePreviewView),
        ])

    def test_home_scan_opens_the_scanner(self):
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView),
        ])

    def test_home_seeds_opens_the_seed_list(self):
        self.load_seed()
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
            FlowStep(seed_views.SeedsMenuView),
        ])

    # ------------------------------------------------------------------ seed entry paths

    def test_scanned_seed_lands_in_the_password_flow(self):
        """
        Scanning a SeedQR must finalize and then redirect past SeedOptionsView
        straight into the password menu.
        """
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_seed_into_decoder),
            FlowStep(seed_views.SeedFinalizeView, button_data_selection=seed_views.SeedFinalizeView.FINALIZE),
            FlowStep(seed_views.SeedOptionsView, is_redirect=True),
            FlowStep(seedpass_views.SeedPassMenuView),
        ])

    def test_seed_list_selection_lands_in_the_password_flow(self):
        self.load_seed()
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
            FlowStep(seed_views.SeedsMenuView, screen_return_value=0),
            FlowStep(seed_views.SeedOptionsView, is_redirect=True),
            FlowStep(seedpass_views.SeedPassMenuView),
        ])

    def test_home_keeps_the_native_2x2_grid(self):
        """
        Four entries means MainMenuScreen still works; LargeButtonScreen raises
        on any count other than 2 or 4.
        """
        from seedsigner.gui.screens.screen import MainMenuScreen

        captured = {}

        def run_screen(Screen_cls, **kwargs):
            captured["screen_cls"] = Screen_cls
            captured["count"] = len(kwargs["button_data"])
            return RET_CODE__POWER_BUTTON

        view = MainMenuView()
        view.run_screen = run_screen
        view.run()

        assert captured["screen_cls"] is MainMenuScreen
        assert captured["count"] in (2, 4)

    def test_home_settings_opens_settings(self):
        from seedsigner.views import settings_views
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SETTINGS),
            FlowStep(settings_views.SettingsMenuView),
        ])

    def test_back_from_password_menu_returns_home(self):
        self.load_seed()
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
            FlowStep(seed_views.SeedsMenuView, screen_return_value=0),
            FlowStep(seed_views.SeedOptionsView, is_redirect=True),
            FlowStep(seedpass_views.SeedPassMenuView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(MainMenuView),
        ])

    # ------------------------------------------------------------------ derive by name

    def test_derive_by_name_full_flow(self):
        """Name -> first password -> review -> reveal -> export -> done."""
        seed = self.load_seed()
        self.run_sequence([
            FlowStep(seedpass_views.SeedPassMenuView,
                     button_data_selection=seedpass_views.SeedPassMenuView.BY_NAME),
            FlowStep(seedpass_views.SeedPassLabelEntryView, screen_return_value="my bank"),
            FlowStep(seedpass_views.SeedPassRotationView,
                     button_data_selection=seedpass_views.SeedPassRotationView.FIRST),
            FlowStep(seedpass_views.SeedPassReviewView,
                     button_data_selection=seedpass_views.SeedPassReviewView.REVEAL),
            FlowStep(seedpass_views.SeedPassWarningView, screen_return_value=0),
            FlowStep(seedpass_views.SeedPassPasswordView,
                     button_data_selection=seedpass_views.SeedPassPasswordView.DONE),
            FlowStep(seedpass_views.SeedPassExportView,
                     button_data_selection=seedpass_views.SeedPassExportView.DONE),
            FlowStep(seedpass_views.SeedPassMenuView),
        ], initial_destination_view_args=dict(seed=seed))

    def test_displayed_chunks_rejoin_into_the_password(self):
        """What the screen shows must concatenate back to the exact password."""
        seed = self.load_seed()
        captured = {}

        def capture(view: seedpass_views.SeedPassPasswordView):
            original = view.run_screen

            def wrapped(Screen_cls, **kwargs):
                captured["chunks"] = list(kwargs["chunks"])
                captured["password"] = view.derived.password
                return original(Screen_cls, **kwargs)

            view.run_screen = wrapped

        self.run_sequence([
            FlowStep(seedpass_views.SeedPassPasswordView, before_run=capture,
                     button_data_selection=seedpass_views.SeedPassPasswordView.DONE),
            FlowStep(seedpass_views.SeedPassExportView),
        ], initial_destination_view_args=dict(seed=seed, label="gmail"))

        assert "".join(captured["chunks"]) == captured["password"]
        assert len(captured["chunks"]) == 5          # 46 chars in groups of 10
        assert len(captured["password"]) == 46
        assert " " not in captured["password"]

    def test_short_format_stays_within_16_chars(self):
        seed = self.load_seed()
        captured = {}

        def capture(view: seedpass_views.SeedPassPasswordView):
            original = view.run_screen

            def wrapped(Screen_cls, **kwargs):
                captured["chunks"] = list(kwargs["chunks"])
                captured["password"] = view.derived.password
                return original(Screen_cls, **kwargs)

            view.run_screen = wrapped

        self.run_sequence([
            FlowStep(seedpass_views.SeedPassPasswordView, before_run=capture,
                     button_data_selection=seedpass_views.SeedPassPasswordView.DONE),
            FlowStep(seedpass_views.SeedPassExportView),
        ], initial_destination_view_args=dict(
            seed=seed, label="gmail", fmt=PasswordFormat.SHORT))

        assert "".join(captured["chunks"]) == captured["password"]
        assert len(captured["chunks"]) == 2
        assert len(captured["password"]) == 16

    def test_change_format_to_short(self):
        seed = self.load_seed()
        self.run_sequence([
            FlowStep(seedpass_views.SeedPassMenuView,
                     button_data_selection=seedpass_views.SeedPassMenuView.BY_INDEX),
            FlowStep(seedpass_views.SeedPassIndexEntryView, screen_return_value="0"),
            FlowStep(seedpass_views.SeedPassReviewView,
                     button_data_selection=seedpass_views.SeedPassReviewView.CHANGE_FORMAT),
            FlowStep(seedpass_views.SeedPassFormatView,
                     screen_return_value=PasswordFormat.ALL.index(PasswordFormat.SHORT)),
            FlowStep(seedpass_views.SeedPassReviewView,
                     button_data_selection=seedpass_views.SeedPassReviewView.REVEAL),
            FlowStep(seedpass_views.SeedPassWarningView, screen_return_value=0),
            FlowStep(seedpass_views.SeedPassPasswordView,
                     button_data_selection=seedpass_views.SeedPassPasswordView.DONE),
            FlowStep(seedpass_views.SeedPassExportView),
        ], initial_destination_view_args=dict(seed=seed))

    def test_rotation_asks_for_a_counter(self):
        seed = self.load_seed()
        self.run_sequence([
            FlowStep(seedpass_views.SeedPassMenuView,
                     button_data_selection=seedpass_views.SeedPassMenuView.BY_NAME),
            FlowStep(seedpass_views.SeedPassLabelEntryView, screen_return_value="gmail"),
            FlowStep(seedpass_views.SeedPassRotationView,
                     button_data_selection=seedpass_views.SeedPassRotationView.ROTATE),
            FlowStep(seedpass_views.SeedPassCounterEntryView, screen_return_value="2"),
            FlowStep(seedpass_views.SeedPassReviewView),
        ], initial_destination_view_args=dict(seed=seed))

    def test_invalid_label_routes_to_error(self):
        """A label the model rejects must not crash the flow."""
        seed = self.load_seed()
        self.run_sequence([
            FlowStep(seedpass_views.SeedPassMenuView,
                     button_data_selection=seedpass_views.SeedPassMenuView.BY_NAME),
            FlowStep(seedpass_views.SeedPassLabelEntryView, screen_return_value="a" * 100),
            FlowStep(seedpass_views.SeedPassRotationView,
                     button_data_selection=seedpass_views.SeedPassRotationView.FIRST),
            FlowStep(seedpass_views.SeedPassReviewView, is_redirect=True),
            FlowStep(seedpass_views.SeedPassErrorView, screen_return_value=0),
            FlowStep(seedpass_views.SeedPassMenuView),
        ], initial_destination_view_args=dict(seed=seed))

    # ------------------------------------------------------------------ derive by index

    def test_derive_by_index_flow(self):
        seed = self.load_seed()
        self.run_sequence([
            FlowStep(seedpass_views.SeedPassMenuView,
                     button_data_selection=seedpass_views.SeedPassMenuView.BY_INDEX),
            FlowStep(seedpass_views.SeedPassIndexEntryView, screen_return_value="7"),
            FlowStep(seedpass_views.SeedPassReviewView,
                     button_data_selection=seedpass_views.SeedPassReviewView.REVEAL),
            FlowStep(seedpass_views.SeedPassWarningView, screen_return_value=0),
            FlowStep(seedpass_views.SeedPassPasswordView),
        ], initial_destination_view_args=dict(seed=seed))

    def test_out_of_range_index_routes_to_error(self):
        seed = self.load_seed()
        self.run_sequence([
            FlowStep(seedpass_views.SeedPassMenuView,
                     button_data_selection=seedpass_views.SeedPassMenuView.BY_INDEX),
            FlowStep(seedpass_views.SeedPassIndexEntryView, screen_return_value=str(2**31)),
            FlowStep(seedpass_views.SeedPassReviewView, is_redirect=True),
            FlowStep(seedpass_views.SeedPassErrorView),
        ], initial_destination_view_args=dict(seed=seed))

    # ------------------------------------------------------------------ export

    def test_export_secret_qr(self):
        seed = self.load_seed()
        self.run_sequence([
            FlowStep(seedpass_views.SeedPassExportView,
                     button_data_selection=seedpass_views.SeedPassExportView.EXPORT_SECRET),
            FlowStep(seedpass_views.SeedPassExportQRView, screen_return_value=0),
            FlowStep(seedpass_views.SeedPassExportView),
        ], initial_destination_view_args=dict(seed=seed, index=0))

    def test_export_reference_qr_omits_secret(self):
        seed = self.load_seed()

        def check_uri(view: seedpass_views.SeedPassExportQRView):
            assert view.uri.startswith("seedpass://v1/ref?")
            assert "secret=" not in view.uri
            assert "fmt=b58-256" in view.uri

        self.run_sequence([
            FlowStep(seedpass_views.SeedPassExportView,
                     button_data_selection=seedpass_views.SeedPassExportView.EXPORT_REF),
            FlowStep(seedpass_views.SeedPassExportQRView, before_run=check_uri, screen_return_value=0),
            FlowStep(seedpass_views.SeedPassExportView),
        ], initial_destination_view_args=dict(seed=seed, label="gmail"))

    # ------------------------------------------------------------------ guards

    def test_backup_seed_is_reachable(self):
        """The seed itself must still be exportable, even though the passwords
        are derived rather than stored."""
        seed = self.load_seed()
        self.run_sequence([
            FlowStep(seedpass_views.SeedPassMenuView,
                     button_data_selection=seedpass_views.SeedPassMenuView.BACKUP),
            FlowStep(seed_views.SeedBackupView),
        ], initial_destination_view_args=dict(seed=seed))

    def test_seedqr_export_flow(self):
        """Backup -> Export as SeedQR -> pick format -> transcribe screens."""
        seed = self.load_seed()
        self.run_sequence([
            FlowStep(seedpass_views.SeedPassMenuView,
                     button_data_selection=seedpass_views.SeedPassMenuView.BACKUP),
            FlowStep(seed_views.SeedBackupView,
                     button_data_selection=seed_views.SeedBackupView.EXPORT_SEEDQR),
            FlowStep(seed_views.SeedTranscribeSeedQRFormatView,
                     button_data_selection=seed_views.SeedTranscribeSeedQRFormatView.STANDARD_24),
            FlowStep(seed_views.SeedTranscribeSeedQRWarningView, screen_return_value=0),
            FlowStep(seed_views.SeedTranscribeSeedQRWholeQRView),
        ], initial_destination_view_args=dict(seed=seed))

    def test_compact_seedqr_export_flow(self):
        """CompactSeedQR is on by default and must still be offered."""
        seed = self.load_seed()
        self.run_sequence([
            FlowStep(seed_views.SeedTranscribeSeedQRFormatView,
                     button_data_selection=seed_views.SeedTranscribeSeedQRFormatView.COMPACT_24),
            FlowStep(seed_views.SeedTranscribeSeedQRWarningView),
        ], initial_destination_view_args=dict(seed=seed))

    def test_seedqr_flow_returns_to_the_password_menu(self):
        """
        SeedSigner's transcribe flow ends at SeedOptionsView, which redirects
        back here -- so the loop has to close rather than dead-end.
        """
        seed = self.load_seed()
        self.run_sequence([
            FlowStep(seed_views.SeedTranscribeSeedQRConfirmQRPromptView,
                     button_data_selection=seed_views.SeedTranscribeSeedQRConfirmQRPromptView.DONE),
            FlowStep(seed_views.SeedOptionsView, is_redirect=True),
            FlowStep(seedpass_views.SeedPassMenuView),
        ], initial_destination_view_args=dict(seed=seed))

    def test_view_seed_words_is_reachable(self):
        seed = self.load_seed()
        self.run_sequence([
            FlowStep(seedpass_views.SeedPassMenuView,
                     button_data_selection=seedpass_views.SeedPassMenuView.BACKUP),
            FlowStep(seed_views.SeedBackupView,
                     button_data_selection=seed_views.SeedBackupView.VIEW_WORDS),
            FlowStep(seed_views.SeedWordsWarningView),
        ], initial_destination_view_args=dict(seed=seed))

    # ------------------------------------------------------------------ identities

    def test_public_key_entry_is_reachable(self):
        """The new menu entry must not displace the password entries."""
        seed = self.load_seed()
        self.run_sequence([
            FlowStep(seedpass_views.SeedPassMenuView,
                     button_data_selection=seedpass_views.SeedPassMenuView.PUBLIC_KEY),
            FlowStep(seedpass_views.SeedPassIdentityEntryView),
        ], initial_destination_view_args=dict(seed=seed))

    def test_password_entries_still_first(self):
        """Adding Public key must not reorder what was already there."""
        seed = self.load_seed()
        captured = {}

        view = seedpass_views.SeedPassMenuView(seed=seed)
        view.run_screen = lambda Screen_cls, **kwargs: (
            captured.update(kwargs) or RET_CODE__BACK_BUTTON
        )
        view.run()

        labels = [b.button_label for b in captured["button_data"]]
        assert labels[:3] == ["New / lookup by name", "By BIP-85 index", "Public key"]

    def test_identity_by_label_derives_and_exports(self):
        seed = self.load_seed()
        self.run_sequence([
            FlowStep(seedpass_views.SeedPassIdentityEntryView, screen_return_value="gmail"),
            FlowStep(seedpass_views.SeedPassIdentityView,
                     button_data_selection=seedpass_views.SeedPassIdentityView.EXPORT),
            FlowStep(seedpass_views.SeedPassIdentityQRView, screen_return_value=0),
            FlowStep(seedpass_views.SeedPassIdentityView),
        ], initial_destination_view_args=dict(seed=seed))

    def test_identity_by_uri(self):
        seed = self.load_seed()

        def check(view: seedpass_views.SeedPassIdentityView):
            assert view.identity.uri == "https://example.com"
            assert view.identity.label is None      # a real URI, not a label

        self.run_sequence([
            FlowStep(seedpass_views.SeedPassIdentityEntryView,
                     screen_return_value="https://example.com"),
            FlowStep(seedpass_views.SeedPassIdentityView, before_run=check,
                     button_data_selection=seedpass_views.SeedPassIdentityView.DONE),
            FlowStep(seedpass_views.SeedPassMenuView),
        ], initial_destination_view_args=dict(seed=seed))

    def test_identity_rotation_increments_the_index(self):
        seed = self.load_seed()
        seen = []

        def capture(view: seedpass_views.SeedPassIdentityView):
            seen.append(view.identity.index)

        self.run_sequence([
            FlowStep(seedpass_views.SeedPassIdentityView, before_run=capture,
                     button_data_selection=seedpass_views.SeedPassIdentityView.ROTATE),
            FlowStep(seedpass_views.SeedPassIdentityView, before_run=capture,
                     button_data_selection=seedpass_views.SeedPassIdentityView.DONE),
            FlowStep(seedpass_views.SeedPassMenuView),
        ], initial_destination_view_args=dict(seed=seed, entered="gmail"))

        assert seen == [0, 1]

    def test_bad_identity_routes_to_error(self):
        seed = self.load_seed()
        self.run_sequence([
            FlowStep(seedpass_views.SeedPassIdentityEntryView, screen_return_value="https://"),
            FlowStep(seedpass_views.SeedPassIdentityView, is_redirect=True),
            FlowStep(seedpass_views.SeedPassErrorView, screen_return_value=0),
            FlowStep(seedpass_views.SeedPassMenuView),
        ], initial_destination_view_args=dict(seed=seed))

    def test_auth_request_approval_signs(self):
        seed = self.load_seed()
        request = dict(uri="https://example.com", index=0,
                       hidden=bytes.fromhex("deadbeef"), visual="2026-08-15 21:00")

        def check_payload(view: seedpass_views.SeedPassAuthSignedQRView):
            assert view.payload.startswith("seedpass://v1/authresp?")
            assert "pk=" in view.payload and "sig=" in view.payload

        self.run_sequence([
            FlowStep(seedpass_views.SeedPassAuthRequestView,
                     button_data_selection=seedpass_views.SeedPassAuthRequestView.APPROVE),
            FlowStep(seedpass_views.SeedPassAuthSignedQRView, before_run=check_payload,
                     screen_return_value=0),
            FlowStep(MainMenuView),
        ], initial_destination_view_args=dict(seed=seed, request=request))

    def test_public_key_exportable_without_typing_the_uri(self):
        """
        A scanned request already names the service, so registering should not
        require re-typing the URI on a joystick keyboard.
        """
        seed = self.load_seed()
        request = dict(uri="https://example.com", index=0, hidden=b"", visual="")

        def check(view: seedpass_views.SeedPassIdentityView):
            assert view.identity.uri == "https://example.com"

        self.run_sequence([
            FlowStep(seedpass_views.SeedPassAuthRequestView,
                     button_data_selection=seedpass_views.SeedPassAuthRequestView.PUBLIC_KEY),
            FlowStep(seedpass_views.SeedPassIdentityView, before_run=check,
                     button_data_selection=seedpass_views.SeedPassIdentityView.EXPORT),
            FlowStep(seedpass_views.SeedPassIdentityQRView),
        ], initial_destination_view_args=dict(seed=seed, request=request))

    def test_auth_request_can_be_cancelled(self):
        seed = self.load_seed()
        request = dict(uri="https://example.com", index=0, hidden=b"", visual="")
        self.run_sequence([
            FlowStep(seedpass_views.SeedPassAuthRequestView,
                     button_data_selection=seedpass_views.SeedPassAuthRequestView.CANCEL),
            FlowStep(MainMenuView),
        ], initial_destination_view_args=dict(seed=seed, request=request))

    # ------------------------------------------------------- splash screen

    def _screensaver_source(self) -> str:
        """
        The screensaver source as text.

        Read from disk rather than imported: the flow-test harness mocks this
        module, so introspecting it returns a MagicMock. The patch is a fact
        about the file, and that is what is checked.
        """
        from pathlib import Path

        import seedsigner

        path = Path(seedsigner.__file__).parent / "views" / "screensaver.py"
        return path.read_text()

    def test_no_sponsor_logo_on_the_splash(self):
        """
        SeedSigner's splash reads "With support from:" above the Human Rights
        Foundation logo. HRF sponsors SeedSigner, not this fork, and displaying
        their logo on modified firmware would claim an endorsement that was
        never given -- a false statement about a real organisation, not a
        cosmetic detail.
        """
        source = self._screensaver_source()

        assert "self.partners = []" in source
        assert '"hrf",' not in source

    def test_splash_guard_precedes_the_partner_lookup(self):
        """
        get_random_partner indexes into the partner list, so an empty list would
        raise if the render path ever reached it. The guard has to come first.
        """
        source = self._screensaver_source()

        guard = source.index("if not self.partners:")
        lookup = source.index("self.get_random_partner()")
        assert guard < lookup, "the empty-partner guard must precede the lookup"

    def test_discard_seed_is_reachable(self):
        seed = self.load_seed()
        self.run_sequence([
            FlowStep(seedpass_views.SeedPassMenuView,
                     button_data_selection=seedpass_views.SeedPassMenuView.DISCARD),
            FlowStep(seed_views.SeedDiscardView),
        ], initial_destination_view_args=dict(seed=seed))

    def test_electrum_seed_is_rejected(self):
        """
        Electrum seeds have no BIP-32 root, so the menu must bounce straight to
        the "unsupported" screen rather than attempting a derivation.
        """
        self.load_seed(mnemonic=ELECTRUM_MNEMONIC.split(), seed_cls=ElectrumSeed)
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
            FlowStep(seed_views.SeedsMenuView, screen_return_value=0),
            FlowStep(seed_views.SeedOptionsView, is_redirect=True),
            FlowStep(seedpass_views.SeedPassMenuView, is_redirect=True),
            FlowStep(seedpass_views.SeedPassUnsupportedSeedView, screen_return_value=0),
            FlowStep(MainMenuView),
        ])

    def test_missing_seed_redirects_to_the_seed_list(self):
        """
        Reached only if a caller routes here without a seed. Asserted directly:
        a redirect on the very first View of a sequence has no history for the
        Controller to pop.
        """
        view = seedpass_views.SeedPassMenuView(seed=None)
        assert view.has_redirect
        assert view.get_redirect().View_cls == seed_views.SeedsMenuView

    def test_password_is_stable_across_the_flow(self):
        """
        The password shown on screen and the one embedded in the export QR must
        be identical: both are re-derived independently from the same inputs.
        """
        seed = self.load_seed()
        captured = {}

        def capture_password(view: seedpass_views.SeedPassPasswordView):
            captured["password"] = view.derived.password

        def check_qr(view: seedpass_views.SeedPassExportQRView):
            from urllib.parse import unquote
            secret = unquote(view.uri.split("secret=")[1])
            assert secret == captured["password"]
            assert len(secret) == 46
            # Formatting and decodability must survive into the QR
            assert secret.endswith("!2")
            assert decode_password(secret, PasswordFormat.FULL) < 2**256
            assert not (set("0OIl") & set(secret))

        self.run_sequence([
            FlowStep(seedpass_views.SeedPassMenuView,
                     button_data_selection=seedpass_views.SeedPassMenuView.BY_NAME),
            FlowStep(seedpass_views.SeedPassLabelEntryView, screen_return_value="gmail"),
            FlowStep(seedpass_views.SeedPassRotationView,
                     button_data_selection=seedpass_views.SeedPassRotationView.FIRST),
            FlowStep(seedpass_views.SeedPassReviewView,
                     button_data_selection=seedpass_views.SeedPassReviewView.REVEAL),
            FlowStep(seedpass_views.SeedPassWarningView, screen_return_value=0),
            FlowStep(seedpass_views.SeedPassPasswordView, before_run=capture_password,
                     button_data_selection=seedpass_views.SeedPassPasswordView.DONE),
            FlowStep(seedpass_views.SeedPassExportView,
                     button_data_selection=seedpass_views.SeedPassExportView.EXPORT_SECRET),
            FlowStep(seedpass_views.SeedPassExportQRView, before_run=check_qr, screen_return_value=0),
            FlowStep(seedpass_views.SeedPassExportView),
        ], initial_destination_view_args=dict(seed=seed))
