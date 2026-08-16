"""
Routing for the QR types SeedPass adds.

Hooked into `ScanView` at the point where the stock decoder gives up. Anything
reaching here would otherwise have produced "not yet implemented", so nothing
SeedSigner already recognises can be affected -- SeedQR, PSBT, addresses,
settings and sign-message requests are all handled before this runs.

Kept in its own module so the patch to `scan_views.py` stays three lines. A
larger edit there would be more likely to break when SeedSigner's own scanner
changes.
"""
import logging

from seedsigner.views.view import Destination

logger = logging.getLogger(__name__)


def route_seedpass_qr(decoder):
    """
    Return a Destination for a SeedPass QR, or None to let the caller carry on.

    Returning None rather than raising matters: an unrecognised QR is not an
    error here, it is simply not ours, and the caller still has its own
    fallback to run.
    """
    payload = _raw_text(decoder)
    if not payload:
        return None

    # SIDO3: a WebAuthn request relayed from the companion app.
    if payload.startswith("sido3://"):
        from seedsigner.models import sido3
        from seedsigner.views.seedpass_views import SeedPassSido3RequestView

        try:
            request = sido3.parse_request(payload)
        except sido3.Sido3Error as e:
            # Malformed, or failing the origin check. Refused rather than shown,
            # because a request that does not validate must never reach an
            # approval screen -- a user should not be asked to approve something
            # the device has already decided is wrong.
            logger.warning("Rejected SIDO3 request: %s", e)
            from seedsigner.views.seedpass_views import SeedPassErrorView
            from seedsigner.views.view import MainMenuView

            return Destination(
                SeedPassErrorView,
                view_args=dict(
                    message=str(e),
                    next_destination=Destination(MainMenuView),
                ),
            )

        return Destination(
            SeedPassSido3RequestView,
            view_args=dict(request=request),
            skip_current_view=True,
        )

    # FIDO2 session preparation.
    if payload.startswith("seedpass://v1/fido2?"):
        from seedsigner.models import fido2_session
        from seedsigner.views.seedpass_views import SeedPassFido2PrepareView

        try:
            request = fido2_session.parse_prepare_uri(payload)
        except fido2_session.SessionError as e:
            logger.warning("Rejected FIDO2 preparation: %s", e)
            return None

        return Destination(
            SeedPassFido2PrepareView,
            view_args=dict(request=request),
            skip_current_view=True,
        )

    # SLIP-13 authentication request.
    if payload.startswith("seedpass://v1/auth?"):
        from seedsigner.models import seedpass_identity
        from seedsigner.views.seedpass_views import SeedPassAuthRequestView

        try:
            request = seedpass_identity.parse_auth_request(payload)
        except seedpass_identity.IdentityError as e:
            logger.warning("Rejected identity auth request: %s", e)
            return None

        return Destination(
            SeedPassAuthRequestView,
            view_args=dict(request=request),
            skip_current_view=True,
        )

    return None


def _raw_text(decoder):
    """
    The decoded text, however this SeedSigner version exposes it.

    Tolerant on purpose: the accessor has moved between releases, and a scanner
    hook that crashes would break every QR type, not just ours.
    """
    for attribute in ("get_qr_data", "get_data"):
        getter = getattr(decoder, attribute, None)
        if getter is None:
            continue
        try:
            data = getter()
        except Exception:
            continue
        if isinstance(data, str):
            return data
        if isinstance(data, dict):
            for key in ("data", "message", "text"):
                if isinstance(data.get(key), str):
                    return data[key]

    return None
