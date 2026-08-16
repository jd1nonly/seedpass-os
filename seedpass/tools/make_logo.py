#!/usr/bin/env python3
"""
Generate the SeedPass boot splash logo.

SeedSigner's splash loads `resources/img/logo_black_240.png`: a 240x240 RGBA
image whose wordmark occupies exactly 218x70 px, vertically centred.
`views/screensaver.py` fades it in over black and prints the version string just
beneath, positioned on the assumption that the logo is 70px tall and centred --
so those numbers are a contract, not a style choice, and this script matches
them.

The mark itself mirrors SeedSigner's: an orange pill split down the middle, with
the first half white-on-orange-text and the second orange-with-white-text. Same
visual family, different word, which is what a fork should look like.

Run it to regenerate the PNG:

    python3 make_logo.py [output.png]

Requires Pillow. The result is checked in, so you only need this if you want to
change the wordmark.
"""
import sys

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


CANVAS = 240

# The wordmark's target box, taken by measuring SeedSigner's own logo. Keeping
# these identical means the version number underneath lands where the splash
# code expects.
INK_HEIGHT = 70
INK_MAX_WIDTH = 218

ORANGE = (255, 115, 0)

# Supersample, then downscale, so the letterforms have smooth edges on a screen
# where every pixel is visible.
SCALE = 4

FONT_CANDIDATES = [
    "src/seedsigner/resources/fonts/OpenSans-SemiBold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
]

# Left half sits on white, right half on orange.
TEXT_LEFT = "SEED"
TEXT_RIGHT = "PASS"

WHITE = (255, 255, 255)


def find_font() -> str:
    for candidate in FONT_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    raise SystemExit(
        "No usable font found. Run this from the SeedSigner repo root, or "
        "install DejaVu/Liberation fonts."
    )


def fit_font(font_path: str, target_cap_height: int) -> ImageFont.FreeTypeFont:
    """Point size whose capital letters are `target_cap_height` tall."""
    size = target_cap_height
    for _ in range(200):
        font = ImageFont.truetype(font_path, size)
        top, bottom = font.getbbox("SEEDPASS")[1], font.getbbox("SEEDPASS")[3]
        if bottom - top >= target_cap_height:
            return ImageFont.truetype(font_path, max(1, size - 1))
        size += 1
    return ImageFont.truetype(font_path, size)


def build() -> Image.Image:
    font_path = find_font()

    width = INK_MAX_WIDTH * SCALE
    height = INK_HEIGHT * SCALE
    radius = height // 2

    # Cap height relative to the pill, matching SeedSigner's proportions.
    font = fit_font(font_path, int(height * 0.42))

    # The white panel sits inset inside the pill, leaving an orange rim.
    inset = int(height * 0.08)

    # 1. The pill: a rounded rectangle, orange throughout.
    pill = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    ImageDraw.Draw(pill).rounded_rectangle(
        (0, 0, width - 1, height - 1), radius=radius, fill=ORANGE + (255,),
    )

    # 2. The white panel: rounded on its left end to follow the pill, square on
    #    the right where it meets the orange half.
    split = width // 2
    panel_radius = (height - 2 * inset) // 2
    panel = ImageDraw.Draw(pill)
    panel.rounded_rectangle(
        (inset, inset, split, height - 1 - inset),
        radius=panel_radius, fill=WHITE + (255,),
    )
    panel.rectangle(
        (split - panel_radius, inset, split, height - 1 - inset),
        fill=WHITE + (255,),
    )

    # 3. The two words, each centred in its own half.
    draw = ImageDraw.Draw(pill)
    for text, colour, centre_x in (
        (TEXT_LEFT, ORANGE, split // 2),
        (TEXT_RIGHT, WHITE, split + (width - split) // 2),
    ):
        draw.text((centre_x, height // 2), text, font=font,
                  fill=colour + (255,), anchor="mm")

    # 4. Drop it into the 240x240 canvas, centred, then downsample.
    # 4. Drop it into the canvas on an OPAQUE BLACK background.
    #
    #    Not a transparent one, even though the splash composites over black
    #    anyway. `OpeningSplashScreen._render` fades the logo in with
    #    `self.logo.putalpha(255 - i)`, which replaces the entire alpha channel
    #    with one uniform value -- destroying any per-pixel alpha. Anti-aliased
    #    edges would then render at full strength and look jagged.
    #
    #    Baking the anti-aliasing into RGB against black makes the image fully
    #    opaque, so putalpha has nothing to destroy. SeedSigner's own logo is
    #    built the same way: it has zero fully-transparent pixels.
    big = Image.new("RGBA", (CANVAS * SCALE, CANVAS * SCALE), (0, 0, 0, 255))
    big.alpha_composite(pill, ((big.width - width) // 2, (big.height - height) // 2))

    small = big.resize((CANVAS, CANVAS), Image.Resampling.LANCZOS)
    small.putalpha(255)
    return small


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "logo_black_240.png")
    image = build()
    image.save(out)

    # Report the ink box so it can be compared against SeedSigner's.
    pixels = image.load()
    min_x, min_y, max_x, max_y = CANVAS, CANVAS, 0, 0
    for py in range(CANVAS):
        for px_ in range(CANVAS):
            r, g, b, _ = pixels[px_, py]
            if r + g + b > 30:
                min_x, max_x = min(min_x, px_), max(max_x, px_)
                min_y, max_y = min(min_y, py), max(max_y, py)

    print(f"wrote {out}")
    print(f"  ink box  : ({min_x},{min_y})-({max_x},{max_y})")
    print(f"  ink size : {max_x - min_x + 1}x{max_y - min_y + 1}"
          f"   (SeedSigner's is 218x70)")
    print(f"  centred  : x={(min_x + max_x + 1) / 2:.0f} y={(min_y + max_y + 1) / 2:.0f}"
          f"   (canvas centre is 120,120)")


if __name__ == "__main__":
    main()
