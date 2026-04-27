#!/usr/bin/env python3

from colorsys import hls_to_rgb


SAMPLE = "⠋ Typing 17s Gerald the dragon had one job."
RESET = "\033[0m"
BOLD = "\033[1m"


def hsl_to_hex(h: float, s: float, l: float) -> str:
    r, g, b = hls_to_rgb(h / 360.0, l / 100.0, s / 100.0)
    return f"#{int(r * 255):02x}{int(g * 255):02x}{int(b * 255):02x}"


def hex_to_rgb(hex_color: str) -> tuple[int, int, int]:
    value = hex_color.lstrip("#")
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def fg_truecolor(r: int, g: int, b: int) -> str:
    return f"\033[38;2;{r};{g};{b}m"


def main() -> None:
    print()
    print("200 terminal color options")
    print("Pick an option number and I will use it for the status prefix.")
    print()

    for i in range(200):
        hue = (i * 17) % 360
        saturation = 52 + (i % 5) * 8
        lightness = 54 + (i % 4) * 6
        hex_color = hsl_to_hex(hue, saturation, lightness)
        r, g, b = hex_to_rgb(hex_color)
        color = fg_truecolor(r, g, b)
        option = f"Option {i + 1:03d}"
        print(f"{BOLD}{option}{RESET}  {hex_color}  {color}{SAMPLE}{RESET}")


if __name__ == "__main__":
    main()
