"""Persian VPN app icon: a globe wrapped by a tilted data orbit with two
connected nodes. Generates SVG layers on the 108x108 adaptive-icon grid
(safe zone = circle of radius 33 around the centre)."""

import math

CX = CY = 54.0
R = 20.5                      # globe radius
ORX, ORY, TILT = 30.5, 10.0, -22   # orbit ellipse (rotated)

BG_TOP, BG_BOTTOM = "#0B3A53", "#00A58E"
GLOW = "#5CF2D6"


def rot(x, y, deg):
    a = math.radians(deg)
    dx, dy = x - CX, y - CY
    return (CX + dx * math.cos(a) - dy * math.sin(a),
            CY + dx * math.sin(a) + dy * math.cos(a))


def orbit_point(t):
    """Point on the rotated orbit at parameter t (radians)."""
    return rot(CX + ORX * math.cos(t), CY + ORY * math.sin(t), TILT)


def orbit_arc(t0, t1, steps=60):
    pts = [orbit_point(t0 + (t1 - t0) * i / steps) for i in range(steps + 1)]
    return "M" + " L".join("%.2f %.2f" % p for p in pts)


def globe(stroke="#FFFFFF", w=1.9):
    parts = []
    # outline
    parts.append('<circle cx="%s" cy="%s" r="%s" fill="none" stroke="%s" stroke-width="%s"/>'
                 % (CX, CY, R, stroke, w + 0.6))
    # meridians (ellipses of shrinking width)
    for k in (0.42, 0.82):
        parts.append('<ellipse cx="%s" cy="%s" rx="%.2f" ry="%s" fill="none" stroke="%s" stroke-width="%s"/>'
                     % (CX, CY, R * k, R, stroke, w))
    parts.append('<line x1="%s" y1="%.2f" x2="%s" y2="%.2f" stroke="%s" stroke-width="%s"/>'
                 % (CX, CY - R, CX, CY + R, stroke, w))
    # latitudes
    for frac in (-0.55, 0.0, 0.55):
        y = CY + R * frac
        half = math.sqrt(R * R - (R * frac) ** 2)
        parts.append('<line x1="%.2f" y1="%.2f" x2="%.2f" y2="%.2f" stroke="%s" stroke-width="%s"/>'
                     % (CX - half, y, CX + half, y, stroke, w))
    return "\n".join(parts)


def foreground(mono=False):
    white = "#FFFFFF"
    glow = white if mono else GLOW
    clip = ('<clipPath id="g"><circle cx="%s" cy="%s" r="%s"/></clipPath>' % (CX, CY, R + 1.5))
    # back half of the orbit passes behind the globe; front half in front
    back = orbit_arc(math.pi, 2 * math.pi)
    front = orbit_arc(0, math.pi)
    full = orbit_arc(0, 2 * math.pi, 120)
    n1 = orbit_point(math.radians(50))     # front, lower right
    n2 = orbit_point(math.radians(155))    # front, left
    out = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 108 108" width="108" height="108">',
           '<defs>%s</defs>' % clip]
    out.append('<path d="%s" fill="none" stroke="%s" stroke-width="2.4" stroke-linecap="round" opacity="0.5"/>'
               % (back, white))
    if not mono:
        out.append('<circle cx="%s" cy="%s" r="%s" fill="#FFFFFF" opacity="0.10"/>' % (CX, CY, R))
    out.append(globe())
    # where the front orbit crosses the globe, cut a gap in the globe lines
    # (clipped to the globe so nothing dark shows outside it)
    if not mono:
        out.append('<g clip-path="url(#g)"><path d="%s" fill="none" stroke="#0E6670" '
                   'stroke-width="7" stroke-linecap="butt"/></g>' % front)
    out.append('<path d="%s" fill="none" stroke="%s" stroke-width="3" stroke-linecap="round"/>'
               % (front, glow))
    for (x, y), r in ((n1, 3.4), (n2, 2.6)):
        if not mono:
            out.append('<circle cx="%.2f" cy="%.2f" r="%.2f" fill="%s" opacity="0.30"/>' % (x, y, r + 2.8, GLOW))
        out.append('<circle cx="%.2f" cy="%.2f" r="%.2f" fill="%s"/>' % (x, y, r, glow))
    out.append('</svg>')
    return "\n".join(out)


def background():
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 108 108" width="108" height="108">'
            '<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">'
            '<stop offset="0" stop-color="%s"/><stop offset="1" stop-color="%s"/>'
            '</linearGradient>'
            '<radialGradient id="hl" cx="0.3" cy="0.25" r="0.6">'
            '<stop offset="0" stop-color="#FFFFFF" stop-opacity="0.18"/>'
            '<stop offset="1" stop-color="#FFFFFF" stop-opacity="0"/></radialGradient></defs>'
            '<rect width="108" height="108" fill="url(#bg)"/>'
            '<rect width="108" height="108" fill="url(#hl)"/></svg>' % (BG_TOP, BG_BOTTOM))


if __name__ == "__main__":
    import sys
    out = sys.argv[1]
    open(out + "/fg.svg", "w").write(foreground())
    open(out + "/fg_mono.svg", "w").write(foreground(mono=True))
    open(out + "/bg.svg", "w").write(background())
