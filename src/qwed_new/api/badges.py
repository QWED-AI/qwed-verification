"""
QWED Verified Badge API

Generates SVG badges for verification status, similar to GitHub CI badges.
Can be embedded in READMEs, documentation, and applications.

Endpoints:
    GET /badge/verified/{attestation_id}
    GET /badge/status/{status}
    GET /badge/custom?label=...&message=...&color=...
"""

from typing import Optional
from enum import Enum


class BadgeColor(Enum):
    """Badge color presets."""
    SUCCESS = "#4c1"      # Bright green
    VERIFIED = "#00C853"  # QWED green
    FAILED = "#e05d44"    # Red
    WARNING = "#dfb317"   # Yellow
    PENDING = "#9f9f9f"   # Gray
    INFO = "#007ec6"      # Blue
    BLOCKED = "#c62828"   # Dark red


class BadgeStyle(Enum):
    """Badge style options."""
    FLAT = "flat"
    FLAT_SQUARE = "flat-square"
    PLASTIC = "plastic"
    FOR_THE_BADGE = "for-the-badge"


# SVG Templates
FLAT_BADGE_TEMPLATE = '''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{width}" height="20" role="img" aria-label="{label}: {message}">
  <title>{label}: {message}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="#555"/>
    <rect x="{label_width}" width="{message_width}" height="20" fill="{color}"/>
    <rect width="{width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="{label_x}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)">{label}</text>
    <text x="{label_x}" y="140" transform="scale(.1)" fill="#fff">{label}</text>
    <text aria-hidden="true" x="{message_x}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)">{message}</text>
    <text x="{message_x}" y="140" transform="scale(.1)" fill="#fff">{message}</text>
  </g>
  {icon}
</svg>'''

QWED_ICON = '''<g transform="translate({x}, 3) scale(0.7)">
    <path fill="#fff" d="M8 0L0 4v8l8 4 8-4V4L8 0zm0 2l6 3-6 3-6-3 6-3z"/>
  </g>'''

CHECKMARK_ICON = '''<g transform="translate({x}, 4) scale(0.6)">
    <circle cx="7" cy="7" r="7" fill="#fff" fill-opacity="0.3"/>
    <path fill="#fff" d="M6 10l-3-3 1-1 2 2 4-4 1 1z"/>
  </g>'''

X_ICON = '''<g transform="translate({x}, 4) scale(0.6)">
    <circle cx="7" cy="7" r="7" fill="#fff" fill-opacity="0.3"/>
    <path fill="#fff" d="M4 4l6 6M10 4l-6 6" stroke="#fff" stroke-width="1.5"/>
  </g>'''


def _calculate_text_width(text: str) -> int:
    """Estimate text width in pixels (approximate)."""
    # Average character width of 6.5px for the font
    return int(len(text) * 6.5) + 10


def generate_badge(
    label: str,
    message: str,
    color: str = BadgeColor.SUCCESS.value,
    style: BadgeStyle = BadgeStyle.FLAT,
    include_icon: bool = True,
    icon_type: str = "qwed",  # qwed, checkmark, x
) -> str:
    """
    Generate an SVG badge.
    
    Args:
        label: Left side label (e.g., "QWED")
        message: Right side message (e.g., "verified")
        color: Hex color for message background
        style: Badge style
        include_icon: Whether to include an icon
        icon_type: Type of icon (qwed, checkmark, x)
    
    Returns:
        SVG string
    """
    # Calculate dimensions
    icon_width = 14 if include_icon else 0
    label_width = _calculate_text_width(label) + icon_width + 6
    message_width = _calculate_text_width(message) + 10
    total_width = label_width + message_width
    
    # Calculate text positions
    label_x = (label_width / 2 + icon_width / 2) * 10  # Scale for transform
    message_x = (label_width + message_width / 2) * 10
    
    # Generate icon
    icon_svg = ""
    if include_icon:
        if icon_type == "checkmark":
            icon_svg = CHECKMARK_ICON.format(x=4)
        elif icon_type == "x":
            icon_svg = X_ICON.format(x=4)
        else:  # qwed
            icon_svg = QWED_ICON.format(x=3)
    
    return FLAT_BADGE_TEMPLATE.format(
        width=total_width,
        label_width=label_width,
        message_width=message_width,
        label=label,
        message=message,
        color=color,
        label_x=label_x,
        message_x=message_x,
        icon=icon_svg,
    )


def verified_badge(verified: bool = True) -> str:
    """Generate a QWED verified/failed badge."""
    if verified:
        return generate_badge(
            label="QWED",
            message="verified",
            color=BadgeColor.VERIFIED.value,
            icon_type="checkmark",
        )
    else:
        return generate_badge(
            label="QWED",
            message="failed",
            color=BadgeColor.FAILED.value,
            icon_type="x",
        )


def status_badge(status: str) -> str:
    """Generate a badge for any verification status."""
    status_upper = status.upper()
    
    status_config = {
        "VERIFIED": (BadgeColor.VERIFIED.value, "checkmark"),
        "FAILED": (BadgeColor.FAILED.value, "x"),
        "CORRECTED": (BadgeColor.WARNING.value, "checkmark"),
        "BLOCKED": (BadgeColor.BLOCKED.value, "x"),
        "PENDING": (BadgeColor.PENDING.value, "qwed"),
        "ERROR": (BadgeColor.FAILED.value, "x"),
    }
    
    color, icon = status_config.get(status_upper, (BadgeColor.INFO.value, "qwed"))
    
    return generate_badge(
        label="QWED",
        message=status.lower(),
        color=color,
        icon_type=icon,
    )


def attestation_badge(
    attestation_id: Optional[str] = None,
    verified: bool = True,
    engine: Optional[str] = None,
) -> str:
    """Generate a badge for an attestation."""
    if engine:
        label = f"QWED {engine}"
    else:
        label = "QWED"
    
    message = "verified" if verified else "failed"
    color = BadgeColor.VERIFIED.value if verified else BadgeColor.FAILED.value
    icon = "checkmark" if verified else "x"
    
    return generate_badge(
        label=label,
        message=message,
        color=color,
        icon_type=icon,
    )


def custom_badge(
    label: str,
    message: str,
    color: Optional[str] = None,
    logo: bool = True,
) -> str:
    """Generate a custom badge."""
    return generate_badge(
        label=label,
        message=message,
        color=color or BadgeColor.INFO.value,
        include_icon=logo,
        icon_type="qwed",
    )


# ============================================================================
# FastAPI Router (for integration into main API)
# ============================================================================

def create_badge_router():
    """Create FastAPI router for badge endpoints."""
    try:
        from fastapi import APIRouter, Query, HTTPException
        from fastapi.responses import Response
    except ImportError:
        return None
    
    router = APIRouter(prefix="/badge", tags=["badges"])
    
    @router.get("/verified")
    async def get_verified_badge(verified: bool = True):
        """Get a verified/failed badge."""
        svg = verified_badge(verified)
        return Response(content=svg, media_type="image/svg+xml")
    
    @router.get("/status/{status}")
    async def get_status_badge(status: str):
        """Get a badge for a specific status."""
        svg = status_badge(status)
        return Response(content=svg, media_type="image/svg+xml")
    
    @router.get("/attestation/{attestation_id}")
    async def get_attestation_badge(attestation_id: str):
        """Get a badge for a specific attestation."""
        # In production, look up the attestation
        # For now, return a verified badge
        svg = attestation_badge(attestation_id=attestation_id, verified=True)
        return Response(content=svg, media_type="image/svg+xml")
    
    @router.get("/custom")
    async def get_custom_badge(
        label: str = Query("QWED", description="Left side label"),
        message: str = Query("verified", description="Right side message"),
        color: Optional[str] = Query(None, description="Hex color (e.g., #00C853)"),
        logo: bool = Query(True, description="Include QWED logo"),
    ):
        """Generate a custom badge."""
        svg = custom_badge(label=label, message=message, color=color, logo=logo)
        return Response(content=svg, media_type="image/svg+xml")
    
    @router.get("/engine/{engine}")
    async def get_engine_badge(
        engine: str,
        verified: bool = True,
    ):
        """Get a badge for a specific verification engine."""
        svg = attestation_badge(verified=verified, engine=engine)
        return Response(content=svg, media_type="image/svg+xml")
    
    return router


# Pre-generated badge examples (can be served statically)
BADGE_EXAMPLES = {
    "verified": verified_badge(True),
    "failed": verified_badge(False),
    "math_verified": attestation_badge(engine="math", verified=True),
    "logic_verified": attestation_badge(engine="logic", verified=True),
    "code_verified": attestation_badge(engine="code", verified=True),
    "sql_verified": attestation_badge(engine="sql", verified=True),
}


# ============================================================================
# Exports
# ============================================================================

__all__ = [
    "generate_badge",
    "verified_badge",
    "status_badge",
    "attestation_badge",
    "custom_badge",
    "create_badge_router",
    "BadgeColor",
    "BadgeStyle",
    "BADGE_EXAMPLES",
]
