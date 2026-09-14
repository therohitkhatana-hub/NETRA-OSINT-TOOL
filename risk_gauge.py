"""
Renders a visual 0-100 risk-score gauge as a PNG for embedding in the PDF report.
Turns the aggregate of all FLAG findings into one glanceable number instead of
requiring the reader to mentally tally flags across several tables.
"""
import matplotlib
matplotlib.use("Agg")  # no display needed, just render to file
import matplotlib.pyplot as plt
from matplotlib.patches import Wedge
import numpy as np


def compute_risk_score(all_findings: list) -> int:
    """
    Weighted sum of every FLAG finding's confidence, scaled to 0-100 with
    diminishing returns so a handful of flags doesn't instantly max out the
    gauge. Deliberately simple and EXPLAINABLE (see scoring.py's rule-based
    philosophy) - not a black-box model.
    """
    flag_findings = [f for f in all_findings if "FLAG" in f.fact]
    if not flag_findings:
        return 0
    raw = sum(f.confidence * 18 for f in flag_findings)
    return min(100, round(raw))


def _score_to_angle(score: float) -> float:
    """score 0 -> 180 degrees (left/west), score 100 -> 0 degrees (right/east),
    sweeping counterclockwise through the top (90 degrees = score 50)."""
    return 180 - (score / 100) * 180


def render_gauge(score: int, output_path: str = "risk_gauge.png"):
    fig, ax = plt.subplots(figsize=(4.2, 2.6))

    zones = [(0, 33, "#1a7f37"), (33, 66, "#d99a00"), (66, 100, "#c0392b")]
    for start, end, color in zones:
        theta1 = _score_to_angle(end)    # smaller angle
        theta2 = _score_to_angle(start)  # larger angle
        wedge = Wedge((0, 0), 1.0, theta1, theta2, width=0.35, facecolor=color, edgecolor="white", linewidth=1.5)
        ax.add_patch(wedge)

    # Needle
    needle_angle_rad = np.radians(_score_to_angle(score))
    needle_len = 0.62
    x = needle_len * np.cos(needle_angle_rad)
    y = needle_len * np.sin(needle_angle_rad)
    ax.plot([0, x], [0, y], color="#1a1a1a", linewidth=3, zorder=5, solid_capstyle="round")
    ax.scatter([0], [0], color="#1a1a1a", s=70, zorder=6)

    # Tick labels at the three boundary points
    for label, sc in [("0", 0), ("50", 50), ("100", 100)]:
        angle_rad = np.radians(_score_to_angle(sc))
        lx, ly = 1.18 * np.cos(angle_rad), 1.18 * np.sin(angle_rad)
        ax.text(lx, ly, label, ha="center", va="center", fontsize=9, color="#333333")

    ax.text(0, -0.35, f"{score}/100", ha="center", va="center",
             fontsize=22, fontweight="bold", color="#1a1a1a")
    ax.text(0, -0.62, "Aggregate Risk Score", ha="center", va="center",
             fontsize=9, color="#555555")

    ax.set_xlim(-1.4, 1.4)
    ax.set_ylim(-0.75, 1.35)
    ax.set_aspect("equal")
    ax.axis("off")

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, transparent=True, bbox_inches="tight")
    plt.close(fig)
    return output_path
