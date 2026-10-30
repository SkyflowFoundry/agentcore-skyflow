#!/usr/bin/env python3
"""Build the blog's diagrams as SVG files with the official AWS Architecture Icons.

    python3 docs/diagrams/build.py
    node docs/diagrams/render.mjs

The first command writes one SVG per figure beside this script. The second
renders each to a PNG 800 pixels wide, the most the AWS blog accepts.

The icons are read from the AWS Architecture Icons package, which is not in the
repository. Download it from https://aws.amazon.com/architecture/icons/ and set
`AWS_ICONS` to the folder that holds its `Architecture-Service-Icons_*`,
`Architecture-Group-Icons_*` and `Resource-Icons_*` folders. The default is
`~/Claude/AWS_icon_package`. The Skyflow logo is read from `SKYFLOW_LOGO`.

Every name, address and number in these figures is fictional and follows the
AWS guidance for example content.
"""

from __future__ import annotations

import glob
import os
import re
from dataclasses import dataclass, field
from html import escape
from pathlib import Path

HERE = Path(__file__).resolve().parent
ICONS = Path(os.environ.get("AWS_ICONS", "~/Claude/AWS_icon_package")).expanduser()
SKYFLOW_LOGO = Path(
    os.environ.get("SKYFLOW_LOGO", "~/Code/agentcore/demo-out/brand/skyflow/skyflow-logo-black.svg")
).expanduser()

WIDTH = 800
FONT = "'Amazon Ember', Arial, Helvetica, sans-serif"
INK = "#232F3E"
MUTED = "#545B64"
LIFELINE = "#A7B0BA"
ACCOUNT = "#E7157B"
DASHED = "#7D8998"
NOTE_FILL = "#F2F6FC"
NOTE_STROKE = "#5A7EB8"

# The fictional values the figures show. The token suffixes are what Skyflow
# minted for these values on the live gateway.
NAME = "Mateo Jackson"
EMAIL = "mateo_jackson@example.com"
MERCHANT = "AnyCompany Electronics"
NAME_TOKEN = os.environ.get("NAME_TOKEN", "[NAME_KhpdiUQ]")
EMAIL_TOKEN = os.environ.get("EMAIL_TOKEN", "[EMAIL_ADDRESS_n6Eg15w]")


# --- Icons -------------------------------------------------------------------

_ICON_GLOBS = {
    "user": "Resource-Icons_*/Res_General-Icons/Res_48_Light/Res_User_48_Light.svg",
    "internet": "Resource-Icons_*/Res_General-Icons/Res_48_Light/Res_Internet-alt1_48_Light.svg",
    "agentcore": "Architecture-Service-Icons_*/Arch_Artificial-Intelligence/64/Arch_Amazon-Bedrock-AgentCore_64.svg",
    "bedrock": "Architecture-Service-Icons_*/Arch_Artificial-Intelligence/64/Arch_Amazon-Bedrock_64.svg",
    "lambda": "Architecture-Service-Icons_*/Arch_Compute/64/Arch_AWS-Lambda_64.svg",
    "s3": "Architecture-Service-Icons_*/Arch_Storage/64/Arch_Amazon-Simple-Storage-Service_64.svg",
    "secrets": "Architecture-Service-Icons_*/Arch_Security-Identity/64/Arch_AWS-Secrets-Manager_64.svg",
    "ssm": "Architecture-Service-Icons_*/Arch_Management-Tools/64/Arch_AWS-Systems-Manager_64.svg",
    "cloudwatch": "Architecture-Service-Icons_*/Arch_Management-Tools/64/Arch_Amazon-CloudWatch_64.svg",
    "dynamodb": "Architecture-Service-Icons_*/Arch_Databases/64/Arch_Amazon-DynamoDB_64.svg",
    "account": "Architecture-Group-Icons_*/AWS-Account_32.svg",
}
_icon_count = 0


def _icon_file(name: str) -> Path:
    hits = sorted(glob.glob(str(ICONS / _ICON_GLOBS[name])))
    if not hits:
        raise SystemExit(f"icon {name!r} not found under {ICONS}; set AWS_ICONS")
    return Path(hits[-1])


def _embed(source: str, x: float, y: float, w: float, h: float) -> str:
    """Nest an SVG file at (x, y), prefixing its ids so two copies never clash."""
    global _icon_count
    _icon_count += 1
    p = f"i{_icon_count}-"
    source = re.sub(r"<\?xml[^>]*\?>|<!DOCTYPE[^>]*>|<!--.*?-->", "", source, flags=re.S)
    source = re.sub(r'\bid="([^"]+)"', lambda m: f'id="{p}{m.group(1)}"', source)
    source = re.sub(r"url\(#([^)]+)\)", lambda m: f"url(#{p}{m.group(1)})", source)
    source = re.sub(r'href="#([^"]+)"', lambda m: f'href="#{p}{m.group(1)}"', source)
    head = re.search(r"<svg\b[^>]*>", source)
    tag = head.group(0)
    vb = re.search(r'viewBox="([^"]+)"', tag)
    if vb:
        view_box = vb.group(1)
    else:
        sw = float(re.search(r'width="([\d.]+)', tag).group(1))
        sh = float(re.search(r'height="([\d.]+)', tag).group(1))
        view_box = f"0 0 {sw} {sh}"
    body = source[head.end():source.rindex("</svg>")]
    return (
        f'<svg x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" '
        f'viewBox="{view_box}" xmlns="http://www.w3.org/2000/svg">{body}</svg>'
    )


def icon(name: str, cx: float, top: float, size: float = 40) -> str:
    """An AWS icon centred on cx with its top edge at top."""
    if name == "skyflow":
        w = size * 2.0
        h = w * 37 / 123
        return _embed(SKYFLOW_LOGO.read_text(), cx - w / 2, top + (size - h) / 2, w, h)
    return _embed(_icon_file(name).read_text(), cx - size / 2, top, size, size)


# --- Drawing primitives ------------------------------------------------------


def text(x, y, lines, size=12, anchor="middle", weight="normal", fill=INK, halo=False):
    """Lines of text whose first baseline is y."""
    if isinstance(lines, str):
        lines = [lines]
    extra = ' stroke="#FFFFFF" stroke-width="4" stroke-linejoin="round" paint-order="stroke"' if halo else ""
    spans = "".join(
        f'<tspan x="{x:.1f}" dy="{0 if i == 0 else size * 1.3:.1f}">{escape(line)}</tspan>'
        for i, line in enumerate(lines)
    )
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" font-family="{FONT}" font-size="{size}" '
        f'font-weight="{weight}" fill="{fill}" text-anchor="{anchor}"{extra}>{spans}</text>'
    )


def line(x1, y1, x2, y2, dashed=False, head_end=True, head_start=False, color=INK, width=1.3):
    dash = ' stroke-dasharray="5 4"' if dashed else ""
    m_end = ' marker-end="url(#arrow)"' if head_end else ""
    m_start = ' marker-start="url(#arrow)"' if head_start else ""
    return (
        f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{color}" '
        f'stroke-width="{width}"{dash}{m_end}{m_start}/>'
    )


def path(d, dashed=False, head_end=True, head_start=False):
    dash = ' stroke-dasharray="5 4"' if dashed else ""
    m_end = ' marker-end="url(#arrow)"' if head_end else ""
    m_start = ' marker-start="url(#arrow)"' if head_start else ""
    return f'<path d="{d}" fill="none" stroke="{INK}" stroke-width="1.3"{dash}{m_end}{m_start}/>'


def badge(x, y, n):
    return (
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="8.5" fill="{INK}"/>'
        + text(x, y + 3.6, str(n), size=10 if n < 10 else 9, weight="bold", fill="#FFFFFF")
    )


def account_group(x, y, w, h, label="Your AWS account"):
    return (
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="none" stroke="{ACCOUNT}" stroke-width="1.5"/>'
        + _embed(_icon_file("account").read_text(), x, y, 26, 26)
        + text(x + 34, y + 17, label, size=12, anchor="start")
    )


def dashed_group(x, y, w, h, label):
    return (
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="none" stroke="{DASHED}" '
        f'stroke-width="1.3" stroke-dasharray="6 4"/>'
        + text(x + 10, y + 18, label, size=12, anchor="start")
    )


def note(x, y, w, h, lines, size=11):
    if isinstance(lines, str):
        lines = [lines]
    first = y + h / 2 - (len(lines) - 1) * size * 0.65 + size * 0.35
    return (
        f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="3" fill="{NOTE_FILL}" '
        f'stroke="{NOTE_STROKE}" stroke-width="1"/>' + text(x + w / 2, first, lines, size=size)
    )


def document(width, height, body):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
        f'width="{width}" height="{height:.0f}" viewBox="0 0 {width} {height:.0f}">'
        f'<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
        f'markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{INK}"/>'
        f"</marker></defs>"
        f'<rect width="100%" height="100%" fill="#FFFFFF"/>{body}</svg>'
    )


# --- Sequence diagrams -------------------------------------------------------


@dataclass
class Lane:
    x: float
    label: list[str]
    icon: str


@dataclass
class Msg:
    n: int
    frm: str
    to: str
    label: list[str]
    reply: bool = False


@dataclass
class Self:
    n: int
    lane: str
    label: list[str]


@dataclass
class Note:
    frm: str
    to: str
    label: list[str]


@dataclass
class Section:
    title: str


@dataclass
class EndSection:
    pass


@dataclass
class Group:
    first: str
    last: str
    label: str
    account: bool = False
    pad: float = 0


@dataclass
class Sequence:
    lanes: dict[str, Lane]
    groups: list[Group]
    steps: list = field(default_factory=list)


def sequence(seq: Sequence) -> str:
    out: list[str] = []
    icon_top = 46
    label_top = icon_top + 40 + 15
    y = label_top + 2 * 15 + 18
    lifeline_top = y - 8
    sections: list[tuple[str, float]] = []
    section_frames: list[tuple[str, float, float]] = []

    for step in seq.steps:
        if isinstance(step, Msg):
            a, b = seq.lanes[step.frm].x, seq.lanes[step.to].x
            y += 15 * len(step.label) + 6
            mid = (a + b) / 2
            out.append(text(mid, y - 15 * len(step.label) + 7, step.label, size=11.5, halo=True))
            gap = 10 if a < b else -10
            out.append(line(a + gap, y, b - (3 if a < b else -3), y, dashed=step.reply))
            out.append(badge(a, y, step.n))
            y += 16
        elif isinstance(step, Self):
            x = seq.lanes[step.lane].x
            y += 10
            out.append(path(f"M{x + 10},{y} H{x + 34} V{y + 22} H{x + 6}"))
            out.append(badge(x, y, step.n))
            out.append(text(x + 42, y + 8, step.label, size=11.5, anchor="start", halo=True))
            y += 22 + 15 * max(0, len(step.label) - 1) + 14
        elif isinstance(step, Note):
            a, b = seq.lanes[step.frm].x, seq.lanes[step.to].x
            h = 12 * 1.3 * len(step.label) + 10
            w = max(abs(b - a) + 80, max(len(t) for t in step.label) * 11 * 0.56 + 24)
            y += 4
            out.append(note((a + b) / 2 - w / 2, y, w, h, step.label))
            y += h + 10
        elif isinstance(step, Section):
            if sections:
                title, start = sections.pop()
                section_frames.append((title, start, y + 6))
                y += 6
            y += 10
            sections.append((step.title, y))
            y += 18
        elif isinstance(step, EndSection):
            title, start = sections.pop()
            section_frames.append((title, start, y + 6))
            y += 6
    bottom = y + 14

    for title, start, end in section_frames:
        out.insert(
            0,
            f'<rect x="12" y="{start:.1f}" width="{WIDTH - 24}" height="{end - start:.1f}" fill="none" '
            f'stroke="{DASHED}" stroke-width="1" stroke-dasharray="4 3"/>'
            + text(20, start + 14, title, size=11, anchor="start", weight="bold", fill=MUTED, halo=True),
        )

    heads: list[str] = []
    for lane in seq.lanes.values():
        heads.append(icon(lane.icon, lane.x, icon_top))
        heads.append(text(lane.x, label_top, lane.label, size=11.5))
        heads.append(
            f'<line x1="{lane.x}" y1="{lifeline_top}" x2="{lane.x}" y2="{bottom}" stroke="{LIFELINE}" '
            f'stroke-width="1" stroke-dasharray="3 3"/>'
        )

    groups: list[str] = []
    for g in seq.groups:
        x0 = seq.lanes[g.first].x - 62 - g.pad
        x1 = seq.lanes[g.last].x + 62 + g.pad
        if g.account:
            groups.append(account_group(x0, 8, x1 - x0, bottom + 4))
        else:
            groups.append(dashed_group(x0, 8, x1 - x0, bottom + 4, g.label))

    return document(WIDTH, bottom + 20, "".join(groups + heads + out))


# --- The figures -------------------------------------------------------------

ANALYST = Lane(46, ["Analyst"], "user")


def agent(x):
    return Lane(x, ["Agent", "(AgentCore Runtime)"], "agentcore")


def gateway(x):
    return Lane(x, ["Amazon Bedrock", "AgentCore Gateway"], "agentcore")


def interceptor(x):
    return Lane(x, ["Skyflow interceptor", "(AWS Lambda)"], "lambda")


def skyflow(x, label=("Skyflow Detect", "+ Vault")):
    return Lane(x, list(label), "skyflow")


def shield_the_tool() -> str:
    query = f"dispute {MERCHANT} London"
    seq = Sequence(
        lanes={
            "analyst": ANALYST,
            "agent": agent(152),
            "gateway": gateway(330),
            "lambda": interceptor(464),
            "skyflow": skyflow(612),
            "tool": Lane(742, ["Web search", "MCP server"], "internet"),
        },
        groups=[
            Group("agent", "lambda", "", account=True, pad=6),
            Group("skyflow", "skyflow", "Skyflow", pad=-6),
            Group("tool", "tool", "Third party", pad=-14),
        ],
        steps=[
            Msg(1, "analyst", "agent", [f"Look into {NAME}'s", f"dispute with {MERCHANT}"]),
            Msg(2, "agent", "gateway", ["tools/call web_search", f'"{NAME} dispute', f'{MERCHANT} London"']),
            Msg(3, "gateway", "lambda", ["REQUEST interception"]),
            Note("gateway", "lambda", ["Policy for web_search: shield the tool"]),
            Msg(4, "lambda", "skyflow", ["De-identify arguments"]),
            Msg(5, "skyflow", "lambda", [f'"{NAME_TOKEN} {query}"', "(original stored in Vault)"], reply=True),
            Note("lambda", "skyflow", ["If de-identification fails, the call is withheld (fail closed)"]),
            Msg(6, "lambda", "gateway", ["Rewritten request"], reply=True),
            Msg(7, "gateway", "tool", [f'"{NAME_TOKEN} {query}"']),
            Msg(8, "tool", "gateway", ["Merchant results"], reply=True),
            Msg(9, "gateway", "lambda", ["RESPONSE interception"]),
            Msg(10, "lambda", "skyflow", ["Re-identify any tokens"]),
            Msg(11, "skyflow", "lambda", ["Tokens restored"], reply=True),
            Msg(12, "lambda", "gateway", ["Rewritten response"], reply=True),
            Msg(13, "gateway", "agent", ["Merchant results"], reply=True),
            Msg(14, "agent", "analyst", ["Answer with the real", "customer name"], reply=True),
        ],
    )
    return sequence(seq)


def shield_the_model() -> str:
    seq = Sequence(
        lanes={
            "analyst": ANALYST,
            "agent": agent(152),
            "gateway": gateway(330),
            "lambda": interceptor(464),
            "skyflow": skyflow(612),
            "model": Lane(742, ["Amazon Bedrock", "(model)"], "bedrock"),
        },
        groups=[
            Group("agent", "lambda", "", account=True, pad=6),
            Group("skyflow", "skyflow", "Skyflow", pad=-6),
            Group("model", "model", "Model provider", pad=-14),
        ],
        steps=[
            Msg(1, "analyst", "agent", ["Draft a reply to", f"{NAME} confirming", "the provisional credit"]),
            Msg(2, "agent", "gateway", ["POST /inference/v1/messages", "system prompt, history,", f"prompt naming {NAME}"]),
            Msg(3, "gateway", "lambda", ["REQUEST interception"]),
            Note("gateway", "lambda", ["Policy for inference: shield the model"]),
            Msg(4, "lambda", "skyflow", ["De-identify every", "message part"]),
            Msg(5, "skyflow", "lambda", [f"{NAME_TOKEN}, {EMAIL_TOKEN}", "(originals stored in Vault)"], reply=True),
            Self(6, "lambda", ["Record the tokens minted", "for this request (no values)"]),
            Msg(7, "lambda", "gateway", ["Rewritten request"], reply=True),
            Msg(8, "gateway", "model", ["Prompt and history", "with tokens only"]),
            Msg(9, "model", "gateway", [f"Draft reply to {NAME_TOKEN}"], reply=True),
            Msg(10, "gateway", "lambda", ["RESPONSE interception"]),
            Msg(11, "lambda", "skyflow", ["Re-identify tokens", "minted for this call"]),
            Msg(12, "skyflow", "lambda", ["Real values"], reply=True),
            Note("lambda", "skyflow", ["If re-identification fails, the answer is withheld"]),
            Msg(13, "lambda", "gateway", ["Rewritten answer"], reply=True),
            Msg(14, "gateway", "agent", [f"Draft reply to {NAME}"], reply=True),
            Msg(15, "agent", "analyst", ["Reply with the real", "name and email"], reply=True),
        ],
    )
    return sequence(seq)


def shield_the_document() -> str:
    seq = Sequence(
        lanes={
            "analyst": ANALYST,
            "agent": agent(152),
            "gateway": gateway(288),
            "lambda": interceptor(414),
            "s3": Lane(536, ["Amazon S3", "document tool"], "s3"),
            "skyflow": skyflow(704, ("Skyflow Detect", "+ clean-copy storage")),
        },
        groups=[
            Group("agent", "s3", "", account=True, pad=-2),
            Group("skyflow", "skyflow", "Skyflow (approved Region)", pad=24),
        ],
        steps=[
            Msg(1, "analyst", "agent", ["Summarize the case", "note for this dispute"]),
            Msg(2, "agent", "gateway", ["tools/call get_case_note"]),
            Msg(3, "gateway", "s3", ["tools/call get_case_note"]),
            Msg(4, "s3", "gateway", ["Presigned URL to original case note"], reply=True),
            Msg(5, "gateway", "lambda", ["RESPONSE interception"]),
            Note("gateway", "lambda", ["Policy for get_case_note: shield the document"]),
            Self(6, "lambda", ["Check the URL against the", "allowlist and the file", "against the size limit"]),
            Section("Not allowlisted or over the size limit"),
            Msg(7, "lambda", "gateway", ["Block response (fail closed)"], reply=True),
            Msg(8, "gateway", "agent", ["Tool error"], reply=True),
            Section("Allowed"),
            Msg(9, "lambda", "skyflow", ["Submit presigned URL"]),
            Msg(10, "skyflow", "s3", ["Fetch via presigned URL"]),
            Msg(11, "s3", "skyflow", ["File bytes"], reply=True),
            Note("skyflow", "skyflow", ["De-identify file", "Store clean copy"]),
            Msg(12, "skyflow", "lambda", ["Signed URL to clean copy"], reply=True),
            Note("lambda", "s3", ["File bytes never pass through Lambda"]),
            Msg(13, "lambda", "gateway", ["Response with URL swapped"], reply=True),
            Msg(14, "gateway", "agent", ["Link to de-identified copy"], reply=True),
            Msg(15, "agent", "skyflow", ["Open clean copy"]),
            Msg(16, "skyflow", "agent", ["De-identified case note"], reply=True),
            Msg(17, "agent", "analyst", ["Summary (no", "original values)"], reply=True),
            EndSection(),
        ],
    )
    return sequence(seq)


# --- Reference architecture --------------------------------------------------


def node(name, cx, top, label, size=40):
    return icon(name, cx, top, size) + text(cx, top + size + 14, label, size=11.5)


def architecture() -> str:
    out: list[str] = []
    out.append(account_group(88, 12, 486, 600))
    out.append(dashed_group(592, 46, 196, 128, "Third party"))
    out.append(dashed_group(592, 430, 196, 136, "Skyflow (approved Region)"))

    # Analyst and agent.
    out.append(node("user", 40, 214, ["Analyst"]))
    out.append(node("agentcore", 150, 214, ["Agent", "(AgentCore", "Runtime)"]))
    out.append(line(62, 234, 124, 234, head_start=True))

    # The gateway and its two interception points.
    gx, gy, gw, gh = 214, 60, 196, 340
    out.append(f'<rect x="{gx}" y="{gy}" width="{gw}" height="{gh}" fill="none" stroke="#01A88D" stroke-width="1.5"/>')
    out.append(icon("agentcore", gx + 13, gy, 26))
    out.append(text(gx + 32, gy + 13, ["Amazon Bedrock", "AgentCore Gateway"], size=11.5, anchor="start"))
    for label, top in (("REQUEST interceptor", gy + 70), ("RESPONSE interceptor", gy + 232)):
        out.append(
            f'<rect x="{gx + 24}" y="{top}" width="{gw - 48}" height="42" rx="4" fill="{NOTE_FILL}" '
            f'stroke="{NOTE_STROKE}" stroke-width="1"/>'
        )
        out.append(text(gx + gw / 2, top + 25, label, size=12, weight="bold"))
    out.append(text(gx + gw / 2, gy + 168, ["Gateway calls", "the target"], size=11.5, fill=MUTED))

    # Agent to gateway, steps 1 and 5.
    out.append(line(176, 234, gx - 3, 234, head_start=True))
    out.append(badge(190, 214, 1))
    out.append(badge(190, 254, 5))

    # Targets.
    tx = 500
    out.append(node("s3", tx, 196, ["Amazon S3", "(case notes)"]))
    out.append(node("bedrock", tx, 300, ["Amazon Bedrock", "(model, through an", "inference target)"]))
    out.append(node("internet", 690, 76, ["Web search", "MCP server"]))
    for ty, tleft in ((96, 666), (216, tx - 22), (320, tx - 22)):
        out.append(line(gx + gw + 3, ty, tleft, ty, head_start=True))
    out.append(text(538, 90, "Tokens out, results back", size=11, fill=MUTED, halo=True))
    out.append(badge(gx + gw + 18, 96, 3))
    out.append(badge(gx + gw + 18, 216, 3))
    out.append(badge(gx + gw + 18, 320, 3))

    # The interceptor and its invocations.
    lx, ly = 312, 440
    out.append(node("lambda", lx, ly, ["Skyflow interceptor", "(AWS Lambda)"]))
    out.append(line(lx, ly - 4, lx, gy + 232 + 45, dashed=True))
    out.append(path(f"M{lx - 22},{ly + 20} H{gx + 10} V{gy + 91} H{gx + 21}", dashed=True))
    out.append(badge(gx + 10, gy + 60, 2))
    out.append(badge(gx + 10, gy + 254, 4))
    out.append(text(lx + 8, ly - 18, ["Invoked at both", "interception points"], size=10.5, anchor="start", fill=MUTED, halo=True))

    # Skyflow.
    sx = 690
    out.append(node("skyflow", sx, 470, ["Skyflow Detect", "+ Vault"]))
    out.append(line(lx + 24, 460, sx - 44, 490, head_start=True))
    out.append(text(486, 466, "De-identify and re-identify", size=10.5, fill=MUTED, halo=True))
    out.append(path(f"M{sx},{466} V{216} H{tx + 24}", dashed=True))
    out.append(text(sx + 6, 300, ["Fetch file via", "presigned URL"], size=10.5, anchor="start", fill=MUTED, halo=True))

    # What the interceptor uses.
    services = [
        ("ssm", 140, ["Parameter Store", "(policy)"]),
        ("secrets", 252, ["Secrets Manager", "(API key)"]),
        ("dynamodb", 368, ["DynamoDB", "(call records)"]),
        ("cloudwatch", 486, ["CloudWatch", "(logs, metrics)"]),
    ]
    rail = 528
    out.append(line(lx, ly + 76, lx, rail, head_end=False))
    out.append(line(140, rail, 486, rail, head_end=False))
    for name, cx, label in services:
        out.append(line(cx, rail, cx, 538))
        out.append(icon(name, cx, 542, 34))
        out.append(text(cx, 542 + 34 + 13, label, size=11))

    return document(WIDTH, 624, "".join(out))


FIGURES = {
    "fig1-reference-architecture": architecture,
    "fig2-shield-the-tool": shield_the_tool,
    "fig3-shield-the-model": shield_the_model,
    "fig4-shield-the-document": shield_the_document,
}


def main() -> None:
    for name, build in FIGURES.items():
        out = HERE / f"{name}.svg"
        out.write_text(build())
        print(out)


if __name__ == "__main__":
    main()
