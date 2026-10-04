"""QuoteShield as-built architecture diagram. Run: python3 architecture_diagram.py  (writes architecture.png and architecture.svg next to it).
Edit the BOXES / text below and re-run. Needs matplotlib only."""
import sys, textwrap
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle

OUT = sys.argv[1] if len(sys.argv) > 1 else 'architecture'
W, H = 200, 134
fig = plt.figure(figsize=(20, 13.4), dpi=150)
ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, W); ax.set_ylim(0, H); ax.axis('off')
fig.patch.set_facecolor('white')

NAVY, SLATE, INK, MUTE = '#1b2f4b', '#5b6b82', '#16202e', '#6b7686'
TEAL, AMBER, PLUM = '#17766f', '#b5780f', '#5f4590'
issues = []

def wrap(text, chars):
    out = []
    for para in text.split('\n'):
        out += textwrap.wrap(para, chars) or ['']
    return '\n'.join(out)

def box(x, y, w, h, title, body='', kind='plain', size=10.5, tsize=12, chars=None, tchars=None, center=False, fc=None, ec=None, ls='-', lw=1.4, tcolor=None, bcolor=None):
    fc = fc or 'white'; ec = ec or SLATE
    p = FancyBboxPatch((x, y), w, h, boxstyle='round,pad=0,rounding_size=1.2', fc=fc, ec=ec, lw=lw, ls=ls, zorder=3)
    ax.add_patch(p)
    chars = chars or max(8, int(w * 1.05))
    tw = tchars or chars
    if center and not body:
        t1 = ax.text(x + w / 2, y + h / 2, wrap(title, tw), ha='center', va='center', fontsize=tsize, fontweight='bold', color=tcolor or INK, zorder=5, linespacing=1.15)
        return (x, y, w, h, [t1])
    t1 = ax.text(x + w / 2, y + h - 1.6, wrap(title, tw), ha='center', va='top', fontsize=tsize, fontweight='bold', color=tcolor or INK, zorder=5, linespacing=1.15)
    texts = [t1]
    if body:
        n = len(wrap(title, tw).split('\n'))
        t2 = ax.text(x + w / 2, y + h - 1.6 - n * (tsize * 0.0182 * H / 13.4 * 1.1) - 0.9, wrap(body, chars + 2), ha='center', va='top', fontsize=size, color=bcolor or INK, zorder=5, linespacing=1.2)
        texts.append(t2)
    return (x, y, w, h, texts)

def arrow(p0, p1, color=SLATE, lw=1.8, style='-|>', ls='-', rad=0.0, ms=14, z=4):
    ax.add_patch(FancyArrowPatch(p0, p1, arrowstyle=style, mutation_scale=ms, color=color, lw=lw, ls=ls, zorder=z, connectionstyle='arc3,rad=%s' % rad, shrinkA=0, shrinkB=0))

def poly(points, color, lw=1.8, ls='-', head=True, z=4):
    for a, b in zip(points[:-2], points[1:-1]):
        ax.plot([a[0], b[0]], [a[1], b[1]], color=color, lw=lw, ls=ls, zorder=z, solid_capstyle='round')
    a, b = points[-2], points[-1]
    if head: arrow(a, b, color=color, lw=lw, ls=ls)
    else: ax.plot([a[0], b[0]], [a[1], b[1]], color=color, lw=lw, ls=ls, zorder=z)

boxes = []
# ---------------- title
ax.text(4, 130.2, 'QuoteShield: as-built architecture', fontsize=24, fontweight='bold', color=INK, va='center')
ax.text(196, 130.2, 'main @ 4b1d24d  ·  Code Utsava X.0 PS3  ·  team Vanquishers', fontsize=13, color=MUTE, va='center', ha='right')

# ---------------- scenario engine panel
ax.add_patch(FancyBboxPatch((3, 95.5), 194, 29, boxstyle='round,pad=0,rounding_size=2', fc='#eef3f9', ec='#8da2bd', lw=1.6, zorder=1))
ax.text(5.5, 121.6, 'SCENARIO ENGINE', fontsize=15, fontweight='bold', color='#2d4a73', va='center')
ax.text(40, 121.6, 'domain-agnostic. Manifests describe a test and never hard-code an outcome; outcomes are observed from the run.', fontsize=11.5, color='#2d4a73', va='center')
SE = [
    ('Manifests', '22 JSON files, 5 domains. Request, resources with classification, policy, attack or benign control.'),
    ('corpus/real', '5 real public pages with origin URL, retrieval time and sha256. Synthetic confidential files.'),
    ('Loader', 'Confined refs, provenance filled from the index, forbidden outcome keys rejected.'),
    ('Injector', '11 deterministic placements: footer, footnote, table cell, HTML comment, metadata...'),
    ('Paired runner', 'Same proposals twice: no defence vs full defence. Per-scenario delta.'),
    ('Scorer', 'Counts as n of N, never a bare rate. Records defence_version, refuses to pool.'),
    ('Explanation layer', 'Per-run plain reading of each layer. Describes one run, not a rate.'),
    ('Live L0-L9 UI', 'Streamlit panel: each layer lights up as the run reaches it.'),
]
bw, step, x0, by, bh = 22.2, 23.9, 5, 97.5, 21.5
for i, (t, b) in enumerate(SE):
    boxes.append(box(x0 + i * step, by, bw, bh, t, b, fc='white', ec='#8da2bd', size=10.5, chars=21))
cy = by + bh / 2
ax.text(x0 + 0 * step + bw + (step - bw) / 2, cy, '+', fontsize=18, ha='center', va='center', color='#2d4a73', fontweight='bold', zorder=6)
for i in (1, 2, 3, 4, 5):
    arrow((x0 + i * step + bw + 0.1, cy), (x0 + (i + 1) * step - 0.1, cy), color='#2d4a73')
arrow((x0 + 4 * step + bw / 2, by - 0.1), (x0 + 7 * step + bw / 2, by - 0.1), color='#2d4a73', ls=(0, (3, 3)), rad=0.0, lw=1.2, style='-', ms=1) if False else None
arrow((x0 + 6 * step + bw + 0.1, cy), (x0 + 7 * step - 0.1, cy), color='#2d4a73', ls=(0, (3, 3)))

# ---------------- boundary
ax.plot([3, 197], [91.5, 91.5], color=NAVY, lw=2.2, ls=(0, (6, 4)), zorder=2)
pill = FancyBboxPatch((28, 88.2), 144, 6.6, boxstyle='round,pad=0,rounding_size=3', fc='white', ec=NAVY, lw=1.8, zorder=6)
ax.add_patch(pill)
ax.text(100, 93.0, 'BOUNDARY: ResourcePolicy + run API. Generic authorization inputs only (resources, classification, recipients, tools).', fontsize=11.5, fontweight='bold', color=NAVY, ha='center', va='center', zorder=7)
ax.text(100, 90.0, 'Scenario engine above is domain-agnostic. It supplies inputs and reads results. It cannot change a gate decision.', fontsize=11, color=NAVY, ha='center', va='center', zorder=7)
for x in (14, 100, 186):
    arrow((x, 88.0), (x, 84.4), color=NAVY, lw=2.2, ms=16)
    arrow((x + 4, 84.4), (x + 4, 88.0), color=NAVY, lw=1.2, ms=10, ls=(0, (2, 2)))

# ---------------- security engine panel
ax.add_patch(FancyBboxPatch((3, 25.5), 194, 58.5, boxstyle='round,pad=0,rounding_size=2', fc='#f7f4ee', ec='#a89b7c', lw=1.6, zorder=1))
ax.text(5.5, 81.4, 'SECURITY ENGINE', fontsize=15, fontweight='bold', color='#5a4a22', va='center')
ax.text(37, 81.4, 'frozen: evaluator and data are byte-identical; gate changes land only by reviewed PR, with a recorded defence_version.', fontsize=11.5, color='#5a4a22', va='center')

L = [
    ('L0', 'User prompt guard', 'Rules plus decoded views on the task text. Can stop before any source is read.', True),
    ('L1', 'Scope engine', 'Tools, files, recipients and URLs fixed from the trusted task. A model may only narrow it.', True),
    ('L2', 'Retrieval', 'Documents and tool output enter as untrusted data.', False),
    ('L3', 'Content firewall', 'Rules, decoded views (base64, hex, ROT13), dual-pass OCR for images, optional classifier.', True),
    ('L4', 'Agent reasoning', 'The model proposes tool calls. Never trusted to decide.', False),
    ('L5', 'Action guard', 'Each call checked against the fixed scope: tool, path, recipient, URL.', True),
    ('L6', 'Provenance / taint', 'Once a confidential file is read, no external sink may receive it.', True),
    ('L7', 'Human approval', 'Exact call reviewed and approved once, rechecked on resume.', True),
    ('L8', 'Mock tool effect', 'Mock outbox and records only.', False),
    ('L9', 'Audit chain', 'Hash-chained entries, verified at the end.', False),
]
bw, step, x0, by, bh = 17.1, 19.05, 5.2, 47.0, 26.0
GX = {}
for i, (code, t, b, gate) in enumerate(L):
    x = x0 + i * step
    if gate:
        bx = box(x, by, bw, bh, t, b, fc=NAVY, ec='#0c1829', lw=2.4, tcolor='white', bcolor='#e6ecf5', size=9.6, tsize=11.5, chars=17, tchars=14)
    else:
        bx = box(x, by, bw, bh, t, b, fc='white', ec='#8d96a3', ls=(0, (4, 3)), lw=1.6, tcolor='#3b4655', bcolor='#4a5565', size=9.6, tsize=11.5, chars=17, tchars=14)
    boxes.append(bx); GX[code] = x + bw / 2
    ax.text(x + 1.2, by + bh + 1.3, code, fontsize=13, fontweight='bold', color=NAVY if gate else MUTE, va='bottom')
    ax.text(x + bw - 0.2, by + bh + 1.3, 'GATE' if gate else 'observed', fontsize=9.5, fontweight='bold' if gate else 'normal', color=NAVY if gate else MUTE, va='bottom', ha='right')
    if i < 9:
        arrow((x + bw + 0.2, by + bh / 2), (x + step - 0.2, by + bh / 2), color='#2b3a52', lw=2.2, ms=15)

# ---------------- classification row
cb_y, cb_h = 27.6, 13.4
CL = [
    ('A  PromptVerdict', 'BENIGN / MALICIOUS / UNCERTAIN. The classifier slot: ProtectAI by default, Prompt Guard 2 parked. A flag only adds a finding.', TEAL, 5.2, 60.0, ['L0', 'L3'], -3.2),
    ('B  DataClass', 'PUBLIC ... SECRET. Read from resource metadata and policy. Never from content, never an LLM.', AMBER, 68.0, 52.0, ['L1', 'L6'], 0.0),
    ('C  ActionDecision', 'ALLOW / BLOCK / ASK. Deterministic from task, tool, resource, recipient, class and provenance.', PLUM, 123.0, 72.0, ['L5', 'L7'], 3.2),
]
chan = {TEAL: 43.9, AMBER: 42.4, PLUM: 41.9}
for t, b, col, x, w, gates, off in CL:
    boxes.append(box(x, cb_y, w, cb_h, t, b, fc='white', ec=col, lw=2.2, tcolor=col, size=10.5, tsize=12.5, chars=int(w * 0.98)))
    cy_ = {TEAL: 44.4, AMBER: 43.0, PLUM: 44.4}[col]
    for g in gates:
        gx = GX[g] + off
        sx = min(max(gx, x + 4), x + w - 4)
        poly([(sx, cb_y + cb_h), (sx, cy_), (gx, cy_), (gx, by - 0.2)], col, lw=2.0)
ax.text(100, 45.9, '', fontsize=1)

# ---------------- lanes
ax.text(5.5, 22.5, 'DATA FLOW, TWO LANES', fontsize=13, fontweight='bold', color=INK, va='center')
ax.text(46, 22.5, 'same task, same documents, same scripted proposals. Only the defence differs. The delta is observed, not stored.', fontsize=11.5, color=MUTE, va='center')
def lane(y, label, items, col, fc, dashed_gaps=()):
    ax.text(5.5, y + 3.3, label, fontsize=11.5, fontweight='bold', color=col, va='center')
    n = len(items); x = 33; tot = 128; gap = 2.3; w = (tot - gap * (n - 1)) / n
    for i, it in enumerate(items):
        ex = x + i * (w + gap)
        boxes.append(box(ex, y, w, 6.6, it, '', fc=fc, ec=col, lw=1.6, tsize=10.2, chars=int(w * 1.12), center=True))
        # center title vertically
        if i < n - 1: arrow((ex + w + 0.1, y + 3.3), (ex + w + gap - 0.1, y + 3.3), color=col, lw=1.8, ms=12)
lane(12.6, 'BASELINE  (no defence)', ['task prompt', 'documents (injected)', 'model proposal', 'tool effect runs', 'audit'], '#9a3b2e', '#fbeeec')
lane(3.8, 'PROTECTED  (full defence)', ['L0 prompt guard', 'L1 scope fixed (audit #1)', 'L3 firewall', 'L4 proposal', 'L5 guard, L6 taint', 'L7 human', 'L8 effect, L9 chain'], '#1d6b3a', '#eaf5ee')
dx = 164
boxes.append(box(dx, 3.8, 32, 15.4, 'DELTA per scenario', 'PREVENTED / STILL_SUCCEEDS / NOT_COMPARABLE_OFFLINE. Aggregated by the scorer.', fc='white', ec=NAVY, lw=2.0, tcolor=NAVY, size=10.2, tsize=12, chars=30))
arrow((161.6, 15.9), (dx - 0.1, 14.6), color='#9a3b2e', lw=1.8, ms=12)
arrow((161.6, 7.1), (dx - 0.1, 8.6), color='#1d6b3a', lw=1.8, ms=12)

# ---------------- honest footer
ax.add_patch(FancyBboxPatch((3, 0.6), 194, 1.9, boxstyle='round,pad=0,rounding_size=0.8', fc=NAVY, ec=NAVY, zorder=3))
ax.text(100, 1.55, 'Allow and block decisions are deterministic code. An LLM or classifier assist can only narrow scope or add a finding, never allow.', fontsize=12.5, fontweight='bold', color='white', ha='center', va='center', zorder=6)
ax.text(197, 133.0, '', fontsize=1)
ax.text(100, 128.0, 'Dev scenario manifests, offline scripted proposals. Not a benchmark and not a live-agent result.', fontsize=11, color=MUTE, ha='center', va='center')

# ---------------- overflow check
fig.canvas.draw()
r = fig.canvas.get_renderer()
inv = ax.transData.inverted()
for (x, y, w, h, texts) in boxes:
    for t in texts:
        bb = t.get_window_extent(r); (x0_, y0_), (x1_, y1_) = inv.transform((bb.x0, bb.y0)), inv.transform((bb.x1, bb.y1))
        if x0_ < x + 0.3 or x1_ > x + w - 0.3 or y0_ < y + 0.3 or y1_ > y + h - 0.3:
            issues.append((t.get_text().split('\n')[0][:30], round(x0_ - x, 1), round(x + w - x1_, 1), round(y0_ - y, 1), round(y + h - y1_, 1)))
print('overflow issues:', issues)
fig.savefig(OUT + '.png', dpi=150, facecolor='white')
fig.savefig(OUT + '.svg', facecolor='white')
