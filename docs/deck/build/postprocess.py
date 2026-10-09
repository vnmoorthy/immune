#!/usr/bin/env python3
"""
Immune deck post-processor (lxml). Runs after build_deck.js + applyTheme:

  1. Maps the slide master's colours dark (bg1→dk1, tx1→lt1, bg2→dk2, tx2→lt2) so slides are white-on-black
     while the notes master keeps the standard map (dark text on a light notes page / presenter view).
  2. Writes a <p:transition> into every slide: Morph (p159, with a Fade fallback) when the slide shares a
     "!!"-named shape with the previous slide, otherwise Fade.
  3. Writes <p:timing> entrance animations for the key reveals (slides 4, 5, 6; slide 8 only when the
     native-shape architecture is used). Targets are resolved by shape name, so a missing shape is skipped.

usage: python3 postprocess.py deck.pptx [out.pptx]
"""
import sys
import zipfile
from lxml import etree

NS = {
    "p": "http://schemas.openxmlformats.org/presentationml/2006/main",
    "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
}
P = "{%s}" % NS["p"]
MC = "http://schemas.openxmlformats.org/markup-compatibility/2006"
P14 = "http://schemas.microsoft.com/office/powerpoint/2010/main"
P159 = "http://schemas.microsoft.com/office/powerpoint/2015/09/main"
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"

# ----------------------------------------------------------------------------- animation plan
# (shape name, effect, duration ms, delay ms from the group start)
def _loop_cascade():
    fx = [("!!rail", "wipe-right", 900, 0), ("step1", "ascend", 500, 150)]
    for i in range(2, 8):
        d = 150 + (i - 1) * 160
        fx += [(f"!!n{i}", "fade", 300, d), (f"step{i}", "ascend", 500, d)]
    fx += [("rule_line", "fade", 500, 1450), ("tti_line", "fade", 500, 1650)]
    return fx


def _theatre():
    fx = []
    for i in range(2, 8):
        d = (i - 2) * 230
        fx += [(f"ok{i}", "fade", 200, d), (f"val{i}", "fade", 300, d)]
    fx += [
        ("tti_label", "fade", 300, 1450),
        ("!!tti", "zoom", 650, 1450),
        ("tti_sub", "fade", 400, 1900),
        ("imm_tag", "fade", 300, 2250),
        ("imm_text", "fade", 400, 2250),
    ]
    return fx


PLAN = {
    4: {"trigger": "auto", "effects": _loop_cascade()},
    5: {"trigger": "click", "effects": _theatre()},
    6: {
        "trigger": "auto",
        "effects": [
            ("catch_after", "ascend", 450, 350), ("catch_sub", "fade", 400, 350),
            ("fp_after", "ascend", 450, 700), ("fp_sub", "fade", 400, 700),
            ("breach_after", "ascend", 450, 1050), ("breach_sub", "fade", 400, 1050),
            ("verify_ok", "fade", 300, 1650),
            ("tamper_cmd", "fade", 300, 2250),
            ("tamper_fail", "fade", 300, 2750),
        ],
    },
    8: {
        "trigger": "auto",
        "effects": [
            ("ret1", "wipe-down", 350, 500), ("ret2", "wipe-left", 700, 850),
            ("ret3", "wipe-up", 350, 1550), ("ret_label", "fade", 400, 1900),
        ],
    },
}

PRESETS = {  # effect → (presetID, presetSubtype)
    "fade": (10, 0),
    "ascend": (42, 0),       # Float In (Ascend)
    "wipe-right": (22, 8),   # Wipe from left  (motion to the right)
    "wipe-left": (22, 2),    # Wipe from right
    "wipe-down": (22, 1),    # Wipe from top
    "wipe-up": (22, 4),      # Wipe from bottom
    "zoom": (53, 16),        # Fade Zoom (object centre)
}

FADE_SPD = "med"
MORPH_MS = 1200


class Ids:
    def __init__(self):
        self.n = 0

    def next(self):
        self.n += 1
        return self.n


def _tgt(spid):
    return f'<p:tgtEl><p:spTgt spid="{spid}"/></p:tgtEl>'


def _set_visible(ids, spid):
    return (f'<p:set><p:cBhvr><p:cTn id="{ids.next()}" dur="1" fill="hold"><p:stCondLst><p:cond delay="0"/></p:stCondLst></p:cTn>'
            f'{_tgt(spid)}<p:attrNameLst><p:attrName>style.visibility</p:attrName></p:attrNameLst></p:cBhvr>'
            f'<p:to><p:strVal val="visible"/></p:to></p:set>')


def _anim_effect(ids, spid, filt, dur):
    return (f'<p:animEffect transition="in" filter="{filt}"><p:cBhvr><p:cTn id="{ids.next()}" dur="{dur}"/>'
            f'{_tgt(spid)}</p:cBhvr></p:animEffect>')


def _anim(ids, spid, attr, frm, to, dur):
    return (f'<p:anim calcmode="lin" valueType="num"><p:cBhvr><p:cTn id="{ids.next()}" dur="{dur}" fill="hold"/>{_tgt(spid)}'
            f'<p:attrNameLst><p:attrName>{attr}</p:attrName></p:attrNameLst></p:cBhvr><p:tavLst>'
            f'<p:tav tm="0"><p:val><p:strVal val="{frm}"/></p:val></p:tav>'
            f'<p:tav tm="100000"><p:val><p:strVal val="{to}"/></p:val></p:tav></p:tavLst></p:anim>')


def _effect(ids, spid, kind, dur, delay, node_type):
    preset, sub = PRESETS[kind]
    ctn = ids.next()
    body = _set_visible(ids, spid)
    if kind == "fade":
        body += _anim_effect(ids, spid, "fade", dur)
    elif kind == "ascend":
        body += _anim_effect(ids, spid, "fade", dur)
        body += _anim(ids, spid, "ppt_x", "#ppt_x", "#ppt_x", dur)
        body += _anim(ids, spid, "ppt_y", "#ppt_y+.03", "#ppt_y", dur)
    elif kind.startswith("wipe-"):
        body += _anim_effect(ids, spid, f"wipe({kind.split('-')[1]})", dur)
    elif kind == "zoom":
        body += _anim(ids, spid, "ppt_w", "#ppt_w*0.82", "#ppt_w", dur)
        body += _anim(ids, spid, "ppt_h", "#ppt_h*0.82", "#ppt_h", dur)
        body += _anim_effect(ids, spid, "fade", dur)
    else:
        raise ValueError(kind)
    return (f'<p:par><p:cTn id="{ctn}" presetID="{preset}" presetClass="entr" presetSubtype="{sub}" fill="hold" grpId="0" '
            f'nodeType="{node_type}"><p:stCondLst><p:cond delay="{delay}"/></p:stCondLst><p:childTnLst>{body}</p:childTnLst></p:cTn></p:par>')


def timing_xml(plan, shapes):
    """shapes: name → (id, tag). Returns (xml or None, list of (name, effect, delay) applied, missing names)."""
    ids = Ids()
    root_id, seq_id, grp_id, inner_id = ids.next(), ids.next(), ids.next(), ids.next()
    effs, bld, applied, missing = "", [], [], []
    for name, kind, dur, delay in plan["effects"]:
        if name not in shapes:
            missing.append(name)
            continue
        spid, tag = shapes[name]
        first = not applied
        node_type = ("afterEffect" if plan["trigger"] == "auto" else "clickEffect") if first else "withEffect"
        effs += _effect(ids, spid, kind, dur, delay, node_type)
        applied.append((name, kind, delay))
        if tag == "sp" and spid not in bld:
            bld.append(spid)
    if not applied:
        return None, applied, missing
    cond = '<p:cond delay="indefinite"/>'
    if plan["trigger"] == "auto":
        cond += f'<p:cond evt="onBegin" delay="0"><p:tn val="{seq_id}"/></p:cond>'
    xml = (
        f'<p:timing xmlns:p="{NS["p"]}"><p:tnLst><p:par><p:cTn id="{root_id}" dur="indefinite" restart="never" nodeType="tmRoot"><p:childTnLst>'
        f'<p:seq concurrent="1" nextAc="seek"><p:cTn id="{seq_id}" dur="indefinite" nodeType="mainSeq"><p:childTnLst>'
        f'<p:par><p:cTn id="{grp_id}" fill="hold"><p:stCondLst>{cond}</p:stCondLst><p:childTnLst>'
        f'<p:par><p:cTn id="{inner_id}" fill="hold"><p:stCondLst><p:cond delay="0"/></p:stCondLst><p:childTnLst>{effs}</p:childTnLst></p:cTn></p:par>'
        f'</p:childTnLst></p:cTn></p:par>'
        f'</p:childTnLst></p:cTn>'
        f'<p:prevCondLst><p:cond evt="onPrev" delay="0"><p:tgtEl><p:sldTgt/></p:tgtEl></p:cond></p:prevCondLst>'
        f'<p:nextCondLst><p:cond evt="onNext" delay="0"><p:tgtEl><p:sldTgt/></p:tgtEl></p:cond></p:nextCondLst>'
        f'</p:seq></p:childTnLst></p:cTn></p:par></p:tnLst>'
        + ("<p:bldLst>" + "".join('<p:bldP spid="%s" grpId="0" animBg="1"/>' % s for s in bld) + "</p:bldLst>" if bld else "")
        + '</p:timing>'
    )
    return xml, applied, missing


def transition_xml(morph):
    if morph:
        return (f'<mc:AlternateContent xmlns:mc="{MC}" xmlns:p="{NS["p"]}"><mc:Choice xmlns:p159="{P159}" xmlns:p14="{P14}" Requires="p159">'
                f'<p:transition spd="slow" p14:dur="{MORPH_MS}"><p159:morph option="byObject"/></p:transition></mc:Choice>'
                f'<mc:Fallback><p:transition spd="slow"><p:fade/></p:transition></mc:Fallback></mc:AlternateContent>')
    return f'<p:transition xmlns:p="{NS["p"]}" spd="{FADE_SPD}"><p:fade/></p:transition>'


def slide_order(z):
    pres = etree.fromstring(z.read("ppt/presentation.xml"))
    rels = etree.fromstring(z.read("ppt/_rels/presentation.xml.rels"))
    target = {r.get("Id"): r.get("Target") for r in rels.findall(f"{{{REL_NS}}}Relationship")}
    out = []
    for sid in pres.find("p:sldIdLst", NS).findall("p:sldId", NS):
        t = target[sid.get(f"{{{NS['r']}}}id")]
        out.append(t[1:] if t.startswith("/") else "ppt/" + t)
    return out


def shapes_of(root):
    shapes = {}
    for el in root.iter(P + "sp", P + "pic", P + "cxnSp", P + "graphicFrame", P + "grpSp"):
        nv = el.find(".//p:cNvPr", NS)
        if nv is None:
            continue
        shapes.setdefault(nv.get("name"), (nv.get("id"), etree.QName(el).localname))
    return shapes


def main(src, dst):
    zin = zipfile.ZipFile(src)
    parts = {i.filename: zin.read(i.filename) for i in zin.infolist()}
    order = slide_order(zin)
    report = []

    # 1. dark colour map on the slide master(s)
    for name in [n for n in parts if n.startswith("ppt/slideMasters/slideMaster") and n.endswith(".xml")]:
        root = etree.fromstring(parts[name])
        cm = root.find("p:clrMap", NS)
        cm.set("bg1", "dk1"); cm.set("tx1", "lt1"); cm.set("bg2", "dk2"); cm.set("tx2", "lt2")
        parts[name] = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)

    # 1b. title placeholders: pptxgenjs writes idx="100"; tools such as python-pptx/markitdown expect the
    #     title at idx 0 (the default). Drop the idx on type="title" placeholders in layouts and slides alike.
    for name in [n for n in parts if (n.startswith("ppt/slideLayouts/slideLayout") or n.startswith("ppt/slides/slide")) and n.endswith(".xml")]:
        root = etree.fromstring(parts[name])
        changed = False
        for ph in root.iter(P + "ph"):
            if ph.get("type") == "title" and ph.get("idx") is not None:
                del ph.attrib["idx"]
                changed = True
        if changed:
            parts[name] = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)

    # 2 + 3. transitions and timing
    prev_morph_names = set()
    for idx, name in enumerate(order, start=1):
        root = etree.fromstring(parts[name])
        for old in root.findall("p:transition", NS) + root.findall("p:timing", NS) + root.findall(f"{{{MC}}}AlternateContent"):
            root.remove(old)
        shapes = shapes_of(root)
        morph_names = {n for n in shapes if n and n.startswith("!!")}
        shared = sorted(morph_names & prev_morph_names) if idx > 1 else []
        morph = bool(shared)
        anchor = root.find("p:clrMapOvr", NS)
        pos = list(root).index(anchor) + 1 if anchor is not None else len(root)
        root.insert(pos, etree.fromstring(transition_xml(morph)))
        line = {"slide": idx, "transition": "Morph" if morph else "Fade", "shared": shared}
        if idx in PLAN:
            xml, applied, missing = timing_xml(PLAN[idx], shapes)
            if xml:
                root.insert(pos + 1, etree.fromstring(xml))
                line["animations"] = len(applied)
                line["trigger"] = PLAN[idx]["trigger"]
            if missing and applied:
                line["skipped"] = missing
        report.append(line)
        prev_morph_names = morph_names
        parts[name] = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)

    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            zout.writestr(info.filename, parts[info.filename])
    for line in report:
        print(line)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else sys.argv[1])
