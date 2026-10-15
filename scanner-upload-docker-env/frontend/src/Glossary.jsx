import { useState, useRef, useLayoutEffect, useId, useCallback } from "react";
import { createPortal } from "react-dom";

/*
 * Plain-language glossary + hover tooltips.
 *
 * Usage in App.jsx:
 *
 *   <Term k="cvss">CVSS</Term>               // underlined term, tooltip on hover/focus/tap
 *   <Term k="cvss" />                        // uses the glossary's own label as the text
 *   <Term k="imageTarget">Image, path, or repo to scan</Term>
 *
 * To add or edit a definition, change GLOSSARY below — nothing else needs
 * to change. Each entry:
 *   label  - the term's proper name (shown as the tooltip heading)
 *   short  - one or two sentences, no jargon, written for someone who has
 *            never used a security tool
 *   where  - optional. "How do I find this?" — shown as a second block.
 *            Use it for things the user has to type in themselves.
 *
 * Unknown keys render their children as plain text, so a typo never breaks
 * the page.
 */

export const GLOSSARY = {
  // ---- Core vulnerability terms -------------------------------------------
  cve: {
    label: "CVE",
    short:
      "A public ID for one specific known security flaw, like CVE-2024-3094. Anyone in the world can look it up by that ID to see what the flaw is and which software it affects.",
  },
  cvss: {
    label: "CVSS score",
    short:
      "A 0–10 score for how dangerous a flaw is in general. 9–10 is critical, 7–8.9 is high, 4–6.9 is medium, below 4 is low. It doesn't know anything about your business, which is why we also show a business-based ranking.",
  },
  severity: {
    label: "Severity",
    short:
      "A label (Critical, High, Medium, Low) that groups the CVSS score into bands, so you can see at a glance what to look at first.",
  },
  asset: {
    label: "Asset",
    short:
      "The thing the problem was found on: a server, a container image, an application or a device.",
  },
  package: {
    label: "Package",
    short:
      "A piece of software installed on the asset (for example openssl or nginx). Most flaws are fixed by updating a package to a newer version.",
  },
  falsePositive: {
    label: "False positive",
    short:
      "A finding that looks like a problem but isn't one for you. For example, the flaw is in a feature you don't use, or the software has already been patched. Marking these avoids wasting time on tickets that don't matter.",
  },
  needsReview: {
    label: "Needs review",
    short:
      "The AI wasn't sure about this one, or the scanner left out some details. It may be a false positive, so a person should double-check it before a ticket is created.",
  },
  noFlags: {
    label: "No flags",
    short:
      "Our automatic checks found nothing to flag: the scanner gave a CVSS score and description, and the AI analysis ran with reasonable confidence. This is not proof the finding is real or that the AI is right. It's still worth a glance, and the reference links on the detail page let you check it yourself.",
  },
  aiConfidence: {
    label: "AI confidence",
    short:
      "How sure the AI is that its explanation and suggested fix are right for this finding. Below about 60% we flag it as Needs review.",
  },
  businessPriority: {
    label: "Business priority",
    short:
      "The CVSS score adjusted using your business profile (what your organisation does, what data it holds). Two flaws with the same CVSS can matter very differently to you; this ranks by that.",
    where: "Complete or edit your business profile on the Profile page to improve this ranking.",
  },
  businessCriticality: {
    label: "Business criticality",
    short:
      "How much this flaw matters to your organisation specifically, based on your business profile, not just how severe it is in general.",
  },
  remediation: {
    label: "Remediation",
    short: "Fixing the problem, usually by updating software, changing a setting or removing something that isn't needed.",
  },
  priority: {
    label: "Ticket priority",
    short:
      "How urgent the ticket is. P1 is the most urgent (fix now), P2 is soon, P3 and below can wait for normal maintenance.",
  },
  newSinceLastScan: {
    label: "New (last scan)",
    short: "Critical findings that appeared in your latest scan but were not in the one before it.",
  },
  uniqueCves: {
    label: "Unique CVEs seen",
    short: "How many different flaws have shown up across all of your scans. A flaw found in five scans still counts once.",
  },
  resolvedCves: {
    label: "Resolved CVEs",
    short: "Flaws that appeared in earlier scans but are no longer in your most recent one, so they've probably been fixed.",
  },
  recurring: {
    label: "Recurring",
    short: "A flaw that has shown up in more than one scan. If it's still in the latest scan, it hasn't been fixed yet.",
  },

  // ---- Scanners and how to connect a target -------------------------------
  scanner: {
    label: "Scanner",
    short:
      "The tool that looks for known flaws. Trivy checks container images, folders and code repositories. Tenable checks servers and devices on your network.",
  },
  trivy: {
    label: "Trivy",
    short: "A free, open-source tool that checks container images, folders and code repositories for known flaws.",
  },
  tenable: {
    label: "Tenable",
    short: "A commercial scanning service (Tenable.io) that checks servers and devices across your network.",
  },
  imageTarget: {
    label: "What to scan",
    short:
      "What Trivy should check. It depends on the scan type: a container image name (like myapp:latest), a folder path on the backend server, or a Git repository URL.",
    where:
      "For an image, run `docker images` in a terminal. Combine the REPOSITORY and TAG columns as repository:tag, e.g. nginx:1.25. Images from a private registry need the registry address in front, like ghcr.io/team/app:latest.",
  },
  tenableScanId: {
    label: "Tenable scan ID",
    short: "The number Tenable uses to identify one of your saved scans. We start that scan and pull in its results.",
    where:
      "In Tenable.io, open Scans and click the scan. The number is in the page address. If you can't find it, ask whoever manages Tenable, or list scans via the Tenable API (GET /scans).",
  },
  scanType: {
    label: "Scan type",
    short:
      "Container image: a packaged app (what Docker runs). Filesystem path: a folder on the backend server. Git repo URL: a code repository, scanned for vulnerable dependencies.",
  },
  runsVia: {
    label: "Runs via",
    short:
      "Where Trivy runs. \"Trivy CLI\" uses Trivy installed directly on the backend server. \"Docker\" runs Trivy inside a temporary container, so nothing needs installing, but the server must have Docker.",
    where: "Not sure? Try Docker if the backend runs on a machine with Docker installed; otherwise ask your admin.",
  },
  containerImage: {
    label: "Container image",
    short: "A packaged copy of an application plus everything it needs to run, used by Docker and Kubernetes. Scanning it finds flaws in the software packed inside.",
  },
  registry: {
    label: "Container registry",
    short:
      "An online store for container images, like Docker Hub, GitHub Container Registry (ghcr.io) or a company's own server. Private ones need a login to pull images.",
  },
  registryHost: {
    label: "Registry host",
    short: "The web address of the registry that holds your image. It's the first part of the image name.",
    where:
      "Look at the full image name. For ghcr.io/team/app:latest the host is ghcr.io. Docker Hub is docker.io. For a company registry, ask your platform team.",
  },
  registryToken: {
    label: "Password or access token",
    short:
      "The secret that proves you can read images from the registry. An access token is safer than your real password because it can be limited to read-only and revoked at any time.",
    where:
      "Create one in your registry's settings: GitHub → Settings → Developer settings → Personal access tokens (read:packages). Docker Hub → Account settings → Security → New access token.",
  },
};

const GAP = 8;
const MARGIN = 10;

export function Term({ k, children, style }) {
  const entry = GLOSSARY[k];
  const id = useId();
  const anchorRef = useRef(null);
  const tipRef = useRef(null);
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState({ top: 0, left: 0, arrow: 20, above: false });

  const show = useCallback(() => setOpen(true), []);
  const hide = useCallback(() => setOpen(false), []);

  // Place the tooltip after it has rendered (so we know its size), flipping
  // above the term if there's no room below and clamping to the viewport so
  // it never gets cut off on a narrow screen.
  useLayoutEffect(() => {
    if (!open || !anchorRef.current || !tipRef.current) return;
    const a = anchorRef.current.getBoundingClientRect();
    const t = tipRef.current.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;

    const above = a.bottom + GAP + t.height > vh - MARGIN && a.top - GAP - t.height > MARGIN;
    const top = above ? a.top - GAP - t.height : a.bottom + GAP;
    let left = a.left + a.width / 2 - t.width / 2;
    left = Math.max(MARGIN, Math.min(left, vw - t.width - MARGIN));
    const arrow = Math.max(12, Math.min(a.left + a.width / 2 - left, t.width - 12));
    setPos({ top, left, arrow, above });
  }, [open]);

  useLayoutEffect(() => {
    if (!open) return;
    const onKey = e => e.key === "Escape" && setOpen(false);
    const onScroll = () => setOpen(false);
    const onDown = e => {
      if (anchorRef.current && !anchorRef.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onDown);
    document.addEventListener("touchstart", onDown);
    window.addEventListener("scroll", onScroll, true);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("touchstart", onDown);
      window.removeEventListener("scroll", onScroll, true);
    };
  }, [open]);

  if (!entry) return <>{children}</>;

  return (
    <>
      <span
        ref={anchorRef}
        tabIndex={0}
        role="button"
        aria-describedby={open ? id : undefined}
        aria-label={`${entry.label}: what does this mean?`}
        onMouseEnter={show}
        onMouseLeave={hide}
        onFocus={show}
        onBlur={hide}
        onClick={e => {
          // Tap-to-toggle on touch screens. Stop propagation so a Term
          // inside a clickable row/header doesn't also trigger the row.
          e.stopPropagation();
          setOpen(o => !o);
        }}
        style={{
          borderBottom: "1px dotted currentColor",
          cursor: "help",
          textTransform: "inherit",
          letterSpacing: "inherit",
          ...style,
        }}
      >
        {children ?? entry.label}
      </span>
      {open &&
        createPortal(
          <div
            ref={tipRef}
            id={id}
            role="tooltip"
            style={{
              position: "fixed",
              top: pos.top,
              left: pos.left,
              zIndex: 10000,
              width: 290,
              maxWidth: `calc(100vw - ${MARGIN * 2}px)`,
              background: "#1f2937",
              color: "#f9fafb",
              borderRadius: 10,
              padding: "12px 14px",
              boxShadow: "0 8px 24px rgba(0,0,0,0.22)",
              fontFamily: "'DM Sans', sans-serif",
              fontSize: 12.5,
              lineHeight: 1.5,
              fontWeight: 400,
              textTransform: "none",
              letterSpacing: "normal",
              textAlign: "left",
              pointerEvents: "none",
            }}
          >
            <span
              aria-hidden="true"
              style={{
                position: "absolute",
                left: pos.arrow - 6,
                [pos.above ? "bottom" : "top"]: -5,
                width: 12,
                height: 12,
                background: "#1f2937",
                transform: "rotate(45deg)",
              }}
            />
            <div style={{ position: "relative" }}>
              <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 4 }}>{entry.label}</div>
              <div>{entry.short}</div>
              {entry.where && (
                <div style={{ marginTop: 8, paddingTop: 8, borderTop: "1px solid #4b5563" }}>
                  <div style={{ fontWeight: 600, color: "#93c5fd", marginBottom: 2 }}>How to find it</div>
                  <div>{entry.where}</div>
                </div>
              )}
            </div>
          </div>,
          document.body
        )}
    </>
  );
}

export default Term;
