import { useState, useEffect, useRef, useCallback } from "react";

/*
 * Onboarding tutorial / guided walkthrough.
 *
 * Why this exists: user testing (see testing notes) found first-time users
 * — especially people without a security/IT background — didn't know
 * where to start in the app, or what fields like "image, path, or repo to
 * scan" actually meant. This component is a lightweight, dependency-free
 * "spotlight" walkthrough: it dims the page, cuts a highlighted window
 * around one real UI element at a time, and shows a small tooltip
 * explaining it in plain language. No new npm packages required — it's
 * built with plain React + inline styles so it drops in without touching
 * package.json or the Docker build.
 *
 * How it finds elements: each step's `target` is a CSS selector. Add a
 * `data-tutorial="some-name"` attribute to the real element in App.jsx,
 * then reference it here as '[data-tutorial="some-name"]'. This is safer
 * than targeting className, since class names are just styling and can
 * change without warning; data-tutorial attributes are only ever used by
 * this component, so nothing else will accidentally rely on them.
 *
 * Steps intentionally never require the user to actually type or submit
 * anything real — per the team's design decision, it only explains what
 * things do; it does not walk them through entering real data.
 *
 * Persistence: right now this is stored in localStorage (per browser),
 * not tied to the user's account server-side. That's a deliberate v1
 * scope choice — a real per-account "has seen tutorial" flag would need
 * a small backend addition (a column on the users table, or a new
 * endpoint similar to business_context.py's pattern) which is a
 * reasonable follow-up task, not something this component assumes.
 */

const STORAGE_KEY = "p972_tutorial_completed_v1";

// The walkthrough script. Edit this array to add, remove, or reorder
// steps — the component itself doesn't need to change.
//
// Each step:
//   target      - CSS selector for the element to highlight, or null for
//                 a centered, non-spotlighted intro/outro card.
//   title       - short heading shown in the tooltip.
//   body        - plain-language explanation. Keep this short — one or
//                 two sentences. This is the part user testing showed
//                 matters most (e.g. explaining what "image, path, or
//                 repo" actually means before the user has to guess).
//   placement   - "bottom" | "top" | "left" | "right" — which side of the
//                 highlighted element the tooltip should try to sit on.
const STEPS = [
  {
    target: null,
    title: "Welcome to P972",
    body: "This is a quick walkthrough of how the app works — it won't ask you to enter anything real, just points out what things do. You can skip it any time.",
  },
  {
    target: '[data-tutorial="nav-upload-scan"]',
    title: "Start here",
    body: "This is where every scan begins. You can either upload a report you already have, or ask the app to run a scan for you directly.",
    placement: "bottom",
  },
  {
    target: '[data-tutorial="upload-dropzone"]',
    title: "Uploading an existing report",
    body: "If you already have scan results as a file (for example from Trivy or Tenable), drag it in here, or click to browse for it.",
    placement: "bottom",
  },
  {
    target: '[data-tutorial="live-scan-button"]',
    title: "Or scan something directly",
    body: "No existing report? Switch to \u201CRun a live scan\u201D and the app will run the scan itself against something you point it at.",
    placement: "bottom",
    // Clicking this step's own target is what reveals the live-scan form
    // fields the next two steps point at, so do it as soon as we arrive
    // here (not just on Next) — that way the fields exist and are visible
    // behind the tooltip by the time this step's own tooltip is showing,
    // and stay revealed if the user goes Back to this step later too.
    clickBefore: '[data-tutorial="live-scan-button"]',
  },
  {
    target: '[data-tutorial="scan-target-field"]',
    title: "What to put here",
    body: "This is asking for the name of a container image or a code repository \u2014 things developers use to package and store software. If your team doesn't use those, this scan type may not apply to what you're checking yet; ask whoever manages your systems if you're unsure.",
    placement: "top",
    // This field only renders in "Run a live scan" mode — without this,
    // arriving here directly (e.g. via Back/Next skipping around) could
    // land on a step whose target doesn't exist yet.
    clickBefore: '[data-tutorial="live-scan-button"]',
  },
  {
    target: '[data-tutorial="scanner-select"]',
    title: "Scanning something private",
    body: "If what you're scanning is kept somewhere private (not publicly available), select \u201CTrivy\u201D here \u2014 that scanner has an option to connect a private registry, set up from your Profile page.",
    placement: "bottom",
    clickBefore: '[data-tutorial="live-scan-button"]',
  },
  {
    target: '[data-tutorial="nav-tickets"]',
    title: "Where fixes get tracked",
    body: "Once you've reviewed and approved a finding, it shows up here as a real ticket \u2014 something your team can assign and work through.",
    placement: "bottom",
  },
  {
    target: '[data-tutorial="nav-profile"]',
    title: "Your account and setup",
    body: "Manage your details, connect integrations like Jira or a private registry, and update the business-context answers that help prioritise findings for you specifically.",
    placement: "bottom",
  },
  {
    target: null,
    title: "That's it",
    body: "You're set \u2014 upload or run your first scan whenever you're ready. You can restart this walkthrough any time from your Profile page.",
  },
];

export function hasCompletedTutorial() {
  try {
    return localStorage.getItem(STORAGE_KEY) === "true";
  } catch {
    return true; // fail safe: if storage is blocked, don't force the tutorial
  }
}

function markTutorialCompleted() {
  try {
    localStorage.setItem(STORAGE_KEY, "true");
  } catch {
    /* ignore — worst case the tutorial just reappears next visit */
  }
}

// Re-exported so a "Restart tutorial" button (e.g. in Profile) can clear
// the flag and re-show it without needing to know the storage key itself.
export function resetTutorial() {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    /* ignore */
  }
}

export default function Tutorial({ active, onFinish, onNavigate }) {
  const [stepIndex, setStepIndex] = useState(0);
  const [rect, setRect] = useState(null);
  const rafRef = useRef(null);

  const step = STEPS[stepIndex];

  // Reset to the first step whenever the tutorial (re)activates — without
  // this, clicking "Restart tutorial" in Profile after finishing once
  // would silently resume at the last step instead of actually restarting,
  // since this component stays mounted and stepIndex isn't otherwise reset.
  useEffect(() => {
    if (active) setStepIndex(0);
  }, [active]);

  // Finds the current step's target element and measures its position so
  // the spotlight cutout and tooltip can be positioned around it. Re-runs
  // on a short interval while active, since the page can scroll/resize or
  // the target element can mount slightly after the step becomes current
  // (e.g. switching tabs via onNavigate below).
  const measure = useCallback(() => {
    if (!step.target) {
      setRect(null);
      return;
    }
    const el = document.querySelector(step.target);
    if (!el) {
      setRect(null);
      return;
    }
    const r = el.getBoundingClientRect();
    setRect({
      top: r.top + window.scrollY,
      left: r.left + window.scrollX,
      width: r.width,
      height: r.height,
    });
  }, [step.target]);

  useEffect(() => {
    if (!active) return;
    // If this step depends on a different part of the UI being revealed
    // first (e.g. switching from "Upload a report" to "Run a live scan"
    // mode before the target field exists), do that first. Safe to call
    // even if that mode is already active — clicking the same toggle
    // again is a no-op, not a problem, so this doesn't need to track
    // whether it already ran.
    if (step.clickBefore) {
      document.querySelector(step.clickBefore)?.click();
    }
    measure();
    const onResize = () => measure();
    window.addEventListener("resize", onResize);
    window.addEventListener("scroll", onResize, true);
    // Poll briefly in case the target mounts a beat after the step changes
    // (e.g. right after onNavigate switches tabs, or clickBefore above
    // switches modes, and React re-renders).
    let tries = 0;
    const interval = setInterval(() => {
      measure();
      tries += 1;
      if (tries > 10) clearInterval(interval);
    }, 100);
    return () => {
      window.removeEventListener("resize", onResize);
      window.removeEventListener("scroll", onResize, true);
      clearInterval(interval);
    };
  }, [active, measure, stepIndex]);

  if (!active) return null;

  const isFirst = stepIndex === 0;
  const isLast = stepIndex === STEPS.length - 1;

  const goNext = () => {
    if (isLast) {
      markTutorialCompleted();
      onNavigate?.("dashboard");
      onFinish?.();
      return;
    }
    const next = STEPS[stepIndex + 1];
    // Let the caller switch tabs if the next step lives on a different
    // page — inferred from the data-tutorial name's "nav-x" prefix mapping
    // isn't assumed here; instead App.jsx passes onNavigate and this just
    // asks for it based on a simple convention: steps targeting
    // "upload-dropzone" / "live-scan-toggle" / etc. need the Upload Scan
    // tab active, "nav-tickets" needs no navigation (it's the nav item
    // itself), and so on. Kept as an explicit map below rather than
    // guessing from the selector, so it's obvious and easy to edit.
    const stepTabMap = {
      '[data-tutorial="upload-dropzone"]': "upload-scan",
      '[data-tutorial="live-scan-button"]': "upload-scan",
      '[data-tutorial="scan-target-field"]': "upload-scan",
      '[data-tutorial="scanner-select"]': "upload-scan",
    };
    const tab = stepTabMap[next.target];
    if (tab) onNavigate?.(tab);
    setStepIndex(i => i + 1);
  };

  const goBack = () => {
    if (isFirst) return;
    setStepIndex(i => i - 1);
  };

  const skip = () => {
    markTutorialCompleted();
    onFinish?.();
  };

  // Tooltip position: anchored near the highlighted rect if there is one,
  // otherwise centered on screen for the intro/outro cards.
  const tooltipStyle = (() => {
    const TOOLTIP_WIDTH = 320;
    // No reliable way to know the tooltip's real height before it renders
    // (content length varies per step), so this is a generous estimate —
    // enough to keep it from being clamped against the bottom edge on a
    // typical 2-3 sentence step. Slightly too tall is harmless (it just
    // leaves a bit more bottom margin than strictly needed); too short
    // would let it clip, which is the actual bug being fixed here.
    const TOOLTIP_HEIGHT_ESTIMATE = 220;
    const margin = 16;
    const maxLeft = window.innerWidth - TOOLTIP_WIDTH - margin;
    const maxTop = window.innerHeight - TOOLTIP_HEIGHT_ESTIMATE - margin;
    const clampLeft = v => Math.min(Math.max(margin, v), Math.max(margin, maxLeft));
    const clampTop = v => Math.min(Math.max(margin, v), Math.max(margin, maxTop));

    const base = {
      position: "fixed",
      zIndex: 10002,
      width: TOOLTIP_WIDTH,
      maxWidth: `calc(100vw - ${margin * 2}px)`,
      background: "#fff",
      borderRadius: 12,
      boxShadow: "0 12px 32px rgba(0,0,0,0.25)",
      padding: 18,
      fontFamily: "DM Sans, sans-serif",
    };
    if (!rect) {
      return { ...base, top: "50%", left: "50%", transform: "translate(-50%, -50%)" };
    }
    const gap = 14;
    const placement = step.placement || "bottom";
    if (placement === "bottom") {
      return { ...base, top: clampTop(rect.top - window.scrollY + rect.height + gap), left: clampLeft(rect.left - window.scrollX) };
    }
    if (placement === "top") {
      return { ...base, top: clampTop(rect.top - window.scrollY - gap - TOOLTIP_HEIGHT_ESTIMATE) + TOOLTIP_HEIGHT_ESTIMATE, left: clampLeft(rect.left - window.scrollX), transform: "translateY(-100%)" };
    }
    if (placement === "left") {
      return { ...base, top: clampTop(rect.top - window.scrollY), left: clampLeft(rect.left - window.scrollX - gap - TOOLTIP_WIDTH) + TOOLTIP_WIDTH, transform: "translateX(-100%)" };
    }
    return { ...base, top: clampTop(rect.top - window.scrollY), left: clampLeft(rect.left - window.scrollX + rect.width + gap) };
  })();

  return (
    <div aria-live="polite">
      {/* Dimmed backdrop. When there's a target rect, a box-shadow "cutout"
          technique creates the spotlight hole without needing an SVG mask. */}
      <div
        style={{
          position: "fixed",
          inset: 0,
          zIndex: 10000,
          background: rect ? "transparent" : "rgba(17, 24, 39, 0.55)",
          transition: "background 0.15s ease",
        }}
        onClick={skip}
      />
      {rect && (
        <div
          style={{
            position: "fixed",
            top: rect.top - window.scrollY - 6,
            left: rect.left - window.scrollX - 6,
            width: rect.width + 12,
            height: rect.height + 12,
            borderRadius: 10,
            boxShadow: "0 0 0 9999px rgba(17, 24, 39, 0.55)",
            zIndex: 10001,
            pointerEvents: "none",
            transition: "top 0.2s ease, left 0.2s ease, width 0.2s ease, height 0.2s ease",
            outline: "2px solid #2563eb",
          }}
        />
      )}

      <div style={tooltipStyle}>
        <div style={{ fontSize: 11, fontWeight: 700, color: "#2563eb", marginBottom: 6, letterSpacing: 0.2 }}>
          Step {stepIndex + 1} of {STEPS.length}
        </div>
        <div style={{ fontSize: 15, fontWeight: 700, color: "#111", marginBottom: 6 }}>{step.title}</div>
        <div style={{ fontSize: 13, color: "#4b5563", lineHeight: 1.5, marginBottom: 16 }}>{step.body}</div>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <button
            onClick={skip}
            style={{ background: "none", border: "none", color: "#9ca3af", fontSize: 12, cursor: "pointer", padding: 0 }}
          >
            Skip tutorial
          </button>
          <div style={{ display: "flex", gap: 8 }}>
            {!isFirst && (
              <button
                onClick={goBack}
                style={{ padding: "7px 14px", borderRadius: 20, border: "1px solid #e5e7eb", background: "#fff", color: "#374151", fontSize: 12, fontWeight: 600, cursor: "pointer" }}
              >
                Back
              </button>
            )}
            <button
              onClick={goNext}
              style={{ padding: "7px 16px", borderRadius: 20, border: "none", background: "#2563eb", color: "#fff", fontSize: 12, fontWeight: 600, cursor: "pointer" }}
            >
              {isLast ? "Done" : "Next"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
