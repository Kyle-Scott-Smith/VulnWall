// AI confidence is an estimate the model reports about its own answer. When
// there isn't one (AI analysis didn't run, or the model returned none) the UI
// must say so rather than show an invented number — a made-up "95%" reads as
// a verification stamp it hasn't earned.

export function hasConfidence(confidence) {
  return typeof confidence === "number" && Number.isFinite(confidence);
}

export function formatConfidence(confidence) {
  return hasConfidence(confidence) ? `${confidence}%` : "Not assessed";
}

// Below this, a human should look at the finding before ticketing it.
export const LOW_CONFIDENCE_THRESHOLD = 60;

export function isLowConfidence(confidence) {
  return hasConfidence(confidence) && confidence < LOW_CONFIDENCE_THRESHOLD;
}
