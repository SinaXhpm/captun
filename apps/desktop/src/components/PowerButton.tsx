import { Power } from "lucide-react";
import { useEffect, useRef } from "react";

export type PowerPhase = "off" | "busy" | "on" | "error" | "unavailable";

/** The wheel's speed while sharing, against the turning-on speed (one turn
 * in 3 s, set in styles.css): one calm turn in 14 s. */
const SAILING_RATE = 3 / 14;
/** Where the wheel starts from rest when sharing turns on or off: slowly,
 * gathering speed, as a hand puts its weight into it. */
const FROM_REST = 0.12;
/** The speed changes over this long, in a few small steps, so the wheel
 * speeds up and slows down instead of lurching. */
const RATE_CHANGE_MS = 900;
const RATE_STEPS = 12;

/** A point `r` out from the middle of the 200 × 200 drawing, `deg` clockwise from three o'clock. */
function at(r: number, deg: number): [number, number] {
  const a = (deg * Math.PI) / 180;
  return [Math.round((100 + r * Math.cos(a)) * 100) / 100, Math.round((100 + r * Math.sin(a)) * 100) / 100];
}

/** A line from `r1` to `r2` out from the middle at each angle. */
function rays(angles: number[], r1: number, r2: number): string {
  return angles
    .map((deg) => {
      const [x1, y1] = at(r1, deg);
      const [x2, y2] = at(r2, deg);
      return `M${x1} ${y1}L${x2} ${y2}`;
    })
    .join("");
}

// A ship's wheel round the button, the logo's helm: a rim with a band inside
// it, six spokes out of it and a long handle on each, one for every device a
// link reaches. Worked out once.
const ANGLES = [-90, -30, 30, 90, 150, 210];
const SPOKES = rays(ANGLES, 68, 80);
const HANDLES = rays(ANGLES, 81, 93);

/**
 * The big round start/stop button, drawn as a ship's wheel in brass: this
 * computer is the hub in the middle (the icon and word), the handles round
 * the rim are the devices. Turning sharing on or off, the wheel is put to
 * work: it gathers speed and turns briskly until it is done, even when the
 * system asks for less motion, as it is what says the app is busy. Once
 * sharing is on the handles light up and the wheel keeps a calm turn; when
 * sharing is off it rests where it stopped.
 */
export function PowerButton({
  phase,
  label,
  title,
  onClick,
}: {
  phase: PowerPhase;
  label: string;
  title?: string;
  onClick?: () => void;
}) {
  const disabled = !onClick || phase === "busy" || phase === "unavailable";
  const helm = useRef<SVGSVGElement>(null);
  const last = useRef<PowerPhase>(phase);

  // The turn is a CSS animation (styles.css, "helm-turn"); only its speed is
  // set here. updatePlaybackRate keeps the wheel's angle, so changing speed
  // never makes it jump. With reduced motion only the busy turn exists.
  useEffect(() => {
    const was = last.current;
    last.current = phase;
    const turn = helm.current
      ?.getAnimations()
      .find((a): a is CSSAnimation => a instanceof CSSAnimation && a.animationName === "helm-turn");
    if (!turn) return;
    const target = phase === "on" ? SAILING_RATE : 1;
    const fromRest = phase === "busy" && was !== "busy" && was !== "on";
    const from = fromRest ? FROM_REST : turn.playbackRate;
    if (from === target) return;
    if (fromRest) turn.updatePlaybackRate(from);
    let step = 0;
    const timer = window.setInterval(() => {
      step += 1;
      // Eased: quick at first, settling at the end.
      const done = 1 - (1 - step / RATE_STEPS) ** 2;
      turn.updatePlaybackRate(from + (target - from) * done);
      if (step >= RATE_STEPS) window.clearInterval(timer);
    }, RATE_CHANGE_MS / RATE_STEPS);
    return () => window.clearInterval(timer);
  }, [phase]);

  return (
    <button className={`power power-${phase}`} onClick={onClick} disabled={disabled} title={title} aria-label={label}>
      <span className="power-glow" aria-hidden="true" />
      <svg ref={helm} className="power-helm" viewBox="0 0 200 200" aria-hidden="true">
        <defs>
          <linearGradient id="power-ink" gradientUnits="userSpaceOnUse" x1="64" y1="12" x2="136" y2="188">
            <stop offset="0" stopColor="#f7dc92" />
            <stop offset="0.5" stopColor="#e3b04e" />
            <stop offset="1" stopColor="#a8741f" />
          </linearGradient>
          <linearGradient id="power-lit" gradientUnits="userSpaceOnUse" x1="64" y1="4" x2="136" y2="196">
            <stop offset="0" stopColor="#fff6dc" />
            <stop offset="0.45" stopColor="#f8d98c" />
            <stop offset="1" stopColor="#dca447" />
          </linearGradient>
        </defs>
        <circle className="helm-rim" cx="100" cy="100" r="64" />
        <circle className="helm-band" cx="100" cy="100" r="57" />
        <path className="helm-spokes" d={SPOKES} />
        <path className="helm-handles" d={HANDLES} />
      </svg>
      <span className="power-core">
        <Power size={28} strokeWidth={2.4} aria-hidden="true" />
        <span className="power-label">{label}</span>
      </span>
    </button>
  );
}
