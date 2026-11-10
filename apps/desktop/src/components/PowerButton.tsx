import { Power } from "lucide-react";
import { useEffect, useRef } from "react";

export type PowerPhase = "off" | "busy" | "on" | "error" | "unavailable";

/** How much faster than the connecting speed (one turn in 18 s, set in
 * styles.css) the wheel turns once sharing is on: one turn in 6 s. */
const SHARING_RATE = 3;
/** The speed changes over this long, in a few small steps, so the wheel
 * speeds up and slows down instead of lurching. */
const RATE_CHANGE_MS = 600;
const RATE_STEPS = 8;

/** A point `r` out from the middle of the 200 × 200 drawing, `deg` clockwise from three o'clock. */
function at(r: number, deg: number): [number, number] {
  const a = (deg * Math.PI) / 180;
  return [Math.round((100 + r * Math.cos(a)) * 100) / 100, Math.round((100 + r * Math.sin(a)) * 100) / 100];
}

// The logo's helm around the button: a rim, six spokes out of it and a handle
// on each, one for every device a link reaches. Worked out once.
const ANGLES = [-90, -30, 30, 90, 150, 210];
const SPOKES = ANGLES.map((deg) => {
  const [x1, y1] = at(71, deg);
  const [x2, y2] = at(80, deg);
  return `M${x1} ${y1}L${x2} ${y2}`;
}).join("");
const HANDLES = ANGLES.map((deg) => at(88, deg));

/**
 * The big round start/stop button, drawn as the logo's helm: this computer is
 * the hub in the middle (the icon and word), the handles round the rim are the
 * devices. While sharing connects the wheel turns very slowly; once it is on,
 * the handles light up with a still glow behind and the wheel keeps turning,
 * faster. When sharing is off it rests where it stopped.
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

  // The turn is a CSS animation (styles.css, "helm-turn"); only its speed is
  // set here. updatePlaybackRate keeps the wheel's angle, so changing speed
  // never makes it jump. With reduced motion there is no animation to find.
  useEffect(() => {
    const turn = helm.current
      ?.getAnimations()
      .find((a): a is CSSAnimation => a instanceof CSSAnimation && a.animationName === "helm-turn");
    if (!turn) return;
    const target = phase === "on" ? SHARING_RATE : 1;
    const from = turn.playbackRate;
    if (from === target) return;
    let step = 0;
    const timer = window.setInterval(() => {
      step += 1;
      turn.updatePlaybackRate(from + ((target - from) * step) / RATE_STEPS);
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
            <stop offset="0" stopColor="#2af3f0" />
            <stop offset="0.5" stopColor="#1fb0f2" />
            <stop offset="1" stopColor="#1c5fe6" />
          </linearGradient>
          <radialGradient id="power-core" cx="0.36" cy="0.3" r="0.82">
            <stop offset="0" stopColor="#ecfeff" />
            <stop offset="0.25" stopColor="#6ee9fd" />
            <stop offset="0.68" stopColor="#1fa3f2" />
            <stop offset="1" stopColor="#1660df" />
          </radialGradient>
        </defs>
        <circle className="helm-rim" cx="100" cy="100" r="64" />
        <path className="helm-spokes" d={SPOKES} />
        {HANDLES.map(([cx, cy]) => (
          <circle key={`${cx},${cy}`} className="helm-handle" cx={cx} cy={cy} r="8.5" />
        ))}
      </svg>
      <span className="power-core">
        <Power size={28} strokeWidth={2.4} aria-hidden="true" />
        <span className="power-label">{label}</span>
      </span>
    </button>
  );
}
