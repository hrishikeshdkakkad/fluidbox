"use client";

import { useRef, useState } from "react";

// The product film (v7, 2:56, narrated) — served from the same public S3
// master the README links, so the site carries no 16MB binary and the
// video costs no bandwidth until someone presses play (it has narration,
// so muted autoplay would waste it). The cover is our own: a designed
// still that hands off to native controls on the first click.
const SRC =
  "https://fluidbox-oss-assets.s3.us-east-1.amazonaws.com/demo-film/v7/fluidbox-demo.mp4";

export function HeroFilm() {
  const ref = useRef<HTMLVideoElement>(null);
  const [started, setStarted] = useState(false);

  return (
    <figure className="st-window st-film" aria-label="The fluidbox product film">
      <div className="st-window-head" aria-hidden>
        <span className="st-dots">
          <i />
          <i />
          <i />
        </span>
        <span className="st-window-title">
          the product film — one incident, governed end to end
        </span>
      </div>
      <div className="st-film-body">
        <video
          ref={ref}
          src={SRC}
          preload="none"
          playsInline
          controls={started}
          onEnded={() => setStarted(false)}
        />
        {!started && (
          <button
            type="button"
            className="st-film-cover"
            onClick={() => {
              setStarted(true);
              ref.current?.play();
            }}
            aria-label="Play the product film — 2 minutes 56 seconds, narrated"
          >
            <span className="st-film-play" aria-hidden>
              <svg viewBox="0 0 24 24" fill="currentColor">
                <path d="M8 5.5v13l11-6.5-11-6.5Z" />
              </svg>
            </span>
            <span className="st-film-cap">Watch the product film</span>
            <span className="st-film-len">
              2:56 · narrated · from agent definition to delivered pull request
            </span>
          </button>
        )}
      </div>
    </figure>
  );
}
