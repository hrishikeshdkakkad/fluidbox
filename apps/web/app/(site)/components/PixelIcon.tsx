// Pixel-grid glyphs for the use-case cards: each icon is a 10×10 bitmap
// rendered as gradient-filled squares, so the whole set shares one material
// (the teal→indigo duotone, the site's accent pair) no matter the subject.
// Rows are strings — "#" paints a cell — which keeps the drawings
// reviewable in source.

const GLYPHS: Record<string, string[]> = {
  // a pull request: two rails, a merge elbow, commit dots
  pr: [
    "##..........",
    "##..........",
    "##....######",
    "##....######",
    "##........##",
    "##........##",
    "##....##..##",
    "##....##..##",
    "######....##",
    "######....##",
  ],
  // a clock face reduced to pixels
  clock: [
    "...######...",
    ".##......##.",
    ".#....##..#.",
    "#.....##...#",
    "#.....##...#",
    "#.....####.#",
    "#..........#",
    ".#........#.",
    ".##......##.",
    "...######...",
  ],
  // a hand pausing on a decision
  hand: [
    "....##......",
    "....##.##...",
    "....##.##.##",
    "....########",
    "##..########",
    "##..########",
    ".###########",
    ".##########.",
    "..########..",
    "...######...",
  ],
  // rails: a run held between guardrails
  rails: [
    "##........##",
    "##........##",
    "##..####..##",
    "##..####..##",
    "##........##",
    "##..####..##",
    "##..####..##",
    "##........##",
    "##........##",
    "##........##",
  ],
  // a key that never leaves the vault
  key: [
    "...#####....",
    "..##...##...",
    "..##...##...",
    "...#####....",
    ".....##.....",
    ".....##.....",
    ".....####...",
    ".....##.....",
    ".....####...",
    ".....##.....",
  ],
  // a plug: bring your own harness
  plug: [
    "..##....##..",
    "..##....##..",
    "..##....##..",
    "############",
    "############",
    "############",
    ".##########.",
    "...######...",
    ".....##.....",
    ".....##.....",
  ],
  // a meter pinned under its ceiling
  meter: [
    "............",
    "############",
    "............",
    "##..........",
    "######......",
    "##########..",
    "............",
    "##......##..",
    "##..##..##..",
    "##..##..##..",
  ],
  // a ledger page with gapless lines
  ledger: [
    "##########..",
    "##########..",
    "............",
    "########....",
    "############",
    "............",
    "##########..",
    "############",
    "............",
    "########....",
  ],
  // a helm wheel: fleets on Kubernetes
  helm: [
    ".....##.....",
    "..#..##..#..",
    "...######...",
    "..##....##..",
    "####.##.####",
    "####.##.####",
    "..##....##..",
    "...######...",
    "..#..##..#..",
    ".....##.....",
  ],
};

export function PixelIcon({ name }: { name: keyof typeof GLYPHS | string }) {
  const rows = GLYPHS[name] ?? GLYPHS.ledger;
  const cell = 10;
  const gap = 2;
  const cols = rows[0].length;
  const w = cols * (cell + gap) - gap;
  const h = rows.length * (cell + gap) - gap;
  const id = `pxg-${name}`;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} role="presentation" aria-hidden="true">
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#5eead4" />
          <stop offset="1" stopColor="#818cf8" />
        </linearGradient>
      </defs>
      {rows.flatMap((row, y) =>
        [...row].map((ch, x) =>
          ch === "#" ? (
            <rect
              key={`${x}-${y}`}
              x={x * (cell + gap)}
              y={y * (cell + gap)}
              width={cell}
              height={cell}
              fill={`url(#${id})`}
            />
          ) : null
        )
      )}
    </svg>
  );
}
