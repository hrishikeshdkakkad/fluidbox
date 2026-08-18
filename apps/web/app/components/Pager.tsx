"use client";

// Pagination for the activity board. Presentation-only: the page owns the
// window it fetched (the control plane's list endpoint takes a plain limit),
// and this component only walks that window. The range readout is always
// shown once rows exist; the page buttons and the density select appear only
// when they can actually change what is on screen.

export const PAGE_SIZES = [25, 50, 100] as const;
export type PageSize = (typeof PAGE_SIZES)[number];

export function pageCount(total: number, pageSize: number): number {
  return Math.max(1, Math.ceil(total / pageSize));
}

/** Clamp a 1-based page into the range the current total allows. */
export function clampPage(page: number, total: number, pageSize: number): number {
  return Math.min(Math.max(1, page), pageCount(total, pageSize));
}

interface PagerProps {
  /** 1-based, already clamped by the caller. */
  page: number;
  /** Row count AFTER filtering — the list the pager walks. */
  total: number;
  pageSize: PageSize;
  onPage: (page: number) => void;
  onPageSize: (size: PageSize) => void;
}

export function Pager({ page, total, pageSize, onPage, onPageSize }: PagerProps) {
  const count = pageCount(total, pageSize);
  const start = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, total);
  const smallest = PAGE_SIZES[0];

  return (
    <nav className="run-pager" aria-label="Run history pages">
      <span className="pager-range" aria-live="polite">
        {total === 0 ? "no runs" : `${start}–${end} of ${total}`}
      </span>
      <div className="pager-controls">
        {total > smallest && (
          <label className="pager-size">
            per page
            <select
              value={pageSize}
              onChange={(event) => onPageSize(Number(event.target.value) as PageSize)}
            >
              {PAGE_SIZES.map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </label>
        )}
        {count > 1 && (
          <div className="pager-pages">
            <button
              type="button"
              className="pager-step"
              disabled={page <= 1}
              onClick={() => onPage(page - 1)}
              aria-label="Previous page"
            >
              &#8249;
            </button>
            {Array.from({ length: count }, (_, index) => index + 1).map((n) => (
              <button
                key={n}
                type="button"
                className={`pager-num${n === page ? " on" : ""}`}
                aria-current={n === page ? "page" : undefined}
                onClick={() => onPage(n)}
              >
                {n}
              </button>
            ))}
            <button
              type="button"
              className="pager-step"
              disabled={page >= count}
              onClick={() => onPage(page + 1)}
              aria-label="Next page"
            >
              &#8250;
            </button>
          </div>
        )}
      </div>
    </nav>
  );
}
