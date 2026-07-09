"use client";

import { usePathname } from "next/navigation";
import Link from "next/link";
import { useEffect, useState } from "react";
import { apiGet } from "../lib/api";

const NAV = [
  { href: "/", label: "Operations", ico: "◉" },
  { href: "/agents", label: "Agents", ico: "⬡" },
  { href: "/approvals", label: "Approvals", ico: "⏸", badge: true },
  { href: "/policies", label: "Policies", ico: "⚖" },
  { href: "/settings", label: "Settings", ico: "⚙" },
];

export function Rail() {
  const path = usePathname();
  const [pending, setPending] = useState(0);
  const [online, setOnline] = useState(true);

  useEffect(() => {
    let alive = true;
    const poll = async () => {
      try {
        const r = await apiGet<{ approvals: unknown[] }>("/approvals");
        if (alive) {
          setPending(r.approvals.length);
          setOnline(true);
        }
      } catch {
        if (alive) setOnline(false);
      }
    };
    poll();
    const t = setInterval(poll, 4000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  const isActive = (href: string) =>
    href === "/" ? path === "/" : path.startsWith(href);

  return (
    <nav className="rail">
      <Link href="/" className="brand">
        <span className="glyph">🧊</span>
        <span className="name">
          fluid<b>box</b>
        </span>
      </Link>

      {NAV.map((n) => (
        <Link
          key={n.href}
          href={n.href}
          className={`navlink ${isActive(n.href) ? "active" : ""}`}
        >
          <span className="ico">{n.ico}</span>
          {n.label}
          {n.badge && pending > 0 && <span className="count">{pending}</span>}
        </Link>
      ))}

      <div className="foot">
        <span className={`signal ${online ? "" : "down"}`} />
        {online ? "control plane · live" : "control plane · offline"}
      </div>
    </nav>
  );
}
