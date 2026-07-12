"use client";

import { usePathname } from "next/navigation";
import Link from "next/link";
import { useEffect, useState } from "react";
import { Activity, Bot, Cable, Menu, Puzzle, Settings, X, Zap } from "lucide-react";
import { apiGet } from "../lib/api";

const NAV = [
  {
    label: "Operate",
    items: [
      { href: "/", label: "Runs", Icon: Activity, badge: true },
      { href: "/automations", label: "Automations", Icon: Zap },
    ],
  },
  {
    label: "Build",
    items: [
      { href: "/agents", label: "Agents", Icon: Bot },
      { href: "/capabilities", label: "Capabilities", Icon: Puzzle },
      { href: "/integrations", label: "Integrations", Icon: Cable },
    ],
  },
];

export function Sidebar() {
  const path = usePathname();
  const [pending, setPending] = useState(0);
  const [online, setOnline] = useState(true);
  const [menuOpen, setMenuOpen] = useState(false);

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
    href === "/" ? path === "/" || path.startsWith("/sessions") : path.startsWith(href);

  return (
    <nav className={`rail ${menuOpen ? "open" : ""}`} aria-label="Primary navigation">
      <div className="rail-head">
        <Link href="/" className="brand" onClick={() => setMenuOpen(false)}>
          <span className="mark">
            <i />
            <i />
            <i />
            <i />
          </span>
          <span className="name">fluidbox</span>
        </Link>
        <button
          className="mobile-menu"
          type="button"
          aria-label={menuOpen ? "Close navigation" : "Open navigation"}
          aria-expanded={menuOpen}
          onClick={() => setMenuOpen((current) => !current)}
        >
          {menuOpen ? <X /> : <Menu />}
        </button>
      </div>

      <div className="nav-body">
        <div className="workspace-context" aria-label="Current workspace">
          <span className="workspace-avatar">F</span>
          <span>
            <strong>Fluidbox Cloud</strong>
            <small>Default workspace</small>
          </span>
        </div>

        {NAV.map((group) => (
          <div className="nav-group" key={group.label}>
            <div className="nav-label">{group.label}</div>
            <div className="nav-items">
              {group.items.map(({ href, label, Icon, badge }) => (
                <Link
                  key={href}
                  href={href}
                  className={`navlink ${isActive(href) ? "active" : ""}`}
                  aria-current={isActive(href) ? "page" : undefined}
                  onClick={() => setMenuOpen(false)}
                >
                  <Icon strokeWidth={1.7} />
                  {label}
                  {badge && pending > 0 && <span className="count">{pending}</span>}
                </Link>
              ))}
            </div>
          </div>
        ))}

        <div className="foot">
          <Link
            href="/settings"
            className={`navlink ${isActive("/settings") ? "active" : ""}`}
            aria-current={isActive("/settings") ? "page" : undefined}
            onClick={() => setMenuOpen(false)}
          >
            <Settings strokeWidth={1.7} />
            Settings
          </Link>
          <div className="system-state">
            <span className={`signal ${online ? "" : "down"}`} />
            <span>{online ? "All systems operational" : "Control plane offline"}</span>
          </div>
        </div>
      </div>
    </nav>
  );
}
