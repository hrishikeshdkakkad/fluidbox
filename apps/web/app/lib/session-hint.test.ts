import { describe, expect, it } from "vitest";
import {
  SESSION_HINT_COOKIE,
  SESSION_HINT_INIT_SCRIPT,
  hintFromCookieValue,
  hintSetCookie,
} from "./session-hint";

describe("hintFromCookieValue", () => {
  it("reads a present hint as signed in", () => {
    expect(hintFromCookieValue("1")).toBe("in");
  });

  it("treats absent, empty and any other value as signed OUT", () => {
    for (const raw of [undefined, "", "0", "false", "yes", "junk"]) {
      expect(hintFromCookieValue(raw), String(raw)).toBe("out");
    }
  });
});

describe("hintSetCookie", () => {
  it("sets a durable hint when a session exists", () => {
    const cookie = hintSetCookie(true);
    expect(cookie).toContain(`${SESSION_HINT_COOKIE}=1`);
    expect(cookie).toContain("Path=/");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).not.toMatch(/Max-Age=0/);
  });

  it("expires the hint when the session is gone", () => {
    const cookie = hintSetCookie(false);
    expect(cookie).toContain(`${SESSION_HINT_COOKIE}=`);
    expect(cookie).toContain("Max-Age=0");
  });

  // This cookie is a UI hint, never a credential. It must stay readable by the
  // pre-paint script (so NOT HttpOnly), and it must never be confused with the
  // real session cookie, which is __Host-fbx_web and stays HttpOnly.
  it("is deliberately NOT HttpOnly and is not the session cookie", () => {
    for (const cookie of [hintSetCookie(true), hintSetCookie(false)]) {
      expect(cookie).not.toMatch(/HttpOnly/i);
      expect(cookie).not.toContain("__Host-fbx_web");
    }
  });
});

describe("SESSION_HINT_INIT_SCRIPT", () => {
  it("references the cookie it reads", () => {
    expect(SESSION_HINT_INIT_SCRIPT).toContain(SESSION_HINT_COOKIE);
  });

  it("is self-contained and swallows its own errors, like the theme script", () => {
    // It runs before paint in <head>; a throw there would blank the page.
    expect(SESSION_HINT_INIT_SCRIPT).toContain("try");
    expect(SESSION_HINT_INIT_SCRIPT).toContain("catch");
  });

  it("actually sets data-session when the cookie is present", () => {
    const root: { dataset: Record<string, string> } = { dataset: {} };
    const doc = { documentElement: root, cookie: `theme=dark; ${SESSION_HINT_COOKIE}=1` };
    new Function("document", SESSION_HINT_INIT_SCRIPT)(doc);
    expect(root.dataset.session).toBe("in");
  });

  it("sets it to out when the cookie is absent", () => {
    const root: { dataset: Record<string, string> } = { dataset: {} };
    const doc = { documentElement: root, cookie: "theme=dark" };
    new Function("document", SESSION_HINT_INIT_SCRIPT)(doc);
    expect(root.dataset.session).toBe("out");
  });

  // A cookie whose NAME merely ends with the hint name must not be mistaken
  // for it — e.g. `other_fbx_ui=1` while the real hint is absent.
  it("does not match a cookie whose name only ends with the hint name", () => {
    const root: { dataset: Record<string, string> } = { dataset: {} };
    const doc = { documentElement: root, cookie: `other_${SESSION_HINT_COOKIE}=1` };
    new Function("document", SESSION_HINT_INIT_SCRIPT)(doc);
    expect(root.dataset.session).toBe("out");
  });
});
