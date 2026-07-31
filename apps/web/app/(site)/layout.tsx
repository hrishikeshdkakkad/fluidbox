// The public-surface route group: marketing pages, /docs, /changelog. The
// shared header/footer chrome lands with the marketing build; docs pages
// bring their own rail inside it.
export default function SiteLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
