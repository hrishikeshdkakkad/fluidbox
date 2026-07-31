// /login is a pre-auth page: no masthead (mounting it would 401-spam the
// control plane), just the shared background shell the form centers itself in.
export default function LoginLayout({ children }: LayoutProps<"/login">) {
  return <div className="shell">{children}</div>;
}
