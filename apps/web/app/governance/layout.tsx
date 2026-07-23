import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Governance",
  description: "Policies that define agent autonomy, approvals, and action boundaries.",
};

export default function GovernanceLayout({ children }: LayoutProps<"/governance">) {
  return children;
}
