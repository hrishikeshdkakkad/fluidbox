import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Recipes",
  description:
    "Deploy governed agent workloads from opinionated, versioned templates.",
};

export default function RecipesLayout({ children }: LayoutProps<"/app/recipes">) {
  return children;
}
