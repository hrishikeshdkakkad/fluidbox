/* kernel.sh's page-head signature: the page name stacked — latin twice, then
   Japanese, then Chinese — as a decorative block beside the real heading.
   Purely visual, so it's aria-hidden; pages keep their own <h1>. */
export function PageEcho({
  en,
  es,
  jp,
  sc,
}: {
  en: string;
  es: string;
  jp: string;
  sc: string;
}) {
  return (
    <div className="page-echo" aria-hidden>
      <span>{en}</span>
      <span>{es}</span>
      <span className="echo-jp">{jp}</span>
      <span className="echo-sc">{sc}</span>
    </div>
  );
}
