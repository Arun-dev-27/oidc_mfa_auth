/** Tiny argv parser: --key value, --key=value, --flag; repeated keys collect into arrays. */
export function parseArgs(argv = process.argv.slice(2)): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) continue;
    const eq = arg.indexOf('=');
    const key = eq > 0 ? arg.slice(2, eq) : arg.slice(2);
    const next = argv[i + 1];
    // --key=value keeps values that start with '-' (e.g. random secrets) unambiguous.
    const value = eq > 0 ? arg.slice(eq + 1) : next && !next.startsWith('--') ? (i++, next) : 'true';
    out.set(key, [...(out.get(key) ?? []), value]);
  }
  return out;
}

export function one(args: Map<string, string[]>, key: string, fallback?: string): string {
  const v = args.get(key)?.[0] ?? fallback;
  if (v === undefined) throw new Error(`missing --${key}`);
  return v;
}

export function many(args: Map<string, string[]>, key: string): string[] {
  return (args.get(key) ?? []).flatMap((v) => v.split(',')).map((v) => v.trim()).filter(Boolean);
}
