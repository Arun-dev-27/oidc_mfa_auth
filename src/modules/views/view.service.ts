import { Injectable } from '@nestjs/common';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { AppConfig } from '../../config/config.module';

export type ViewData = Record<string, string | number | boolean | null | undefined>;

const ESCAPES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' };

export function escapeHtml(value: unknown): string {
  return String(value ?? '').replace(/[&<>"'`]/g, (c) => ESCAPES[c]);
}

/**
 * Minimal, dependency-free SSR templating for the login pages (views/*.html):
 *   {{name}}               HTML-escaped value
 *   {{{name}}}             raw value (only for trusted, server-built HTML)
 *   {{#flag}}...{{/flag}}  block kept when flag is truthy
 *   {{^flag}}...{{/flag}}  block kept when flag is falsy
 * Every page is wrapped in views/layout.html at {{{content}}}. Templates are plain HTML files so the
 * design can be replaced later without touching TypeScript.
 */
@Injectable()
export class ViewService {
  private readonly dir = resolve(process.cwd(), 'views');
  private readonly cache = new Map<string, string>();

  constructor(private readonly config: AppConfig) {}

  render(name: string, data: ViewData): string {
    const base: ViewData = { tagline: this.config.env.BRAND_TAGLINE, year: new Date().getFullYear(), ...data };
    const content = this.fill(this.template(name), base);
    return this.fill(this.template('layout'), { ...base, content });
  }

  private template(name: string): string {
    if (!/^[a-z0-9-]+$/.test(name)) throw new Error(`invalid view name ${name}`);
    const cached = this.cache.get(name);
    if (cached !== undefined) return cached;
    const source = readFileSync(join(this.dir, `${name}.html`), 'utf8');
    if (this.config.isProduction) this.cache.set(name, source);
    return source;
  }

  private fill(template: string, data: ViewData): string {
    const sections = template.replace(/\{\{([#^])(\w+)\}\}([\s\S]*?)\{\{\/\2\}\}/g, (_m, kind: string, key: string, body: string) => {
      const on = Boolean(data[key]);
      return (kind === '#' ? on : !on) ? body : '';
    });
    // Raw values are swapped in last, through placeholders, so inserted text is never re-scanned
    // for {{...}} (a value can never inject another placeholder).
    const raw: string[] = [];
    return sections
      .replace(/\{\{\{(\w+)\}\}\}/g, (_m, key: string) => `\u0000${raw.push(String(data[key] ?? '')) - 1}\u0000`)
      .replace(/\{\{(\w+)\}\}/g, (_m, key: string) => escapeHtml(data[key]))
      .replace(/\u0000(\d+)\u0000/g, (_m, i: string) => raw[Number(i)]);
  }
}
