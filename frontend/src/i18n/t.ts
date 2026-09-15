import { getLocale, type Locale } from './locale'
import { catalogs } from './catalog'

export type MessageVars = Record<string, string | number>

export function translate(locale: Locale, key: string, vars?: MessageVars): string {
  const table = catalogs[locale] || catalogs.zh
  let text = table[key] ?? catalogs.zh[key] ?? key
  if (vars) {
    text = text.replace(/\{(\w+)\}/g, (_, name: string) =>
      vars[name] == null ? `{${name}}` : String(vars[name]),
    )
  }
  return text
}

export function t(key: string, vars?: MessageVars): string {
  return translate(getLocale(), key, vars)
}
