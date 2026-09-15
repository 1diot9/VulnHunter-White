import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { applyLocale, getLocale, subscribeLocale, type Locale } from './locale'
import { t as translate, type MessageVars } from './t'

type I18nValue = {
  locale: Locale
  setLocale: (locale: Locale) => void
  t: (key: string, vars?: MessageVars) => string
}

const I18nContext = createContext<I18nValue>({
  locale: 'zh',
  setLocale: applyLocale,
  t: translate,
})

export function LocaleProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(getLocale)

  useEffect(() => subscribeLocale(() => setLocaleState(getLocale())), [])

  const setLocale = useCallback((next: Locale) => {
    applyLocale(next)
  }, [])

  const t = useCallback(
    (key: string, vars?: MessageVars) => translate(key, vars),
    [locale],
  )

  const value = useMemo(() => ({ locale, setLocale, t }), [locale, setLocale, t])
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export function useI18n(): I18nValue {
  return useContext(I18nContext)
}

export type { Locale } from './locale'
export type { MessageVars } from './t'
export { t } from './t'
