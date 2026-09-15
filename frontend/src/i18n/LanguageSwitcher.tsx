import { cn } from '@/lib/utils'
import { useI18n } from './index'

export default function LanguageSwitcher({ className }: { className?: string }) {
  const { locale, setLocale, t } = useI18n()
  return (
    <div
      className={cn(
        'inline-flex items-center rounded-md border border-border bg-muted/40 p-0.5 text-xs',
        className,
      )}
      role="group"
      aria-label={t('lang.switch')}
    >
      <button
        type="button"
        className={cn(
          'rounded px-2 py-1 font-medium transition-colors',
          locale === 'zh' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground',
        )}
        aria-pressed={locale === 'zh'}
        onClick={() => setLocale('zh')}
      >
        {t('lang.zh')}
      </button>
      <button
        type="button"
        className={cn(
          'rounded px-2 py-1 font-medium transition-colors',
          locale === 'en' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground',
        )}
        aria-pressed={locale === 'en'}
        onClick={() => setLocale('en')}
      >
        {t('lang.en')}
      </button>
    </div>
  )
}
