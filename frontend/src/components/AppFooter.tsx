import { PROJECT_AUTHOR_GITHUB_URL } from '@/lib/projectLinks'
import { useI18n } from '@/i18n'

export default function AppFooter() {
  const { t } = useI18n()
  return (
    <footer className="mt-auto shrink-0 border-t border-border">
      <div className="mx-auto max-w-7xl px-4 py-4 text-center text-xs text-muted-foreground">
        {t('footer.poweredByPrefix')}
        <a
          href={PROJECT_AUTHOR_GITHUB_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="font-medium text-foreground/80 hover:text-foreground hover:underline"
        >
          1diot9
        </a>
      </div>
    </footer>
  )
}
