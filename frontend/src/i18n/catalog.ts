import { commonPack } from './packs/common'
import { formatPack } from './packs/format'
import { flowPack } from './packs/flow'
import { pagesPack } from './packs/pages'
import { settingsPack } from './packs/settings'
import { componentsPack } from './packs/components'
import type { Locale } from './locale'

export type MessageTable = Record<string, string>

function merge(...packs: { zh: MessageTable; en: MessageTable }[]): {
  zh: MessageTable
  en: MessageTable
} {
  const zh: MessageTable = {}
  const en: MessageTable = {}
  for (const pack of packs) {
    Object.assign(zh, pack.zh)
    Object.assign(en, pack.en)
  }
  return { zh, en }
}

export const catalogs: Record<Locale, MessageTable> = merge(
  commonPack,
  formatPack,
  flowPack,
  pagesPack,
  settingsPack,
  componentsPack,
)
