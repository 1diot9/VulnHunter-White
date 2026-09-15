import { t } from '@/i18n/t'

/** Shared copy for Docker Desktop manual-lab UI. */
export function dockerManualLabHint(): string {
  return t('docker.manualHint')
}

/** @deprecated call dockerManualLabHint() so locale can change */
export const DOCKER_MANUAL_LAB_HINT = dockerManualLabHint
