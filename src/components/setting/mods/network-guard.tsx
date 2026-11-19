import { Button } from '@mui/material'
import { useLockFn } from 'ahooks'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { Switch } from '@/components/base'
import { getNetworkGuardStatus, setNetworkGuardEnabled } from '@/services/cmds'
import { mutate } from '@/services/mutate'
import { useQuery } from '@/services/query-client'

import { SettingItem } from './setting-comp'

const statusKey = 'getNetworkGuardStatus'

export const NetworkGuard = () => {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)
  const { data, error, refetch } = useQuery({
    queryKey: statusKey,
    queryFn: getNetworkGuardStatus,
    refetchInterval: 3000,
  })
  const label = t('settings.sections.system.networkGuard.label')
  const status = error ? 'unverified' : (data ?? 'loading')

  const toggle = useLockFn(async (enabled: boolean) => {
    setBusy(true)
    try {
      await mutate(() => setNetworkGuardEnabled(enabled), {
        id: 'network-guard',
      })
    } catch {
      // The mutation already surfaced the error.
    } finally {
      try {
        await refetch()
      } finally {
        setBusy(false)
      }
    }
  })

  return (
    <SettingItem
      label={label}
      secondary={t(`settings.sections.system.networkGuard.${status}`)}
    >
      {status === 'unverified' ? (
        <Button disabled={busy} onClick={() => void toggle(false)}>
          {t('settings.sections.system.networkGuard.disable')}
        </Button>
      ) : (
        <Switch
          edge="end"
          checked={status === 'active' || status === 'blocking'}
          disabled={busy || status === 'loading' || status === 'unavailable'}
          slotProps={{ input: { 'aria-label': label } }}
          onChange={(_, checked) => void toggle(checked)}
        />
      )}
    </SettingItem>
  )
}
