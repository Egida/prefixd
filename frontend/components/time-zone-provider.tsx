"use client"

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react"
import { displayDateKey, formatClock, formatTimestamp, formatTimestampTick, isDisplayTimeZone } from "@/lib/format"

export const TIME_ZONE_STORAGE_KEY = "prefixd-display-timezone-v1"

interface TimeZonePreference {
  timeZone: string
  notice: string | null
  setTimeZone: (value: string) => void
}

const TimeZoneContext = createContext<TimeZonePreference>({
  timeZone: "UTC",
  notice: null,
  setTimeZone: (_value: string) => {},
})

export function TimeZoneProvider({ children }: { children: ReactNode }) {
  // The server and initial hydration both use UTC; browser storage is read after hydration.
  const [timeZone, setZone] = useState("UTC")
  const [notice, setNotice] = useState<string | null>(null)

  useEffect(() => {
    const read = () => {
      try {
        const saved = localStorage.getItem(TIME_ZONE_STORAGE_KEY)
        setZone(isDisplayTimeZone(saved) ? saved : "UTC")
        setNotice(saved !== null && !isDisplayTimeZone(saved) ? "Saved timezone is unavailable. UTC is in use." : null)
      } catch {
        setNotice("Browser storage is unavailable. Timezone changes apply only to this visit.")
      }
    }

    read()

    const onStorage = (event: StorageEvent) => {
      if (event.key === TIME_ZONE_STORAGE_KEY || event.key === null) read()
    }

    window.addEventListener("storage", onStorage)

    return () => window.removeEventListener("storage", onStorage)
  }, [])

  const setTimeZone = useCallback((value: string) => {
    if (!isDisplayTimeZone(value)) {
      setNotice("Choose a supported IANA timezone.")

      return
    }

    setZone(value)

    try {
      localStorage.setItem(TIME_ZONE_STORAGE_KEY, value)
      setNotice(null)
    } catch {
      setNotice("Could not save the timezone in this browser. It applies only to this visit.")
    }
  }, [])

  const value = useMemo(() => ({ timeZone, notice, setTimeZone }), [timeZone, notice, setTimeZone])

  return <TimeZoneContext.Provider value={value}>{children}</TimeZoneContext.Provider>
}

export function useTimeZone() {
  return useContext(TimeZoneContext)
}

export function useTimeFormat() {
  const { timeZone } = useTimeZone()

  return useMemo(() => ({
    timeZone,
    formatTime: (value: string | number | Date, now?: number) => formatTimestamp(value, timeZone, now),
    formatTick: (value: string | number | Date, withDate = false) => formatTimestampTick(value, timeZone, withDate),
    formatClock: (value: number) => formatClock(value, timeZone),
    dateKey: (value: string | number | Date) => displayDateKey(value, timeZone),
  }), [timeZone])
}
