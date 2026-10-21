"use client"

import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useTimeZone } from "@/components/time-zone-provider"
import { DISPLAY_TIME_ZONES } from "@/lib/format"

export function DisplayPreferencesPanel() {
  const { timeZone, setTimeZone, notice } = useTimeZone()

  return (
    <section className="space-y-2" aria-labelledby="display-preferences-heading">
      <h2 id="display-preferences-heading" className="text-sm font-medium text-balance">Display</h2>
      <Label htmlFor="display-timezone">Display timezone</Label>
      <Select value={timeZone} onValueChange={setTimeZone}>
        <SelectTrigger id="display-timezone" className="w-full"><SelectValue /></SelectTrigger>
        <SelectContent>
          {DISPLAY_TIME_ZONES.map(zone => <SelectItem key={zone} value={zone}>{zone}</SelectItem>)}
        </SelectContent>
      </Select>
      <p className="text-xs text-muted-foreground text-pretty">
        Saved automatically in this browser, across accounts. Changes timestamps and charts;
        API data, UTC exports, expiry and notification quiet hours are unchanged.
      </p>
      {notice && <p role="status" className="text-xs text-muted-foreground">{notice}</p>}
    </section>
  )
}
