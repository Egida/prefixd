"use client"

import { useHealthDetail } from "@/hooks/use-api"
import { cn } from "@/lib/utils"
import { Skeleton } from "@/components/ui/skeleton"

export function formatControllerUptime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "unavailable"
  const minutes = Math.floor(seconds / 60)
  if (minutes === 0) return `${Math.floor(seconds)}s`
  if (minutes < 60) return `${minutes}m`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ${minutes % 60}m`
  return `${Math.floor(hours / 24)}d ${hours % 24}h`
}

export function BgpSessionStatus() {
  const { data: health, error } = useHealthDetail()
  const status = error ? "ERROR"
    : !health ? "LOADING"
    : health.speaker?.capabilities.peer_observer === false || health.gobgp.status === "unsupported" ? "UNSUPPORTED"
    : health.gobgp.status !== "connected" ? "ERROR"
    : Object.keys(health.bgp_sessions).length === 0 ? "NO PEERS"
    : health.bgp_session_up ? "UP" : "DOWN"
  const isUp = status === "UP"
  const isError = status === "ERROR" || status === "DOWN"
  const observed = error ? undefined : health
  const peers = observed ? Object.values(observed.bgp_sessions) : []
  const established = peers.filter(state => state === "established").length

  return (
    <section aria-label="Speaker and controller health" className="flex flex-wrap items-center gap-x-6 gap-y-3 rounded-lg border bg-card px-4 py-3 text-[13px]">
      <div className="flex items-center gap-2">
        <span aria-hidden="true" className={cn("size-2 rounded-full", isUp ? "bg-primary" : isError ? "bg-destructive" : "bg-muted-foreground")} />
        <span className="text-muted-foreground">Backend</span>
        <span className="font-medium">{observed ? observed.speaker?.backend ?? "Unknown backend" : "Unavailable"}</span>
        <span className="text-muted-foreground">Peers <span className={cn("font-mono text-xs", isUp ? "text-primary" : isError ? "text-destructive" : "text-muted-foreground")}>{status}</span></span>
      </div>
      {error ? (
        <span role="status" className="text-destructive">Health unavailable. Retrying automatically.</span>
      ) : !health ? (
        <div role="status" className="flex items-center gap-2 text-muted-foreground"><Skeleton className="h-4 w-24" />Loading health…</div>
      ) : (
        <>
          <span className="text-muted-foreground">
            Sessions <span className="font-mono text-foreground">{status === "UNSUPPORTED" || status === "ERROR" ? "unavailable" : `${established}/${peers.length} established`}</span>
          </span>
          <span className="text-muted-foreground">Database <span className={cn(health.database === "connected" ? "text-foreground" : "text-destructive")}>{health.database === "connected" ? "connected" : "unavailable"}</span></span>
          <span className="text-muted-foreground sm:ml-auto">Controller <span className="font-mono text-foreground">v{health.version}</span> · up <span className="font-mono">{formatControllerUptime(health.uptime_seconds)}</span></span>
        </>
      )}
    </section>
  )
}
