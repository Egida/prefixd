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
  const { data: health, error, isStale: stale, receiptAge: age } = useHealthDetail()
  const daemon = error ? undefined : health?.speaker?.daemon
  const daemonAvailable = daemon?.status === "observed" && !stale
  const status = error ? "ERROR"
    : stale ? "STALE"
    : !health ? "LOADING"
    : health.speaker?.capabilities.peer_observer === false || health.gobgp.status === "unsupported" ? "UNSUPPORTED"
    : health.gobgp.status !== "connected" ? "ERROR"
    : Object.keys(health.bgp_sessions).length === 0 ? "NO PEERS"
    : health.bgp_session_up ? "UP" : "DOWN"
  const isUp = status === "UP"
  const isError = status === "ERROR" || status === "DOWN" || status === "STALE"
  const observed = error || stale ? undefined : health
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
      ) : stale ? (
        <>
          <span role="status" className="text-destructive">Health observation is stale. Retrying automatically.</span>
          <span className="text-muted-foreground">Daemon {daemon?.status === "unsupported" ? "unsupported" : daemon?.status === "observed" ? "stale" : "unavailable"}</span>
        </>
      ) : (
        <>
          <span className="text-muted-foreground">
            Sessions <span className="font-mono text-foreground">{status === "UNSUPPORTED" || status === "ERROR" || status === "STALE" ? "unavailable" : `${established}/${peers.length} established`}</span>
          </span>
          <span className="text-muted-foreground">
            Daemon <span className={cn("font-mono", daemonAvailable && daemon?.ready === false ? "text-destructive" : "text-foreground")}>{daemonAvailable ? daemon.version ?? "version unavailable" : daemon?.status === "unsupported" ? "unsupported" : "unavailable"}</span>
            {daemonAvailable && <>{" · up "}<span className="font-mono text-foreground">{daemon.uptime_seconds === null ? "unavailable" : formatControllerUptime(daemon.uptime_seconds)}</span>{" · "}<span className={daemon.ready === false ? "font-medium text-destructive" : undefined}>{daemon.ready === true ? "ready" : daemon.ready === false ? "not ready" : "readiness unavailable"}</span>{daemon.observed_at && <>{" · observed "}<time dateTime={daemon.observed_at} title={daemon.observed_at}>{new Date(daemon.observed_at).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</time></>}</>}
          </span>
          {!stale && age !== null && <span className="text-muted-foreground">Received {Math.floor(age / 1000)}s ago</span>}
          <span className="text-muted-foreground">Database <span className={cn(health.database === "connected" ? "text-foreground" : "text-destructive")}>{health.database === "connected" ? "connected" : "unavailable"}</span></span>
          <span className="text-muted-foreground sm:ml-auto">Controller <span className="font-mono text-foreground">v{health.version}</span> · up <span className="font-mono">{formatControllerUptime(health.uptime_seconds)}</span></span>
        </>
      )}
    </section>
  )
}
