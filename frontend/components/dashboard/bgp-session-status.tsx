"use client"

import { motion } from "motion/react"
import { useHealthDetail, usePops } from "@/hooks/use-api"
import { cn } from "@/lib/utils"
import { useReducedMotion } from "@/hooks/use-reduced-motion"

export function BgpSessionStatus() {
  const { data: health, error } = useHealthDetail()
  const { data: pops } = usePops()
  const reducedMotion = useReducedMotion()

  const status = error ? "ERROR"
    : !health ? "LOADING"
    : health.gobgp.status === "unsupported" ? "UNSUPPORTED"
    : health.gobgp.status !== "connected" ? "ERROR"
    : Object.keys(health.bgp_sessions).length === 0 ? "NO PEERS"
    : health.bgp_session_up ? "UP" : "DOWN"
  const isUp = status === "UP"
  const isError = status === "ERROR" || status === "DOWN"
  const shouldAnimate = isUp && !reducedMotion

  return (
    <div className="border border-border bg-card p-4">
      <h3 className="text-xs font-mono uppercase tracking-wide text-muted-foreground mb-3">System Status</h3>
      <div className="flex flex-wrap gap-2">
        <div className="group relative flex items-center gap-2 bg-secondary px-3 py-2 border border-border">
          {shouldAnimate ? (
            <motion.span
              className="size-1.5 bg-primary"
              animate={{ opacity: [1, 0.4, 1] }}
              transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
            />
          ) : (
            <span className={cn("size-1.5", isUp ? "bg-primary" : isError ? "bg-destructive" : "bg-muted-foreground")} />
          )}
          <span className="font-mono text-xs text-foreground">BGP</span>
          <span className={cn("text-[10px] font-mono uppercase", isUp ? "text-primary" : isError ? "text-destructive" : "text-muted-foreground")}>
            {status}
          </span>
        </div>

        {health && (
          <div className="group relative flex items-center gap-2 bg-secondary px-3 py-2 border border-border">
            <span className="size-1.5 bg-primary" />
            <span className="font-mono text-xs text-foreground">DB</span>
            <span className="text-[10px] font-mono uppercase text-primary">
              {health.database === "connected" ? "OK" : "ERR"}
            </span>
          </div>
        )}

        {health && (
          <div className="group relative flex items-center gap-2 bg-secondary px-3 py-2 border border-border">
            <span className="font-mono text-xs text-muted-foreground tabular-nums">
              {health.active_mitigations} active
            </span>
          </div>
        )}

        {pops && pops.length > 1 && (
          <div className="flex items-center gap-2 bg-secondary px-3 py-2 border border-border">
            <span className="font-mono text-xs text-muted-foreground">
              {pops.length} POPs
            </span>
          </div>
        )}
      </div>
    </div>
  )
}
