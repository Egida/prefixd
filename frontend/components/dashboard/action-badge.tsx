import { cn } from "@/lib/utils"

interface ActionBadgeProps {
  actionType: "police" | "discard" | string
  rateBps?: number | null
  size?: "sm" | "default"
}

function formatBps(bps: number): string {
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(1)} Gbps`
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbps`
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(1)} Kbps`
  return `${bps} bps`
}

export function ActionBadge({ actionType, rateBps, size = "default" }: ActionBadgeProps) {
  const isPolice = actionType === "police"
  
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-sm border font-medium tabular-nums",
        size === "sm" ? "px-1.5 py-0.5 text-xs" : "px-2 py-0.5 text-[13px]",
        isPolice
          ? "bg-primary/5 text-primary border-primary/30"
          : "bg-destructive/5 text-destructive border-destructive/30",
      )}
    >
      {isPolice && rateBps ? `police ${formatBps(rateBps)}` : actionType}
    </span>
  )
}
